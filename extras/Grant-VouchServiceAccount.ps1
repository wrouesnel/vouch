#Requires -Version 5.1
#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Delegates exactly the Active Directory permissions the vouch service account needs, and no more.

.DESCRIPTION
    vouch binds to Active Directory as a dedicated service account. This script grants that account
    the five permissions vouch needs beyond the default read access every authenticated user has:

      On each -TargetOU, inherited by user objects only (Descendents, user class):
        Write Property  lockoutTime          clear an account's lockout
        Write Property  userAccountControl   disable an account (only as a fail-safe; see below)
        Write Property  description          record when and why vouch disabled an account
        Read Property   msDS-ResultantPSO    find the account's fine-grained password policy

      On the Password Settings Container, inherited by msDS-PasswordSettings objects only:
        Read Property   msDS-LockoutThreshold   read that policy's lockout threshold

    Why each is needed: vouch checks a locked account's password by briefly clearing its lockout,
    binding as the user and re-locking it. AD won't let anyone write a non-zero lockoutTime, so
    the re-lock is done with failed binds up to the account's lockout threshold, which vouch must
    therefore be able to read. If an account can't be re-locked, vouch disables it rather than
    leave it unlocked, and writes a description saying when and why.

    Everything else vouch reads (users, group membership, the domain lockout policy, the computed
    lockout state) is covered by the default read access of Authenticated Users. If your domain
    has removed that, vouch won't work; this script doesn't widen read access to compensate.

    The script refuses to run against an account that is privileged (a member, directly or
    nested, of Domain/Enterprise/Schema Admins, Administrators, the operator groups and similar,
    or protected by AdminSDHolder), since such an account already has far more access than vouch
    needs. It is idempotent: rules that already exist are left alone. It reports any other
    explicit permissions the account holds on the objects it touches; -RemoveOtherPermissions
    removes them so the account ends up with exactly this set there.

    Delegations don't reach accounts protected by AdminSDHolder (adminCount=1), so vouch can't
    unlock administrators even under a delegated OU. That's intended.

    Run as a Domain Admin, or another account allowed to change permissions on the target OUs and
    on CN=Password Settings Container,CN=System. Every change supports -WhatIf and -Confirm.

.PARAMETER Identity
    The service account: its sAMAccountName, userPrincipalName, distinguished name, SID or GUID.

.PARAMETER TargetOU
    Distinguished names of the OUs or containers holding the users vouch may unlock. Permissions
    are inherited by user objects beneath them. Don't use the domain root.

.PARAMETER Server
    The domain controller to use. Defaults to one chosen by the ActiveDirectory module.

.PARAMETER Revoke
    Remove the permissions this script grants, instead of granting them.

.PARAMETER RemoveOtherPermissions
    Also remove any other explicit permissions the account holds on the target OUs, the Password
    Settings Container and the domain root, so it's left with exactly the vouch set there.

.EXAMPLE
    .\Grant-VouchServiceAccount.ps1 -Identity svc-vouch -TargetOU 'OU=Staff,DC=example,DC=com' -WhatIf

    Shows what would be granted, without changing anything.

.EXAMPLE
    .\Grant-VouchServiceAccount.ps1 -Identity svc-vouch -TargetOU 'OU=Staff,DC=example,DC=com','OU=Contractors,DC=example,DC=com'

    Grants the permissions for users in two OUs.

.EXAMPLE
    .\Grant-VouchServiceAccount.ps1 -Identity svc-vouch -TargetOU 'OU=Staff,DC=example,DC=com' -Revoke

    Removes the permissions again.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory = $true)]
    [string] $Identity,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string[]] $TargetOU,

    [string] $Server,

    [switch] $Revoke,

    [switch] $RemoveOtherPermissions
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$InformationPreference = 'Continue'
Import-Module ActiveDirectory -Verbose:$false

$adParams = @{}
if ($Server) { $adParams.Server = $Server }

# --- Resolve the domain, schema and account --------------------------------------------------

$rootDSE = Get-ADRootDSE @adParams
$domain = Get-ADDomain @adParams
$domainDN = $domain.DistinguishedName
$pscDN = "CN=Password Settings Container,CN=System,$domainDN"

$account = Get-ADUser @adParams -Identity $Identity -Properties adminCount, primaryGroupID, objectSid, Enabled
$accountSid = [System.Security.Principal.SecurityIdentifier] $account.objectSid
Write-Verbose "Service account: $($account.DistinguishedName) ($accountSid)"

# Look up schemaIDGUIDs from this forest's schema rather than hard-coding them.
function Get-SchemaGuid {
    param([string] $LdapDisplayName)
    $entry = Get-ADObject @adParams -SearchBase $rootDSE.schemaNamingContext `
        -LDAPFilter "(lDAPDisplayName=$LdapDisplayName)" -Properties schemaIDGUID
    if (-not $entry) { throw "Schema has no '$LdapDisplayName'. Is this forest's schema at least Windows Server 2008?" }
    return [guid] $entry.schemaIDGUID
}
$guid = @{
    lockoutTime           = Get-SchemaGuid 'lockoutTime'
    userAccountControl    = Get-SchemaGuid 'userAccountControl'
    description           = Get-SchemaGuid 'description'
    resultantPSO          = Get-SchemaGuid 'msDS-ResultantPSO'
    lockoutThreshold      = Get-SchemaGuid 'msDS-LockoutThreshold'
    userClass             = Get-SchemaGuid 'user'
    passwordSettingsClass = Get-SchemaGuid 'msDS-PasswordSettings'
}

# --- Refuse privileged accounts ---------------------------------------------------------------

# RIDs of domain groups, and SIDs of builtin groups, that already confer broad rights.
$privilegedRids = @{
    512 = 'Domain Admins'; 516 = 'Domain Controllers'; 518 = 'Schema Admins'; 519 = 'Enterprise Admins'
    520 = 'Group Policy Creator Owners'; 526 = 'Key Admins'; 527 = 'Enterprise Key Admins'
}
$privilegedBuiltins = @{
    'S-1-5-32-544' = 'Administrators'; 'S-1-5-32-548' = 'Account Operators'; 'S-1-5-32-549' = 'Server Operators'
    'S-1-5-32-550' = 'Print Operators'; 'S-1-5-32-551' = 'Backup Operators'
}
function Get-PrivilegeName {
    param([System.Security.Principal.SecurityIdentifier] $Sid)
    if ($privilegedBuiltins.ContainsKey($Sid.Value)) { return $privilegedBuiltins[$Sid.Value] }
    $rid = [int] ($Sid.Value -split '-')[-1]
    if ($privilegedRids.ContainsKey($rid)) { return $privilegedRids[$rid] }
    return $null
}

$problems = @()
if ($account.adminCount -eq 1) {
    $problems += 'it is protected by AdminSDHolder (adminCount=1), i.e. it is or was privileged'
}
$primaryGroupName = $privilegedRids[[int] $account.primaryGroupID]
if ($primaryGroupName) { $problems += "its primary group is $primaryGroupName" }
$groups = Get-ADGroup @adParams -LDAPFilter "(member:1.2.840.113556.1.4.1941:=$($account.DistinguishedName))" -Properties objectSid
foreach ($group in $groups) {
    $name = Get-PrivilegeName ([System.Security.Principal.SecurityIdentifier] $group.objectSid)
    if ($name) { $problems += "it is a member of $name (via $($group.Name))" }
}
if ($problems -and -not $Revoke) {
    throw "Refusing to use '$($account.SamAccountName)' as the vouch service account: $($problems -join '; '). " +
    'Use a dedicated, unprivileged account.'
}
if (-not $account.Enabled) {
    Write-Warning "'$($account.SamAccountName)' is disabled. vouch can't bind as it until it's enabled."
}

# --- The exact permission set -----------------------------------------------------------------

$allow = [System.Security.AccessControl.AccessControlType]::Allow
$descendents = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents
$readProperty = [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty
$writeProperty = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty

function Build-Rule {
    param($Rights, [guid] $Attribute, [guid] $InheritedClass)
    New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $accountSid, $Rights, $allow, $Attribute, $descendents, $InheritedClass)
}

$ouRules = @(
    @{ Name = 'Write lockoutTime on users'; Rule = Build-Rule -Rights $writeProperty -Attribute $guid.lockoutTime -InheritedClass $guid.userClass }
    @{ Name = 'Write userAccountControl on users'; Rule = Build-Rule -Rights $writeProperty -Attribute $guid.userAccountControl -InheritedClass $guid.userClass }
    @{ Name = 'Write description on users'; Rule = Build-Rule -Rights $writeProperty -Attribute $guid.description -InheritedClass $guid.userClass }
    @{ Name = 'Read msDS-ResultantPSO on users'; Rule = Build-Rule -Rights $readProperty -Attribute $guid.resultantPSO -InheritedClass $guid.userClass }
)
$pscRules = @(
    @{ Name = 'Read msDS-LockoutThreshold on password settings objects'
        Rule = Build-Rule -Rights $readProperty -Attribute $guid.lockoutThreshold -InheritedClass $guid.passwordSettingsClass }
)

# --- Applying rules ---------------------------------------------------------------------------

# A dedicated drive, so -Server is honoured for ACL reads and writes too.
$driveName = 'VouchAD'
if (-not (Get-PSDrive -Name $driveName -ErrorAction SilentlyContinue)) {
    $driveParams = @{ Name = $driveName; PSProvider = 'ActiveDirectory'; Root = '//RootDSE/'; Scope = 'Script' }
    if ($Server) { $driveParams.Server = $Server }
    New-PSDrive @driveParams | Out-Null
}
function Get-AclPath { param([string] $DistinguishedName) "$($driveName):\$DistinguishedName" }

function Test-SameRule {
    param($A, $B)
    $A.IdentityReference -eq $B.IdentityReference -and
    $A.ActiveDirectoryRights -eq $B.ActiveDirectoryRights -and
    $A.AccessControlType -eq $B.AccessControlType -and
    $A.ObjectType -eq $B.ObjectType -and
    $A.InheritedObjectType -eq $B.InheritedObjectType -and
    $A.InheritanceType -eq $B.InheritanceType
}

# Explicit rules for the account on an ACL, with identities as SIDs so they compare reliably.
function Get-AccountRule {
    param($Acl)
    $Acl.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]) |
        Where-Object { $_.IdentityReference -eq $accountSid }
}

function Set-VouchPermission {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [string] $DistinguishedName,
        [array] $Wanted,
        [switch] $Revoke,
        [switch] $RemoveOther
    )

    $path = Get-AclPath $DistinguishedName
    $acl = Get-Acl -Path $path
    $existing = @(Get-AccountRule $acl)
    $changed = $false

    foreach ($item in $Wanted) {
        $present = @($existing | Where-Object { Test-SameRule $_ $item.Rule })
        if ($Revoke) {
            if ($present -and $PSCmdlet.ShouldProcess($DistinguishedName, "Remove: $($item.Name)")) {
                $acl.RemoveAccessRuleSpecific($item.Rule)
                $changed = $true
                Write-Information "  removed  $($item.Name)"
            }
        }
        elseif ($present) {
            Write-Information "  present  $($item.Name)"
        }
        elseif ($PSCmdlet.ShouldProcess($DistinguishedName, "Grant: $($item.Name)")) {
            $acl.AddAccessRule($item.Rule)
            $changed = $true
            Write-Information "  granted  $($item.Name)"
        }
    }

    # Anything else the account holds explicitly here is more than vouch needs.
    $others = @($existing | Where-Object { $rule = $_; -not ($Wanted | Where-Object { Test-SameRule $rule $_.Rule }) })
    foreach ($other in $others) {
        $what = "$($other.AccessControlType) $($other.ActiveDirectoryRights) (object type $($other.ObjectType))"
        if ($RemoveOther -and $PSCmdlet.ShouldProcess($DistinguishedName, "Remove extra permission: $what")) {
            $acl.RemoveAccessRuleSpecific($other)
            $changed = $true
            Write-Information "  removed extra  $what"
        }
        elseif (-not $RemoveOther) {
            Write-Warning "$DistinguishedName grants '$($account.SamAccountName)' an extra permission: $what. Use -RemoveOtherPermissions to remove it."
        }
    }

    if ($changed) { Set-Acl -Path $path -AclObject $acl }
}

# Warn about inherited permissions too: they can't be removed here, but they also exceed the set.
function Test-InheritedPermission {
    param([string] $DistinguishedName)
    $acl = Get-Acl -Path (Get-AclPath $DistinguishedName)
    $inherited = @($acl.GetAccessRules($false, $true, [System.Security.Principal.SecurityIdentifier]) |
            Where-Object { $_.IdentityReference -eq $accountSid })
    foreach ($rule in $inherited) {
        Write-Warning ("$DistinguishedName inherits a permission for '$($account.SamAccountName)' from a parent: " +
            "$($rule.AccessControlType) $($rule.ActiveDirectoryRights) (object type $($rule.ObjectType)). Remove it at the parent.")
    }
}

# --- Go ---------------------------------------------------------------------------------------

$verb = if ($Revoke) { 'Revoking' } else { 'Granting' }
Write-Information "$verb vouch permissions for $($account.SamAccountName) ($accountSid)"

foreach ($ou in $TargetOU) {
    $target = Get-ADObject @adParams -Identity $ou
    if ($target.DistinguishedName -eq $domainDN) {
        throw "Don't delegate at the domain root ($domainDN). Pass the OUs holding the users vouch may unlock."
    }
    Write-Information "$($target.DistinguishedName):"
    Set-VouchPermission -DistinguishedName $target.DistinguishedName -Wanted $ouRules -Revoke:$Revoke -RemoveOther:$RemoveOtherPermissions
    Test-InheritedPermission -DistinguishedName $target.DistinguishedName
}

Write-Information "${pscDN}:"
Set-VouchPermission -DistinguishedName $pscDN -Wanted $pscRules -Revoke:$Revoke -RemoveOther:$RemoveOtherPermissions

# The account should hold nothing explicit on the domain root at all.
Write-Information "${domainDN}:"
Set-VouchPermission -DistinguishedName $domainDN -Wanted @() -Revoke:$Revoke -RemoveOther:$RemoveOtherPermissions

# Password settings objects with inheritance blocked won't receive the read permission, and
# vouch then refuses to unlock their members rather than guess the lockout threshold.
if (-not $Revoke) {
    foreach ($pso in Get-ADObject @adParams -SearchBase $pscDN -SearchScope OneLevel -LDAPFilter '(objectClass=msDS-PasswordSettings)') {
        if ((Get-Acl -Path (Get-AclPath $pso.DistinguishedName)).AreAccessRulesProtected) {
            Write-Warning ("Password settings object '$($pso.Name)' blocks inheritance, so vouch can't read its lockout " +
                'threshold and will refuse to unlock its members. Enable inheritance on it, or grant the read directly.')
        }
    }
}

Write-Information 'Done. Changes may take a few minutes to replicate to every domain controller.'
