import { api, ApiError, type Account, type Info, type SessionState } from "./api";

// --- DOM helpers ----------------------------------------------------------------------------
// Everything is built with text nodes, never innerHTML, so directory data can't inject markup.

type Child = Node | string | null | undefined | false;
type Attrs = Record<string, string | boolean | EventListener | undefined>;

function h<K extends keyof HTMLElementTagNameMap>(tag: K, attrs: Attrs = {}, ...children: Child[]): HTMLElementTagNameMap[K] {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === undefined || value === false) continue;
    if (typeof value === "function") {
      el.addEventListener(key.replace(/^on/, ""), value);
    } else if (value === true) {
      el.setAttribute(key, "");
    } else {
      el.setAttribute(key, value);
    }
  }
  for (const child of children) {
    if (child === null || child === undefined || child === false) continue;
    el.append(child);
  }
  return el;
}

const app = document.getElementById("app") as HTMLElement;
const steps = document.getElementById("steps") as HTMLOListElement;
const title = document.getElementById("title") as HTMLHeadingElement;

let info: Info = {
  title: "Account unlock",
  voucherDescription: "an authorised colleague",
  sessionLifetimeSeconds: 300,
  confirmWindowSeconds: 120,
};

// --- Countdown ------------------------------------------------------------------------------

let countdownTimer: number | undefined;

function formatRemaining(ms: number): string {
  const total = Math.max(0, Math.ceil(ms / 1000));
  const minutes = Math.floor(total / 60);
  const seconds = total % 60;
  return `${minutes}:${seconds.toString().padStart(2, "0")}`;
}

/** countdown renders a ticking timer to deadline, and refreshes the session when it passes. */
function countdown(label: string, deadline: string | undefined): HTMLElement | null {
  if (!deadline) return null;
  const end = Date.parse(deadline);
  const value = h("strong", {}, formatRemaining(end - Date.now()));
  const el = h("p", { class: "countdown" }, label, " ", value);
  window.clearInterval(countdownTimer);
  countdownTimer = window.setInterval(() => {
    const remaining = end - Date.now();
    value.textContent = formatRemaining(remaining);
    el.classList.toggle("urgent", remaining < 30_000);
    if (remaining <= 0) {
      window.clearInterval(countdownTimer);
      void refresh("This request has expired. Please start again.");
    }
  }, 500);
  return el;
}

// --- Shared pieces --------------------------------------------------------------------------

function alertBox(message: string | undefined, kind: "error" | "info" = "error"): HTMLElement | null {
  if (!message) return null;
  return h("div", { class: `alert ${kind}`, role: kind === "error" ? "alert" : "status" }, message);
}

function field(id: string, label: string, input: HTMLInputElement): HTMLElement {
  input.id = id;
  return h("div", { class: "field" }, h("label", { for: id }, label), input);
}

function setSteps(active: "vouch" | "claim" | "confirm" | "done"): void {
  const order = ["vouch", "claim", "confirm"];
  const activeIdx = active === "done" ? order.length : order.indexOf(active);
  for (const li of Array.from(steps.children) as HTMLElement[]) {
    const idx = order.indexOf(li.dataset.step ?? "");
    li.classList.toggle("done", idx < activeIdx);
    li.classList.toggle("active", idx === activeIdx);
    if (idx === activeIdx) li.setAttribute("aria-current", "step");
    else li.removeAttribute("aria-current");
  }
}

function render(...children: Child[]): void {
  window.clearInterval(countdownTimer);
  app.replaceChildren(...children.filter((c): c is Node | string => !!c));
  const focusTarget = app.querySelector<HTMLElement>("[autofocus]") ?? app.querySelector<HTMLElement>("h2");
  focusTarget?.focus();
}

/** submitting disables a form while a request is in flight. */
async function submitting<T>(form: HTMLFormElement, work: () => Promise<T>): Promise<T> {
  const controls = Array.from(form.querySelectorAll<HTMLInputElement | HTMLButtonElement>("input, button"));
  controls.forEach((c) => (c.disabled = true));
  form.setAttribute("aria-busy", "true");
  try {
    return await work();
  } finally {
    controls.forEach((c) => (c.disabled = false));
    form.removeAttribute("aria-busy");
  }
}

/** handleError shows an error. If the session is gone or moved on, the view is refreshed first. */
async function handleError(err: unknown, retry: (message: string) => void): Promise<void> {
  const message = err instanceof Error ? err.message : String(err);
  if (err instanceof ApiError && ["no_session", "session_expired", "wrong_stage", "presence_mismatch"].includes(err.code)) {
    await refresh(message);
    return;
  }
  retry(message);
}

async function cancel(): Promise<void> {
  try {
    await api.cancel();
  } finally {
    showVoucher();
  }
}

function cancelButton(label = "Cancel"): HTMLButtonElement {
  return h("button", { type: "button", class: "secondary", onclick: () => void cancel() }, label);
}

function accountDetails(account: Account): HTMLElement {
  const rows: [string, string | undefined][] = [
    ["Name", account.displayName],
    ["Username", account.username],
    ["Job title", account.title],
    ["Department", account.department],
    ["Email", account.mail],
    ["Description", account.description],
  ];
  return h(
    "dl",
    { class: "account" },
    ...rows.filter(([, v]) => !!v).flatMap(([k, v]) => [h("dt", {}, k), h("dd", {}, v as string)]),
  );
}

// --- Views ----------------------------------------------------------------------------------

/** credentialInputs makes username and password fields the browser is asked not to remember:
 * every step may happen on a computer that belongs to someone else. */
function credentialInputs(prefix: string): [HTMLInputElement, HTMLInputElement] {
  const noSave = { autocomplete: "off", "data-lpignore": "true", "data-1p-ignore": "true" };
  const username = h("input", {
    type: "text", name: `${prefix}-username`, autocapitalize: "none", spellcheck: "false",
    required: true, maxlength: "256", ...noSave,
  });
  const password = h("input", {
    type: "password", name: `${prefix}-password`, required: true, maxlength: "1024", ...noSave,
  });
  return [username, password];
}

function showVoucher(error?: string): void {
  setSteps("vouch");
  const [usernameInput, passwordInput] = credentialInputs("voucher");
  usernameInput.autofocus = true;
  const form = h(
    "form",
    { autocomplete: "off" },
    field("voucher-username", "Your username", usernameInput),
    field("voucher-password", "Your password", passwordInput),
    h("div", { class: "actions" }, h("button", { type: "submit" }, "Sign in")),
  );
  form.addEventListener("submit", (ev) => {
    ev.preventDefault();
    const user = usernameInput.value;
    const pass = passwordInput.value;
    passwordInput.value = "";
    void submitting(form, () => api.vouch(user, pass))
      .then(show)
      .catch((err) => handleError(err, (message) => showVoucher(message)));
  });
  render(
    h("h2", { tabindex: "-1" }, "Unlock a colleague's account"),
    h(
      "p",
      {},
      "Accounts are unlocked in person. First, ",
      h("strong", {}, info.voucherDescription),
      " signs in here. Then the locked-out user enters their own username and password on this screen, " +
        "and you confirm who they are.",
    ),
    alertBox(error),
    form,
    h("p", { class: "muted small" }, "Locked out yourself? Ask ", info.voucherDescription, " to start this for you."),
  );
}

function showClaim(state: SessionState, error?: string, username = ""): void {
  setSteps("claim");
  const [usernameInput, passwordInput] = credentialInputs("claim");
  usernameInput.value = username;
  usernameInput.autofocus = !username;
  passwordInput.autofocus = !!username;
  const form = h(
    "form",
    { autocomplete: "off" },
    field("claim-username", "Username", usernameInput),
    field("claim-password", "Current password", passwordInput),
    h("div", { class: "actions" }, h("button", { type: "submit" }, "Continue"), cancelButton()),
  );
  form.addEventListener("submit", (ev) => {
    ev.preventDefault();
    const user = usernameInput.value;
    const pass = passwordInput.value;
    passwordInput.value = "";
    void submitting(form, () => api.claim(user, pass))
      .then(show)
      .catch((err) => handleError(err, (message) => showClaim(state, message, user)));
  });
  render(
    h("h2", { tabindex: "-1" }, "Hand this device to the locked-out user"),
    h(
      "div",
      { class: "handover" },
      h("p", {}, h("strong", {}, state.voucher?.displayName ?? ""), " is signed in and will vouch for you."),
      h("p", {}, "Enter your own username and the password you normally use. It's checked once your account is unlocked."),
    ),
    info.helpText ? h("p", { class: "muted" }, info.helpText) : null,
    alertBox(error),
    form,
    countdown("This request expires in", state.expiresAt),
  );
}

function showConfirm(state: SessionState, error?: string): void {
  setSteps("confirm");
  const target = state.target as Account;
  const voucher = state.voucher as Account;
  const attest = h("input", { type: "checkbox", id: "attest", name: "attest" });
  const [usernameInput, passwordInput] = credentialInputs("confirm");
  const unlockButton = h("button", { type: "submit", disabled: true }, "Unlock account");
  attest.addEventListener("change", () => (unlockButton.disabled = !attest.checked));
  const form = h(
    "form",
    { autocomplete: "off" },
    h(
      "label",
      { class: "attest", for: "attest" },
      attest,
      h(
        "span",
        {},
        "I am with ",
        h("strong", {}, target.displayName),
        " in person right now, and I have confirmed they are who they say they are.",
      ),
    ),
    h("p", { class: "muted small" }, "Sign in again as ", h("strong", {}, voucher.username), " to unlock the account."),
    field("confirm-username", "Your username", usernameInput),
    field("confirm-password", "Your password", passwordInput),
    h("div", { class: "actions" }, unlockButton, cancelButton()),
  );
  form.addEventListener("submit", (ev) => {
    ev.preventDefault();
    if (!attest.checked) return;
    const user = usernameInput.value;
    const pass = passwordInput.value;
    passwordInput.value = "";
    void submitting(form, () => api.confirm(user, pass, true))
      .then(show)
      .catch((err) => handleError(err, (message) => showConfirm(state, message)));
  });
  render(
    h("h2", { tabindex: "-1" }, "Check who you're vouching for"),
    h(
      "p",
      {},
      "Hand the device back to ",
      h("strong", {}, voucher.displayName),
      ". Make sure these details match the person with you.",
    ),
    accountDetails(target),
    alertBox(error),
    form,
    countdown("Confirm within", state.confirmBy),
  );
}

function showComplete(state: SessionState): void {
  setSteps("done");
  const outcomes = {
    unlocked: { kind: "success", heading: "Account unlocked" },
    not_locked: { kind: "info", heading: "This account isn't locked" },
    verification_failed: { kind: "error", heading: "Password check failed" },
    ineligible: { kind: "error", heading: "Can't unlock this account here" },
  } as const;
  const outcome = state.outcome ? outcomes[state.outcome] : { kind: "error", heading: "Something went wrong" };
  render(
    h(
      "div",
      { class: `outcome ${outcome.kind}` },
      h("h2", { tabindex: "-1" }, outcome.heading),
      h("p", {}, state.message ?? "Please start again, or contact the service desk."),
    ),
    h("div", { class: "actions" }, h("button", { type: "button", onclick: () => void cancel() }, "Done")),
  );
}

function show(state: SessionState, error?: string): void {
  switch (state.stage) {
    case "awaiting_claim":
      showClaim(state, error);
      break;
    case "awaiting_confirmation":
      showConfirm(state, error);
      break;
    case "complete":
      showComplete(state);
      break;
    default:
      showVoucher(error);
  }
}

async function refresh(error?: string): Promise<void> {
  try {
    show(await api.session(), error);
  } catch (err) {
    showVoucher(err instanceof Error ? err.message : String(err));
  }
}

async function start(): Promise<void> {
  try {
    info = await api.info();
    title.textContent = info.title;
    document.title = info.title;
  } catch {
    // Fall back to the defaults.
  }
  await refresh();
}

void start();
