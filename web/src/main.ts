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
  title: "Unlock your account",
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

function setSteps(active: "claim" | "vouch" | "confirm" | "done"): void {
  const order = ["claim", "vouch", "confirm"];
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
    showClaim();
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

function showClaim(error?: string, username = ""): void {
  setSteps("claim");
  const usernameInput = h("input", {
    type: "text", name: "username", autocomplete: "username", autocapitalize: "none",
    spellcheck: "false", required: true, maxlength: "256", value: username, autofocus: !username,
  });
  const passwordInput = h("input", {
    type: "password", name: "password", autocomplete: "current-password", required: true,
    maxlength: "1024", autofocus: !!username,
  });
  const form = h(
    "form",
    {},
    field("claim-username", "Username", usernameInput),
    field("claim-password", "Password", passwordInput),
    h("div", { class: "actions" }, h("button", { type: "submit" }, "Continue")),
  );
  form.addEventListener("submit", (ev) => {
    ev.preventDefault();
    const user = usernameInput.value;
    const pass = passwordInput.value;
    passwordInput.value = "";
    void submitting(form, () => api.claim(user, pass))
      .then(show)
      .catch((err) => handleError(err, (message) => showClaim(message, user)));
  });
  render(
    h("h2", { tabindex: "-1" }, "Locked out?"),
    h(
      "p",
      {},
      "Enter your username and your current password. Then ",
      h("strong", {}, info.voucherDescription),
      " signs in on this same screen to confirm who you are, and your account is unlocked.",
    ),
    info.helpText ? h("p", { class: "muted" }, info.helpText) : null,
    alertBox(error),
    form,
    h("p", { class: "muted small" }, "Forgotten your password? This page can't reset it. Contact the service desk instead."),
  );
}

function showVoucher(state: SessionState, error?: string): void {
  setSteps("vouch");
  // The voucher is signing in on someone else's computer. Ask the browser not to remember
  // their credentials.
  const usernameInput = h("input", {
    type: "text", name: "voucher-username", autocomplete: "off", autocapitalize: "none",
    spellcheck: "false", required: true, maxlength: "256", autofocus: true,
    "data-lpignore": "true", "data-1p-ignore": "true",
  });
  const passwordInput = h("input", {
    type: "password", name: "voucher-password", autocomplete: "off", required: true, maxlength: "1024",
    "data-lpignore": "true", "data-1p-ignore": "true",
  });
  const form = h(
    "form",
    { autocomplete: "off" },
    field("voucher-username", "Colleague's username", usernameInput),
    field("voucher-password", "Colleague's password", passwordInput),
    h("div", { class: "actions" }, h("button", { type: "submit" }, "Sign in to vouch"), cancelButton()),
  );
  form.addEventListener("submit", (ev) => {
    ev.preventDefault();
    const user = usernameInput.value;
    const pass = passwordInput.value;
    passwordInput.value = "";
    void submitting(form, () => api.vouch(user, pass))
      .then(show)
      .catch((err) => handleError(err, (message) => showVoucher(state, message)));
  });
  render(
    h("h2", { tabindex: "-1" }, "Hand this device to a colleague"),
    h(
      "div",
      { class: "handover" },
      h("p", {}, "Unlocking ", h("strong", {}, state.claimedUsername ?? ""), "."),
      h(
        "p",
        {},
        "Ask ",
        h("strong", {}, info.voucherDescription),
        " to sign in below. They must be with you in person, using this browser on this computer.",
      ),
    ),
    alertBox(error),
    form,
    countdown("This request expires in", state.expiresAt),
  );
}

function showConfirm(state: SessionState, error?: string): void {
  setSteps("confirm");
  const target = state.target as Account;
  const attest = h("input", { type: "checkbox", id: "attest", name: "attest" });
  const unlockButton = h("button", { type: "submit", disabled: true }, "Unlock account");
  attest.addEventListener("change", () => (unlockButton.disabled = !attest.checked));
  const form = h(
    "form",
    {},
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
    h("div", { class: "actions" }, unlockButton, cancelButton()),
  );
  form.addEventListener("submit", (ev) => {
    ev.preventDefault();
    if (!attest.checked) return;
    void submitting(form, () => api.confirm(true))
      .then(show)
      .catch((err) => handleError(err, (message) => showConfirm(state, message)));
  });
  render(
    h("h2", { tabindex: "-1" }, "Check who you're vouching for"),
    h("p", {}, "Signed in as ", h("strong", {}, state.voucher?.displayName ?? ""), ". Make sure these details match the person with you."),
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
    not_locked: { kind: "info", heading: "Your account isn't locked" },
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
    case "awaiting_voucher":
      showVoucher(state, error);
      break;
    case "awaiting_confirmation":
      showConfirm(state, error);
      break;
    case "complete":
      showComplete(state);
      break;
    default:
      showClaim(error);
  }
}

async function refresh(error?: string): Promise<void> {
  try {
    show(await api.session(), error);
  } catch (err) {
    showClaim(err instanceof Error ? err.message : String(err));
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
