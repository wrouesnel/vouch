// Client for the vouch API. Types mirror api/vouch.yaml.

export type Stage = "start" | "awaiting_claim" | "awaiting_confirmation" | "complete";
export type Outcome = "not_locked" | "unlocked" | "ineligible";

export interface Info {
  title: string;
  voucherDescription: string;
  helpText?: string;
  sessionLifetimeSeconds: number;
  confirmWindowSeconds: number;
}

export interface Account {
  username: string;
  displayName: string;
  mail?: string;
  title?: string;
  department?: string;
  description?: string;
}

export interface SessionState {
  stage: Stage;
  claimedUsername?: string;
  voucher?: Account;
  target?: Account;
  outcome?: Outcome;
  message?: string;
  expiresAt?: string;
  confirmBy?: string;
}

export interface Problem {
  code: string;
  message: string;
}

/** ApiError carries a Problem returned by the server. */
export class ApiError extends Error {
  readonly code: string;
  readonly status: number;

  constructor(status: number, problem: Problem) {
    super(problem.message);
    this.code = problem.code;
    this.status = status;
  }
}

const base = "/api/v1";

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const init: RequestInit = {
    method,
    credentials: "same-origin",
    cache: "no-store",
    headers: { Accept: "application/json" },
  };
  if (body !== undefined) {
    init.headers = { ...init.headers, "Content-Type": "application/json" };
    init.body = JSON.stringify(body);
  }

  let response: Response;
  try {
    response = await fetch(base + path, init);
  } catch {
    throw new ApiError(0, { code: "network", message: "Couldn't reach the server. Check your connection and try again." });
  }
  if (response.status === 204) {
    return undefined as T;
  }
  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    throw new ApiError(response.status, { code: "bad_response", message: `The server returned an unexpected response (${response.status}).` });
  }
  if (!response.ok) {
    throw new ApiError(response.status, payload as Problem);
  }
  return payload as T;
}

export const api = {
  info: () => request<Info>("GET", "/info"),
  session: () => request<SessionState>("GET", "/session"),
  cancel: () => request<void>("DELETE", "/session"),
  vouch: (username: string, password: string) =>
    request<SessionState>("POST", "/session/voucher", { username, password }),
  claim: (username: string, password: string) =>
    request<SessionState>("POST", "/session/claim", { username, password }),
  confirm: (username: string, password: string, attest: boolean) =>
    request<SessionState>("POST", "/session/confirm", { username, password, attest }),
};
