// Thin client for BioVault's API + WebAuthn ceremonies.
import { startRegistration, startAuthentication } from "@simplewebauthn/browser";
import { generateIdentityKeys } from "./crypto";

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...init,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new ApiError(data.error ?? `Request failed (${res.status})`, res.status, data);
  }
  return data as T;
}

export class ApiError extends Error {
  constructor(message: string, public status: number, public data: Record<string, unknown>) {
    super(message);
  }
}

export async function registerWithBiometrics(email: string): Promise<void> {
  const options = await api<Parameters<typeof startRegistration>[0]["optionsJSON"]>(
    "/api/auth/register/options",
    { method: "POST", body: JSON.stringify({ email }) }
  );
  // OS biometric prompt (Touch ID / Face ID / Windows Hello)
  const response = await startRegistration({ optionsJSON: options });
  // Generate the E2E identity key pair locally; only the public half is published.
  const { publicJwk } = await generateIdentityKeys(email.trim().toLowerCase());
  await api("/api/auth/register/verify", {
    method: "POST",
    body: JSON.stringify({ response, publicJwk }),
  });
}

export async function loginWithBiometrics(email: string): Promise<void> {
  const options = await api<Parameters<typeof startAuthentication>[0]["optionsJSON"]>(
    "/api/auth/login/options",
    { method: "POST", body: JSON.stringify({ email }) }
  );
  const response = await startAuthentication({ optionsJSON: options });
  await api("/api/auth/login/verify", {
    method: "POST",
    body: JSON.stringify({ response }),
  });
}

/** Fresh biometric assertion; returns a one-shot token for protected opens. */
export async function reauthWithBiometrics(): Promise<string> {
  const options = await api<Parameters<typeof startAuthentication>[0]["optionsJSON"]>(
    "/api/auth/reauth/options",
    { method: "POST", body: JSON.stringify({}) }
  );
  const response = await startAuthentication({ optionsJSON: options });
  const { reauthToken } = await api<{ reauthToken: string }>("/api/auth/reauth/verify", {
    method: "POST",
    body: JSON.stringify({ response }),
  });
  return reauthToken;
}
