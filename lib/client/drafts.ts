// Drafts are metadata only (recipient, subject, text, options) and live
// in localStorage. Files are never persisted unencrypted.

export interface Draft {
  id: string;
  to: string;
  subject: string;
  body: string;
  priority: string;
  tags: string;
  security: {
    oneTime: boolean;
    downloadProtection: boolean;
    watermark: boolean;
    requireBiometric: boolean;
    screenshotWarn: boolean;
  };
  expiryChoice: string;
  customExpiry: string;
  savedAt: number;
}

const KEY = "bv_drafts";

export function loadDrafts(): Draft[] {
  try {
    return JSON.parse(localStorage.getItem(KEY) ?? "[]") as Draft[];
  } catch {
    return [];
  }
}

export function saveDraft(draft: Draft): void {
  const drafts = loadDrafts().filter((d) => d.id !== draft.id);
  drafts.unshift(draft);
  localStorage.setItem(KEY, JSON.stringify(drafts.slice(0, 50)));
}

export function deleteDraft(id: string): void {
  localStorage.setItem(KEY, JSON.stringify(loadDrafts().filter((d) => d.id !== id)));
}

export function getDraft(id: string): Draft | undefined {
  return loadDrafts().find((d) => d.id === id);
}
