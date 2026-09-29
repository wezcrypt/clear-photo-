// VoidMail client protocol: everything the browser does with keys and ciphertext.
// Transport-agnostic so the same code runs in the web app and in integration tests.
import * as C from './crypto.js';
import type { KdfParams } from './crypto.js';
import type { AttachmentRef, BodyPayload, HeaderPayload, SecurityLabel } from './mail.js';
import { isValidUsername, makeSnippet, normalizeAddress, sanitizeFilename } from './mail.js';

type OpenPGPKey = Awaited<ReturnType<typeof C.readPublicKey>>;
type OpenPGPPrivateKey = Awaited<ReturnType<typeof C.unlockPrivateKey>>;

export interface TransportResponse {
  status: number;
  data: any;
  bytes?: Uint8Array;
}
export type Transport = (
  method: string,
  path: string,
  opts?: { json?: unknown; bytes?: Uint8Array; headers?: Record<string, string>; binary?: boolean },
) => Promise<TransportResponse>;

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    public detail?: unknown,
  ) {
    super(code);
  }
}

export class KeyChangedError extends Error {
  constructor(public changes: { address: string; oldFingerprint: string; newFingerprint: string }[]) {
    super('key_changed');
  }
}

export interface SessionInfo {
  user: {
    id: string;
    username: string;
    address: string;
    displayName: string;
    locale: 'en' | 'ar';
    theme: 'system' | 'dark' | 'light';
    remoteImages: 'ask' | 'never';
    totpEnabled: boolean;
    recoveryEmail: string | null;
    hasRecoveryKey: boolean;
    quotaBytes: number;
  };
  csrf: string;
  domain: string;
  mkWrappedPassword: string;
  keys: { id: string; fingerprint: string; status: 'active' | 'retired' | 'locked'; publicKey: string; privateKeyEnc: string; createdAt: string }[];
}

export interface Pin {
  fingerprint: string;
  verified: boolean;
  firstSeen: string;
  history?: { fingerprint: string; replacedAt: string }[];
}
interface Vault {
  v: 1;
  pins: Record<string, Pin>;
}

export type KeyStatus = 'self' | 'new' | 'pinned' | 'verified' | 'changed';

export interface RecipientKeyInfo {
  address: string;
  internal: boolean;
  exists?: boolean;
  fingerprint?: string;
  status?: KeyStatus;
  pinnedFingerprint?: string;
  key?: OpenPGPKey;
}

export interface ListItem {
  id: string;
  folder: string;
  kind: string;
  security: SecurityLabel;
  unread: boolean;
  starred: boolean;
  size: number;
  receivedAt: string;
  senderAddress: string | null;
  messageId: string | null;
  inReplyTo: string | null;
  labels: string[];
  header: HeaderPayload | null;
  error?: 'undecryptable';
}

export interface OpenedMessage extends ListItem {
  body: BodyPayload | null;
  signature: C.SignatureStatus | 'n/a';
  senderKeyStatus?: KeyStatus;
  integrity: 'ok' | 'mismatch';
  blobIds: string[];
}

export interface ComposeInput {
  to: string[];
  cc: string[];
  bcc: string[];
  subject: string;
  text: string;
  html?: string;
  attachments: { id: string; name: string; type: string; size: number; key: string }[];
  requireTls: boolean;
  inReplyTo?: string;
  references?: string[];
  draftId?: string;
}

const DEFAULT_KDF: KdfParams = C.DEFAULT_KDF;

export class VoidClient {
  session: SessionInfo | null = null;
  private mk: Uint8Array | null = null;
  private privateKeys = new Map<string, OpenPGPPrivateKey>();
  private vault: Vault | null = null;
  private vaultVersion = 0;

  constructor(private readonly transport: Transport) {}

  // ---------- plumbing ----------

  async call(method: string, path: string, json?: unknown): Promise<any> {
    const headers: Record<string, string> = { 'X-Requested-With': 'voidmail' };
    if (this.session) headers['X-CSRF-Token'] = this.session.csrf;
    const res = await this.transport(method, path, { json, headers });
    if (res.status >= 400) throw new ApiError(res.status, res.data?.error ?? 'error', res.data?.detail);
    return res.data;
  }

  get unlocked(): boolean {
    return this.mk !== null && this.privateKeys.size > 0;
  }

  get address(): string {
    return this.session!.user.address;
  }

  activeKeyInfo() {
    return this.session!.keys.find((k) => k.status === 'active')!;
  }

  private activePrivate(): OpenPGPPrivateKey {
    const k = this.privateKeys.get(this.activeKeyInfo().fingerprint);
    if (!k) throw new Error('mailbox locked');
    return k;
  }

  private async ownPublicKeys(): Promise<OpenPGPKey[]> {
    return Promise.all(this.session!.keys.filter((k) => k.status !== 'locked').map((k) => C.readPublicKey(k.publicKey)));
  }

  lock(): void {
    this.mk?.fill(0);
    this.mk = null;
    this.privateKeys.clear();
    this.vault = null;
  }

  private async params(): Promise<{ kdfParams: KdfParams; domain: string; registrationOpen: boolean }> {
    return this.call('GET', '/api/auth/params');
  }

  private async newCredentials(password: string, mk: Uint8Array, kdfParams: KdfParams) {
    const salt = C.randomBytes(16);
    const { authKey, wrapKey } = await C.deriveCredentials(password, salt, kdfParams);
    return {
      salt: C.toB64(salt),
      kdfParams,
      authKey: C.toB64(authKey),
      mkWrappedPassword: C.toB64(await C.aesGcmEncrypt(wrapKey, mk, C.AAD.mkPassword)),
    };
  }

  private async newRecovery(mk: Uint8Array) {
    const recoveryKey = C.randomBytes(32);
    const { recoveryAuth, recoveryWrap } = await C.deriveRecovery(recoveryKey);
    return {
      display: C.encodeRecoveryKey(recoveryKey),
      fields: {
        recoveryAuth: C.toB64(recoveryAuth),
        mkWrappedRecovery: C.toB64(await C.aesGcmEncrypt(recoveryWrap, mk, C.AAD.mkRecovery)),
      },
    };
  }

  private async newKeyFields(address: string, name: string, mk: Uint8Array) {
    const k = await C.generateUserKey(address, name, mk);
    // The revocation certificate is stored encrypted with a key derived from the Mailbox Key.
    const rcKey = await C.hkdf(mk, 'voidmail/v1/revocation-cert');
    return {
      publicKey: k.publicKey,
      privateKeyEnc: k.privateKeyEnc,
      fingerprint: k.fingerprint,
      revocationCertEnc: C.toB64(await C.aesGcmEncrypt(rcKey, C.utf8Encoder.encode(k.revocationCertificate), 'voidmail/v1/rc')),
    };
  }

  private async unlockWithMk(mk: Uint8Array): Promise<void> {
    this.mk = mk;
    this.privateKeys.clear();
    for (const k of this.session!.keys) {
      if (k.status === 'locked') continue;
      this.privateKeys.set(k.fingerprint, await C.unlockPrivateKey(k.privateKeyEnc, mk));
    }
    await this.loadVault();
  }

  // ---------- account lifecycle ----------

  async register(input: { username: string; password: string; displayName?: string; recoveryEmail?: string | null }): Promise<{ recoveryKey: string }> {
    if (!isValidUsername(input.username.trim().toLowerCase())) throw new ApiError(400, 'invalid_username');
    if (input.password.length < 10) throw new ApiError(400, 'weak_password');
    const { kdfParams, domain } = await this.params();
    const mk = C.randomBytes(32);
    const address = `${input.username.trim().toLowerCase()}@${domain}`;
    const creds = await this.newCredentials(input.password, mk, kdfParams);
    const rec = await this.newRecovery(mk);
    const key = await this.newKeyFields(address, input.displayName ?? '', mk);
    this.session = await this.call('POST', '/api/auth/register', {
      username: input.username.trim().toLowerCase(),
      displayName: input.displayName ?? '',
      recoveryEmail: input.recoveryEmail || null,
      ...creds,
      ...rec.fields,
      ...key,
    });
    await this.unlockWithMk(mk);
    return { recoveryKey: rec.display };
  }

  /** Step 1: returns 'mfa' if a TOTP code is needed. Keeps the derived wrap key in memory only until unlock. */
  private pendingWrap: Uint8Array | null = null;
  async login(username: string, password: string): Promise<{ mfaRequired: true; challenge: string } | { mfaRequired: false }> {
    const pre = await this.call('POST', '/api/auth/prelogin', { username });
    const { authKey, wrapKey } = await C.deriveCredentials(password, C.fromB64(pre.salt), pre.kdfParams);
    const res = await this.call('POST', '/api/auth/login', { username, authKey: C.toB64(authKey) });
    if (res.mfaRequired) {
      this.pendingWrap = wrapKey;
      return { mfaRequired: true, challenge: res.challenge };
    }
    this.session = res;
    await this.finishUnlock(wrapKey);
    return { mfaRequired: false };
  }

  async loginTotp(challenge: string, code: string): Promise<void> {
    this.session = await this.call('POST', '/api/auth/login/totp', { challenge, code });
    if (!this.pendingWrap) throw new Error('no pending login');
    await this.finishUnlock(this.pendingWrap);
    this.pendingWrap = null;
  }

  private async finishUnlock(wrapKey: Uint8Array): Promise<void> {
    const mk = await C.aesGcmDecrypt(wrapKey, C.fromB64(this.session!.mkWrappedPassword), C.AAD.mkPassword);
    wrapKey.fill(0);
    await this.unlockWithMk(mk);
  }

  /** Resume an existing cookie session (page reload). Returns false if not logged in. */
  async resume(): Promise<boolean> {
    try {
      this.session = await this.call('GET', '/api/session');
      return true;
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) return false;
      throw e;
    }
  }

  /** Unlock after reload: re-derive the wrap key from the password. */
  async unlock(password: string): Promise<void> {
    const pre = await this.call('POST', '/api/auth/prelogin', { username: this.session!.user.username });
    const { wrapKey } = await C.deriveCredentials(password, C.fromB64(pre.salt), pre.kdfParams);
    try {
      await this.finishUnlock(wrapKey);
    } catch {
      throw new ApiError(401, 'invalid_credentials');
    }
  }

  async refreshSession(): Promise<void> {
    this.session = await this.call('GET', '/api/session');
  }

  async logout(): Promise<void> {
    await this.call('POST', '/api/auth/logout').catch(() => undefined);
    this.lock();
    this.session = null;
  }

  private async authKeyFor(password: string): Promise<string> {
    const pre = await this.call('POST', '/api/auth/prelogin', { username: this.session!.user.username });
    const { authKey } = await C.deriveCredentials(password, C.fromB64(pre.salt), pre.kdfParams);
    return C.toB64(authKey);
  }

  async changePassword(currentPassword: string, newPassword: string): Promise<void> {
    if (!this.mk) throw new Error('mailbox locked');
    const currentAuthKey = await this.authKeyFor(currentPassword);
    const creds = await this.newCredentials(newPassword, this.mk, (await this.params()).kdfParams);
    this.session = await this.call('POST', '/api/auth/change-password', { currentAuthKey, ...creds });
  }

  async regenerateRecoveryKey(password: string): Promise<string> {
    if (!this.mk) throw new Error('mailbox locked');
    const authKey = await this.authKeyFor(password);
    const rec = await this.newRecovery(this.mk);
    await this.call('POST', '/api/security/recovery-key', { authKey, ...rec.fields });
    return rec.display;
  }

  /** Password reset with the recovery key: mail stays readable. Returns the NEW recovery key. */
  async recoverWithKey(username: string, recoveryKeyText: string, newPassword: string): Promise<string> {
    const recoveryKey = C.decodeRecoveryKey(recoveryKeyText);
    const { recoveryAuth, recoveryWrap } = await C.deriveRecovery(recoveryKey);
    const start = await this.call('POST', '/api/recovery/start', { username, recoveryAuth: C.toB64(recoveryAuth) });
    const mk = await C.aesGcmDecrypt(recoveryWrap, C.fromB64(start.mkWrappedRecovery), C.AAD.mkRecovery);
    const creds = await this.newCredentials(newPassword, mk, (await this.params()).kdfParams);
    const rec = await this.newRecovery(mk);
    this.session = await this.call('POST', '/api/recovery/complete', { challenge: start.challenge, ...creds, ...rec.fields });
    await this.unlockWithMk(mk);
    return rec.display;
  }

  async requestEmailReset(username: string): Promise<void> {
    await this.call('POST', '/api/recovery/email-request', { username });
  }

  /** Reset via email link WITHOUT recovery key: new keys, existing mail becomes permanently unreadable. */
  async completeEmailReset(input: { token: string; username: string; newPassword: string; totpCode?: string; displayName?: string }): Promise<string> {
    const { kdfParams, domain } = await this.params();
    const mk = C.randomBytes(32);
    const creds = await this.newCredentials(input.newPassword, mk, kdfParams);
    const rec = await this.newRecovery(mk);
    const key = await this.newKeyFields(`${input.username.toLowerCase()}@${domain}`, input.displayName ?? '', mk);
    this.session = await this.call('POST', '/api/recovery/email-complete', {
      token: input.token,
      acknowledgeDataLoss: true,
      totpCode: input.totpCode,
      ...creds,
      ...rec.fields,
      ...key,
    });
    await this.unlockWithMk(mk);
    return rec.display;
  }

  async rotateKey(): Promise<string> {
    if (!this.mk) throw new Error('mailbox locked');
    const key = await this.newKeyFields(this.address, this.session!.user.displayName, this.mk);
    await this.call('POST', '/api/keys/rotate', key);
    await this.refreshSession();
    await this.unlockWithMk(this.mk);
    await this.saveVault(); // re-encrypt the vault to the new key
    return key.fingerprint;
  }

  async deleteAccount(password: string): Promise<void> {
    const authKey = await this.authKeyFor(password);
    await this.call('POST', '/api/account/delete', { authKey, confirm: 'DELETE' });
    this.lock();
    this.session = null;
  }

  // ---------- 2FA ----------
  async totpSetup(): Promise<{ secret: string; uri: string }> {
    return this.call('POST', '/api/security/totp/setup');
  }
  async totpEnable(code: string): Promise<string[]> {
    return (await this.call('POST', '/api/security/totp/enable', { code })).recoveryCodes;
  }
  async totpDisable(password: string, code: string): Promise<void> {
    await this.call('POST', '/api/security/totp/disable', { authKey: await this.authKeyFor(password), code });
  }

  // ---------- vault: pinned contact keys ----------

  async loadVault(): Promise<void> {
    const res = await this.call('GET', '/api/vault');
    this.vaultVersion = res.version;
    if (!res.data) {
      this.vault = { v: 1, pins: {} };
      return;
    }
    const own = await this.ownPublicKeys();
    try {
      const out = await C.decryptJson<Vault>(C.fromB64(res.data), [...this.privateKeys.values()], own);
      if (out.signature !== 'valid') throw new Error('vault signature ' + out.signature);
      this.vault = out.value;
    } catch (e) {
      // A vault we cannot authenticate is never trusted. Start empty and surface the problem.
      console.warn('[vault] could not verify stored contact pins:', (e as Error).message);
      this.vault = { v: 1, pins: {} };
      this.vaultProblem = true;
    }
  }
  vaultProblem = false;

  async saveVault(): Promise<void> {
    if (!this.vault) return;
    const data = await C.encryptJson(this.vault, await C.readPublicKey(this.activeKeyInfo().publicKey), this.activePrivate());
    try {
      const res = await this.call('PUT', '/api/vault', { version: this.vaultVersion, data: C.toB64(data) });
      this.vaultVersion = res.version;
    } catch (e) {
      if (e instanceof ApiError && e.code === 'vault_conflict') {
        // Another device updated pins: merge (union; conflicting fingerprints keep the remote value and are re-evaluated).
        const mine = this.vault;
        await this.loadVault();
        for (const [addr, pin] of Object.entries(mine.pins)) if (!this.vault!.pins[addr]) this.vault!.pins[addr] = pin;
        const again = await C.encryptJson(this.vault, await C.readPublicKey(this.activeKeyInfo().publicKey), this.activePrivate());
        const res = await this.call('PUT', '/api/vault', { version: this.vaultVersion, data: C.toB64(again) });
        this.vaultVersion = res.version;
      } else throw e;
    }
  }

  pins(): Record<string, Pin> {
    return { ...(this.vault?.pins ?? {}) };
  }

  async setVerified(address: string, verified: boolean): Promise<void> {
    const pin = this.vault?.pins[address];
    if (!pin) throw new Error('no pinned key for ' + address);
    pin.verified = verified;
    await this.saveVault();
  }

  async acceptKeyChange(address: string, newFingerprint: string): Promise<void> {
    const pin = this.vault!.pins[address];
    const history = [...(pin?.history ?? [])];
    if (pin) history.push({ fingerprint: pin.fingerprint, replacedAt: new Date().toISOString() });
    this.vault!.pins[address] = { fingerprint: newFingerprint, verified: false, firstSeen: new Date().toISOString(), history };
    await this.saveVault();
  }

  private lookupCache = new Map<string, { at: number; data: any }>();
  private async lookup(address: string): Promise<any> {
    const hit = this.lookupCache.get(address);
    if (hit && Date.now() - hit.at < 60_000) return hit.data;
    const data = await this.call('GET', `/api/keys/lookup?address=${encodeURIComponent(address)}`);
    this.lookupCache.set(address, { at: Date.now(), data });
    return data;
  }

  /** Resolves a recipient's key and evaluates it against the pinned fingerprint (TOFU). */
  async recipientKey(rawAddress: string, opts: { pinIfNew?: boolean } = {}): Promise<RecipientKeyInfo> {
    const address = normalizeAddress(rawAddress);
    if (!address) throw new ApiError(400, 'invalid_address', rawAddress);
    if (address === this.address) {
      const a = this.activeKeyInfo();
      return { address, internal: true, exists: true, fingerprint: a.fingerprint, status: 'self', key: await C.readPublicKey(a.publicKey) };
    }
    const res = await this.lookup(address);
    if (!res.internal) return { address, internal: false };
    if (!res.exists) return { address, internal: true, exists: false };
    const key = await C.readPublicKey(res.publicKey);
    // Never trust the directory's claimed fingerprint; compute it.
    const fingerprint = key.getFingerprint();
    const pin = this.vault?.pins[address];
    let status: KeyStatus;
    if (!pin) {
      status = 'new';
      if (opts.pinIfNew !== false && this.vault) {
        this.vault.pins[address] = { fingerprint, verified: false, firstSeen: new Date().toISOString() };
        await this.saveVault();
      }
    } else if (pin.fingerprint === fingerprint) status = pin.verified ? 'verified' : 'pinned';
    else status = 'changed';
    return { address, internal: true, exists: true, fingerprint, status, pinnedFingerprint: pin?.fingerprint, key };
  }

  // ---------- messages ----------

  private toItem(m: any, header: HeaderPayload | null): ListItem {
    return {
      id: m.id,
      folder: m.folder,
      kind: m.kind,
      security: m.security,
      unread: m.unread,
      starred: m.starred,
      size: m.size,
      receivedAt: m.receivedAt,
      senderAddress: m.senderAddress,
      messageId: m.messageId,
      inReplyTo: m.inReplyTo,
      labels: m.labels ?? [],
      header,
      ...(header ? {} : { error: 'undecryptable' as const }),
    };
  }

  private async decryptHeader(m: any): Promise<HeaderPayload | null> {
    try {
      return (await C.decryptJson<HeaderPayload>(C.fromB64(m.headerEnc), [...this.privateKeys.values()])).value;
    } catch {
      return null;
    }
  }

  async list(opts: { folder?: string; label?: string; before?: string | null; limit?: number }): Promise<{ items: ListItem[]; next: string | null }> {
    const q = new URLSearchParams();
    if (opts.label) q.set('label', opts.label);
    else q.set('folder', opts.folder ?? 'inbox');
    if (opts.before) q.set('before', opts.before);
    if (opts.limit) q.set('limit', String(opts.limit));
    const res = await this.call('GET', `/api/messages?${q}`);
    const items = await Promise.all(res.messages.map(async (m: any) => this.toItem(m, await this.decryptHeader(m))));
    return { items, next: res.next };
  }

  async open(id: string): Promise<OpenedMessage> {
    const m = await this.call('GET', `/api/messages/${id}`);
    const keys = [...this.privateKeys.values()];
    let verificationKeys: OpenPGPKey[] | undefined;
    let senderKeyStatus: KeyStatus | undefined;
    const signed = m.kind === 'internal_in' || m.kind === 'internal_out' || m.kind === 'draft';
    const signerAddress: string | null = m.kind === 'draft' ? this.address : m.senderAddress;
    if (signed && signerAddress) {
      if (signerAddress === this.address) {
        verificationKeys = await this.ownPublicKeys();
        senderKeyStatus = 'self';
      } else {
        const info = await this.recipientKey(signerAddress).catch(() => null);
        if (info?.key) {
          const res = await this.lookup(info.address);
          verificationKeys = [info.key, ...(await Promise.all((res.retired ?? []).map((r: any) => C.readPublicKey(r.publicKey))))];
          // Only keys consistent with our pin (current or historical) count as trusted.
          const pin = this.vault?.pins[info.address];
          if (pin && info.status === 'changed') {
            const allowed = new Set([pin.fingerprint, ...(pin.history ?? []).map((h) => h.fingerprint)]);
            verificationKeys = verificationKeys.filter((k) => allowed.has(k.getFingerprint()));
          }
          senderKeyStatus = info.status;
        }
      }
    }
    let header: HeaderPayload | null = null;
    let body: BodyPayload | null = null;
    let signature: C.SignatureStatus | 'n/a' = 'n/a';
    try {
      const h = await C.decryptJson<HeaderPayload & { nonce?: string }>(C.fromB64(m.headerEnc), keys, verificationKeys);
      const b = await C.decryptJson<BodyPayload & { nonce?: string }>(C.fromB64(m.bodyEnc), keys, verificationKeys);
      header = h.value;
      body = b.value;
      if (signed) {
        const order: C.SignatureStatus[] = ['invalid', 'unsigned', 'unknown-key', 'valid'];
        signature = order[Math.min(order.indexOf(h.signature), order.indexOf(b.signature))];
      }
      const integrity = h.value.nonce === b.value.nonce ? 'ok' : 'mismatch';
      const fromMismatch = signed && signerAddress && header.from.address !== signerAddress;
      return { ...this.toItem(m, header), body, signature: fromMismatch ? 'invalid' : signature, senderKeyStatus, integrity, blobIds: m.blobIds };
    } catch {
      return { ...this.toItem(m, null), body: null, signature, senderKeyStatus, integrity: 'ok', blobIds: m.blobIds };
    }
  }

  async update(ids: string[], patch: { unread?: boolean; starred?: boolean; folder?: string; delete?: boolean }): Promise<void> {
    await this.call('POST', '/api/messages/bulk', { ids, ...patch });
  }

  async setLabels(id: string, labelIds: string[]): Promise<void> {
    await this.call('PUT', `/api/messages/${id}/labels`, { labelIds });
  }

  async delivery(id: string): Promise<any[]> {
    return this.call('GET', `/api/messages/${id}/delivery`);
  }

  // ---------- attachments ----------

  async uploadAttachment(name: string, type: string, data: Uint8Array): Promise<AttachmentRef> {
    const { ciphertext, key } = await C.encryptAttachment(data);
    const headers: Record<string, string> = { 'X-Requested-With': 'voidmail', 'Content-Type': 'application/octet-stream' };
    if (this.session) headers['X-CSRF-Token'] = this.session.csrf;
    const res = await this.transport('POST', '/api/attachments', { bytes: ciphertext, headers });
    if (res.status >= 400) throw new ApiError(res.status, res.data?.error ?? 'error');
    return { id: res.data.id, name: sanitizeFilename(name), type: type || 'application/octet-stream', size: data.length, key };
  }

  async downloadAttachment(ref: AttachmentRef): Promise<Uint8Array> {
    const res = await this.transport('GET', `/api/attachments/${ref.id}`, { binary: true });
    if (res.status >= 400) throw new ApiError(res.status, 'download_failed');
    return C.decryptAttachment(res.bytes!, ref.key);
  }

  // ---------- compose ----------

  private buildHeader(input: ComposeInput, includeBcc: boolean, nonce: string): HeaderPayload & { nonce: string } {
    return {
      v: 1,
      subject: input.subject,
      from: { name: this.session!.user.displayName, address: this.address },
      to: input.to,
      cc: input.cc,
      ...(includeBcc ? { bcc: input.bcc } : {}),
      date: new Date().toISOString(),
      snippet: makeSnippet(input.text),
      hasAttachments: input.attachments.length > 0,
      nonce,
    };
  }

  private buildBody(input: ComposeInput, nonce: string, draft = false): BodyPayload & { nonce: string } {
    return {
      v: 1,
      text: input.text,
      html: input.html,
      attachments: input.attachments,
      nonce,
      ...(draft ? { draft: { requireTls: input.requireTls, inReplyTo: input.inReplyTo, references: input.references } } : {}),
    };
  }

  /** Classifies recipients to decide the security label before sending. */
  async plan(input: Pick<ComposeInput, 'to' | 'cc' | 'bcc' | 'requireTls'>): Promise<{
    mode: 'e2ee' | 'standard';
    label: SecurityLabel;
    recipients: RecipientKeyInfo[];
    unknown: string[];
    changed: RecipientKeyInfo[];
  }> {
    const all = [...new Set([...input.to, ...input.cc, ...input.bcc].map((a) => normalizeAddress(a) ?? a))];
    const recipients = await Promise.all(all.map((a) => this.recipientKey(a, { pinIfNew: false })));
    const external = recipients.filter((r) => !r.internal);
    const unknown = recipients.filter((r) => r.internal && !r.exists).map((r) => r.address);
    const changed = recipients.filter((r) => r.status === 'changed');
    const mode = external.length ? 'standard' : 'e2ee';
    return { mode, label: mode === 'e2ee' ? 'e2ee' : input.requireTls ? 'standard_tls_required' : 'standard_tls_optional', recipients, unknown, changed };
  }

  async send(input: ComposeInput): Promise<{ id: string; security: SecurityLabel; messageId: string }> {
    const norm = (l: string[]) =>
      l.map((a) => {
        const n = normalizeAddress(a);
        if (!n) throw new ApiError(400, 'invalid_address', a);
        return n;
      });
    const msg = { ...input, to: norm(input.to), cc: norm(input.cc), bcc: norm(input.bcc) };
    const all = [...new Set([...msg.to, ...msg.cc, ...msg.bcc])];
    const infos = await Promise.all(all.map((a) => this.recipientKey(a)));
    const unknown = infos.filter((i) => i.internal && !i.exists);
    if (unknown.length) throw new ApiError(400, 'unknown_recipient', unknown.map((u) => u.address));
    const changed = infos.filter((i) => i.status === 'changed');
    if (changed.length) {
      throw new KeyChangedError(changed.map((c) => ({ address: c.address, oldFingerprint: c.pinnedFingerprint!, newFingerprint: c.fingerprint! })));
    }
    const external = infos.filter((i) => !i.internal).map((i) => i.address);
    const nonce = C.toB64(C.randomBytes(16));
    const signer = this.activePrivate();
    const ownKey = await C.readPublicKey(this.activeKeyInfo().publicKey);

    const sentCopy = {
      headerEnc: C.toB64(await C.encryptJson(this.buildHeader(msg, true, nonce), ownKey, signer)),
      bodyEnc: C.toB64(await C.encryptJson(this.buildBody(msg, nonce), ownKey, signer)),
      keyFingerprint: this.activeKeyInfo().fingerprint,
    };
    // One ciphertext per recipient: no recipient learns other (e.g. BCC) recipients' key IDs; BCC list only in sender copy.
    const internal = [];
    for (const i of infos.filter((x) => x.internal)) {
      internal.push({
        address: i.address,
        headerEnc: C.toB64(await C.encryptJson(this.buildHeader(msg, false, nonce), i.key!, signer)),
        bodyEnc: C.toB64(await C.encryptJson(this.buildBody(msg, nonce), i.key!, signer)),
        keyFingerprint: i.fingerprint!,
      });
    }
    const res = await this.call('POST', '/api/send', {
      draftId: msg.draftId,
      requireTls: external.length ? msg.requireTls : false,
      inReplyTo: msg.inReplyTo,
      references: msg.references,
      recipients: { to: msg.to, cc: msg.cc, bcc: msg.bcc },
      sentCopy,
      attachmentIds: msg.attachments.map((a) => a.id),
      internal,
      ...(external.length
        ? {
            external: {
              subject: msg.subject,
              text: msg.text,
              html: msg.html,
              attachments: msg.attachments.map((a) => ({ id: a.id, key: a.key, name: a.name, type: a.type })),
            },
          }
        : {}),
    });
    return { id: res.id, security: res.security, messageId: res.messageId };
  }

  async saveDraft(input: ComposeInput): Promise<string> {
    const nonce = C.toB64(C.randomBytes(16));
    const own = await C.readPublicKey(this.activeKeyInfo().publicKey);
    const signer = this.activePrivate();
    const body = {
      headerEnc: C.toB64(await C.encryptJson(this.buildHeader(input, true, nonce), own, signer)),
      bodyEnc: C.toB64(await C.encryptJson(this.buildBody(input, nonce, true), own, signer)),
      keyFingerprint: this.activeKeyInfo().fingerprint,
      attachmentIds: input.attachments.map((a) => a.id),
    };
    const res = input.draftId ? await this.call('PUT', `/api/drafts/${input.draftId}`, body) : await this.call('POST', '/api/drafts', body);
    return res.id;
  }

  async deleteDraft(id: string): Promise<void> {
    await this.call('DELETE', `/api/drafts/${id}`);
  }

  // ---------- export ----------

  async exportAll(onProgress?: (done: number) => void, includeAttachments = true): Promise<unknown> {
    const account = await this.call('GET', '/api/export/account');
    const messages: unknown[] = [];
    for (const folder of ['inbox', 'sent', 'drafts', 'archive', 'spam', 'trash']) {
      let before: string | null = null;
      do {
        const page = await this.list({ folder, before, limit: 100 });
        for (const item of page.items) {
          const full = await this.open(item.id);
          const attachments = [];
          for (const a of full.body?.attachments ?? []) {
            attachments.push({
              name: a.name,
              type: a.type,
              size: a.size,
              ...(includeAttachments ? { base64: C.toB64(await this.downloadAttachment(a).catch(() => new Uint8Array())) } : {}),
            });
          }
          messages.push({
            folder,
            security: full.security,
            receivedAt: full.receivedAt,
            unread: full.unread,
            starred: full.starred,
            header: full.header,
            text: full.body?.text,
            html: full.body?.html,
            attachments,
            decryptable: full.header !== null,
          });
          onProgress?.(messages.length);
        }
        before = page.next;
      } while (before);
    }
    return { format: 'voidmail-export-v1', account, contacts: this.pins(), messages };
  }
}

export { C as crypto };
