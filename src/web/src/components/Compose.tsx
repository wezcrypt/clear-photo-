import { useCallback, useEffect, useRef, useState } from 'react';
import { KeyChangedError, type RecipientKeyInfo } from '../../../shared/client';
import type { AttachmentRef, SecurityLabel } from '../../../shared/mail';
import { normalizeAddress } from '../../../shared/mail';
import { formatFingerprint } from '../../../shared/crypto';
import { client, formatBytes } from '../lib/api';
import { errorText, useT } from '../lib/i18n';
import { IconClip, IconClose } from './Icons';
import { Modal, SecurityBadge, Spinner, toast } from './ui';

export interface ComposeDraft {
  draftId?: string;
  to: string;
  cc: string;
  bcc: string;
  subject: string;
  text: string;
  attachments: AttachmentRef[];
  requireTls: boolean;
  inReplyTo?: string;
  references?: string[];
}

export const emptyDraft = (): ComposeDraft => ({ to: '', cc: '', bcc: '', subject: '', text: '', attachments: [], requireTls: false });

const split = (s: string) =>
  s
    .split(/[,;\n]/)
    .map((x) => x.trim())
    .filter(Boolean);

export function Compose({ initial, onClose, onSent }: { initial: ComposeDraft; onClose: () => void; onSent: () => void }) {
  const { t } = useT();
  const [d, setD] = useState<ComposeDraft>(initial);
  const [showCc, setShowCc] = useState(Boolean(initial.cc || initial.bcc));
  const [plan, setPlan] = useState<{ label: SecurityLabel; mode: string; recipients: RecipientKeyInfo[]; unknown: string[]; invalid: string[] } | null>(null);
  const [saving, setSaving] = useState<'idle' | 'saving' | 'saved'>('idle');
  const [uploading, setUploading] = useState(0);
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [keyChanges, setKeyChanges] = useState<KeyChangedError['changes'] | null>(null);
  const dirty = useRef(false);
  const closed = useRef(false);
  const draftId = useRef<string | undefined>(initial.draftId);
  const fileInput = useRef<HTMLInputElement>(null);

  const update = (patch: Partial<ComposeDraft>) => {
    dirty.current = true;
    setD((prev) => ({ ...prev, ...patch }));
  };

  // Live security plan: which label will apply, and each recipient's key status.
  useEffect(() => {
    const id = setTimeout(async () => {
      const all = [...split(d.to), ...split(d.cc), ...split(d.bcc)];
      const invalid = all.filter((a) => !normalizeAddress(a));
      const valid = (l: string) => split(l).filter((a) => normalizeAddress(a));
      if (!all.length) return setPlan(null);
      try {
        const p = await client.plan({ to: valid(d.to), cc: valid(d.cc), bcc: valid(d.bcc), requireTls: d.requireTls });
        setPlan({ ...p, invalid });
      } catch {
        setPlan(null);
      }
    }, 450);
    return () => clearTimeout(id);
  }, [d.to, d.cc, d.bcc, d.requireTls]);

  const toInput = useCallback(
    (x: ComposeDraft) => ({
      to: split(x.to),
      cc: split(x.cc),
      bcc: split(x.bcc),
      subject: x.subject,
      text: x.text,
      attachments: x.attachments,
      requireTls: x.requireTls,
      inReplyTo: x.inReplyTo,
      references: x.references,
      draftId: draftId.current,
    }),
    [],
  );

  // Autosave: encrypted to the author's own key, 3 s after the last change.
  useEffect(() => {
    if (!dirty.current || closed.current) return;
    const id = setTimeout(async () => {
      if (closed.current) return;
      setSaving('saving');
      try {
        draftId.current = await client.saveDraft(toInput(d));
        setSaving('saved');
      } catch {
        setSaving('idle');
      }
    }, 3000);
    return () => clearTimeout(id);
  }, [d, toInput]);

  const attach = async (files: FileList | null) => {
    if (!files) return;
    for (const f of Array.from(files)) {
      setUploading((n) => n + 1);
      try {
        const ref = await client.uploadAttachment(f.name, f.type, new Uint8Array(await f.arrayBuffer()));
        dirty.current = true;
        setD((prev) => ({ ...prev, attachments: [...prev.attachments, ref] }));
      } catch (e) {
        setError(errorText(t, e));
      } finally {
        setUploading((n) => n - 1);
      }
    }
  };

  const send = async () => {
    setError(null);
    const bad = [...split(d.to), ...split(d.cc), ...split(d.bcc)].find((a) => !normalizeAddress(a));
    if (bad) return setError(t('invalidAddress', { a: bad }));
    setSending(true);
    closed.current = true;
    try {
      await client.send(toInput(d));
      toast(t('sent_ok'));
      onSent();
    } catch (e) {
      closed.current = false;
      if (e instanceof KeyChangedError) setKeyChanges(e.changes);
      else setError(errorText(t, e));
    } finally {
      setSending(false);
    }
  };

  const discard = async () => {
    closed.current = true;
    if (draftId.current) await client.deleteDraft(draftId.current).catch(() => undefined);
    onClose();
  };

  const statusChip = (r: RecipientKeyInfo) => {
    if (!r.internal) return <span key={r.address} className="chip">{r.address} · {t('external')}</span>;
    if (r.exists === false) return <span key={r.address} className="chip changed">{r.address} ✕</span>;
    const label = r.status === 'verified' ? t('keyVerified') : r.status === 'changed' ? t('keyChanged') : r.status === 'new' ? t('keyNew') : r.status === 'self' ? '' : t('keyPinned');
    return (
      <span key={r.address} className={`chip${r.status === 'changed' ? ' changed' : ''}`} title={r.fingerprint ? formatFingerprint(r.fingerprint) : ''}>
        {r.address}
        {label && ` · ${label}`}
      </span>
    );
  };

  const external = plan?.mode === 'standard';
  const mixed = external && plan?.recipients.some((r) => r.internal);

  return (
    <div className="compose-wrap">
      <section className="compose" aria-label={t('newMessage')}>
        <header className="compose-head">
          <span>{d.subject || t('newMessage')}</span>
          <span className="spacer" />
          <span className="faint small" aria-live="polite">{saving === 'saving' ? t('draftSaving') : saving === 'saved' ? t('draftSaved') : ''}</span>
          <button className="btn icon ghost" onClick={onClose} aria-label={t('close')}>
            <IconClose />
          </button>
        </header>
        <div className="compose-body">
          <div className="line">
            <label htmlFor="c-to">{t('to')}</label>
            <input id="c-to" value={d.to} onChange={(e) => update({ to: e.target.value })} autoFocus={!initial.to} dir="ltr" autoCapitalize="none" spellCheck={false} placeholder={t('recipientsHint')} />
            {!showCc && <button className="btn sm ghost" onClick={() => setShowCc(true)}>{t('addCc')}</button>}
          </div>
          {showCc && (
            <>
              <div className="line">
                <label htmlFor="c-cc">{t('cc')}</label>
                <input id="c-cc" value={d.cc} onChange={(e) => update({ cc: e.target.value })} dir="ltr" autoCapitalize="none" spellCheck={false} />
              </div>
              <div className="line">
                <label htmlFor="c-bcc">{t('bcc')}</label>
                <input id="c-bcc" value={d.bcc} onChange={(e) => update({ bcc: e.target.value })} dir="ltr" autoCapitalize="none" spellCheck={false} />
              </div>
            </>
          )}
          <div className="line">
            <label htmlFor="c-subj">{t('subject')}</label>
            <input id="c-subj" value={d.subject} onChange={(e) => update({ subject: e.target.value.replace(/[\r\n]/g, ' ') })} dir="auto" />
          </div>
          {plan && (
            <div className="stack" style={{ paddingBlock: 6 }}>
              <div className="row wrap">
                <SecurityBadge label={plan.label} />
                <div className="chips">{plan.recipients.map(statusChip)}</div>
              </div>
              <p className="explain" style={{ margin: 0 }}>{t(`label_${plan.label}_help` as never)}</p>
              {mixed && <p className="notice warn">{t('mixedWarning')}</p>}
              {plan.unknown.length > 0 && <p className="notice danger">{t('unknownRecipients', { list: plan.unknown.join(', ') })}</p>}
              {plan.invalid.length > 0 && <p className="notice danger">{t('invalidAddress', { a: plan.invalid.join(', ') })}</p>}
              {external && (
                <label className="check small">
                  <input type="checkbox" checked={d.requireTls} onChange={(e) => update({ requireTls: e.target.checked })} />
                  <span>
                    {t('requireTls')}
                    <br />
                    <span className="muted">{t('requireTlsHelp')}</span>
                  </span>
                </label>
              )}
            </div>
          )}
          <textarea aria-label={t('messagePlaceholder')} placeholder={t('messagePlaceholder')} value={d.text} onChange={(e) => update({ text: e.target.value })} dir="auto" autoFocus={Boolean(initial.to)} />
          {(d.attachments.length > 0 || uploading > 0) && (
            <div className="attachments">
              {d.attachments.map((a) => (
                <span key={a.id} className="attachment">
                  <IconClip size={14} />
                  <span className="name" dir="auto">{a.name}</span>
                  <span className="faint small">{formatBytes(a.size)}</span>
                  <button className="btn icon sm ghost" aria-label={`${t('remove')} ${a.name}`} onClick={() => update({ attachments: d.attachments.filter((x) => x.id !== a.id) })}>
                    <IconClose size={14} />
                  </button>
                </span>
              ))}
              {uploading > 0 && <Spinner label={t('uploading')} />}
            </div>
          )}
          {error && <p className="error" role="alert">{error}</p>}
        </div>
        <footer className="compose-foot">
          <button className="btn primary" onClick={send} disabled={sending || uploading > 0 || !split(d.to + ',' + d.cc + ',' + d.bcc).length || (plan?.unknown.length ?? 0) > 0}>
            {sending ? <Spinner label={t('sending')} /> : t('send')}
          </button>
          <input ref={fileInput} type="file" multiple hidden onChange={(e) => void attach(e.target.files).then(() => (e.target.value = ''))} />
          <button className="btn" onClick={() => fileInput.current?.click()}>
            <IconClip size={15} /> {t('attach')}
          </button>
          <span className="spacer" />
          <button className="btn ghost danger" onClick={discard}>{t('discard')}</button>
        </footer>
      </section>
      {keyChanges && (
        <Modal title={t('keyChangedTitle')} onClose={() => setKeyChanges(null)}>
          <p className="muted">{t('keyChangedBody')}</p>
          {keyChanges.map((c) => (
            <div key={c.address} className="card" style={{ padding: 14 }}>
              <strong dir="ltr">{c.address}</strong>
              <div className="small" style={{ marginBlock: 6 }}>
                <div>{t('oldFingerprint')}: <span className="fingerprint">{formatFingerprint(c.oldFingerprint)}</span></div>
                <div>{t('newFingerprint')}: <span className="fingerprint">{formatFingerprint(c.newFingerprint)}</span></div>
              </div>
              <button
                className="btn sm danger"
                onClick={async () => {
                  await client.acceptKeyChange(c.address, c.newFingerprint);
                  const rest = keyChanges.filter((x) => x.address !== c.address);
                  setKeyChanges(rest.length ? rest : null);
                  dirty.current = true;
                  setD((x) => ({ ...x }));
                }}
              >
                {t('acceptNewKey')}
              </button>
            </div>
          ))}
          <button className="btn" onClick={() => setKeyChanges(null)}>{t('close')}</button>
        </Modal>
      )}
    </div>
  );
}
