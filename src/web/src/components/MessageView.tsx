import { useEffect, useMemo, useRef, useState } from 'react';
import type { OpenedMessage } from '../../../shared/client';
import type { AttachmentRef } from '../../../shared/mail';
import { formatFingerprint, toB64 } from '../../../shared/crypto';
import { client, formatBytes, saveBytes } from '../lib/api';
import { errorText, useT } from '../lib/i18n';
import { frameDocument, makeSanitizer } from '../lib/sanitize';
import { IconArchive, IconBack, IconClip, IconSpam, IconStar, IconTrash } from './Icons';
import { SecurityBadge, Spinner, formatDate, toast } from './ui';
import type { ComposeDraft } from './Compose';

const sanitize = makeSanitizer();
const MAX_INLINE_IMAGE = 5 * 1024 * 1024;

export type MessageAction = 'archive' | 'trash' | 'spam' | 'notspam' | 'restore' | 'deleteForever' | 'unread' | 'star';

function linkify(text: string) {
  const parts = text.split(/(https?:\/\/[^\s<>"')\]]+)/g);
  return parts.map((p, i) =>
    i % 2 === 1 ? (
      <a key={i} href={p} target="_blank" rel="noopener noreferrer nofollow">
        {p}
      </a>
    ) : (
      p
    ),
  );
}

function quote(m: OpenedMessage, locale: string): string {
  const h = m.header!;
  const lines = (m.body?.text ?? '').split('\n').map((l) => '> ' + l);
  return `\n\n${formatDate(h.date, locale, true)}, ${h.from.name || h.from.address} <${h.from.address}>:\n${lines.join('\n')}`;
}

export function buildReply(m: OpenedMessage, kind: 'reply' | 'replyAll' | 'forward', me: string, locale: string): ComposeDraft {
  const h = m.header!;
  const refs = m.messageId ? [m.messageId] : [];
  const prefix = kind === 'forward' ? 'Fwd: ' : 'Re: ';
  const subject = new RegExp(`^${prefix.trim()}`, 'i').test(h.subject) ? h.subject : prefix + h.subject;
  if (kind === 'forward') {
    const header = `\n\n---------- Forwarded message ----------\nFrom: ${h.from.name} <${h.from.address}>\nDate: ${formatDate(h.date, locale, true)}\nSubject: ${h.subject}\nTo: ${h.to.join(', ')}\n\n`;
    return { to: '', cc: '', bcc: '', subject, text: header + (m.body?.text ?? ''), attachments: m.body?.attachments ?? [], requireTls: false };
  }
  const fromMe = h.from.address === me;
  const to = fromMe ? h.to : [h.from.address];
  const cc = kind === 'replyAll' ? [...(fromMe ? [] : h.to), ...h.cc].filter((a) => a !== me && !to.includes(a)) : [];
  return { to: to.join(', '), cc: cc.join(', '), bcc: '', subject, text: quote(m, locale), attachments: [], requireTls: false, inReplyTo: m.messageId ?? undefined, references: refs };
}

export function MessageView({
  id,
  onBack,
  onAction,
  onCompose,
  labels,
}: {
  id: string;
  onBack: () => void;
  onAction: (a: MessageAction, m: OpenedMessage) => void;
  onCompose: (d: ComposeDraft) => void;
  labels: { id: string; name: string; color: string }[];
}) {
  const { t, locale } = useT();
  const [m, setM] = useState<OpenedMessage | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [allowRemote, setAllowRemote] = useState(false);
  const [asHtml, setAsHtml] = useState(true);
  const [inline, setInline] = useState<Record<string, string>>({});
  const [delivery, setDelivery] = useState<any[] | null>(null);
  const [labelIds, setLabelIds] = useState<string[]>([]);
  const frame = useRef<HTMLIFrameElement>(null);

  useEffect(() => {
    let live = true;
    setM(null);
    setError(null);
    setAllowRemote(false);
    setInline({});
    setDelivery(null);
    client
      .open(id)
      .then(async (msg) => {
        if (!live) return;
        setM(msg);
        setLabelIds(msg.labels);
        if (msg.unread) void client.update([id], { unread: false });
        if (msg.kind === 'external_out') setDelivery(await client.delivery(id));
        // Inline (cid:) images are attachments: decrypt locally and embed as data: URLs.
        const map: Record<string, string> = {};
        for (const a of msg.body?.attachments ?? []) {
          if (a.cid && /^image\/(png|gif|jpe?g|webp)$/i.test(a.type) && a.size <= MAX_INLINE_IMAGE) {
            try {
              map[a.cid] = `data:${a.type};base64,${toB64(await client.downloadAttachment(a))}`;
            } catch {
              /* ignore broken inline image */
            }
          }
        }
        if (live && Object.keys(map).length) setInline(map);
      })
      .catch((e) => live && setError(errorText(t, e)));
    return () => {
      live = false;
    };
  }, [id, t]);

  const html = m?.body?.html;
  const rendered = useMemo(() => (html ? sanitize(html, { allowRemote, inline }) : null), [html, allowRemote, inline]);

  const resize = () => {
    const f = frame.current;
    const doc = f?.contentDocument;
    if (f && doc?.documentElement) f.style.height = Math.min(Math.max(doc.documentElement.scrollHeight + 4, 120), 20000) + 'px';
  };

  const download = async (a: AttachmentRef) => {
    try {
      saveBytes(a.name, await client.downloadAttachment(a));
    } catch (e) {
      toast(errorText(t, e));
    }
  };

  if (error) return <div className="empty">{error}</div>;
  if (!m) return <div className="empty"><Spinner label={t('loading')} /></div>;

  const h = m.header;
  const inTrash = m.folder === 'trash';
  const inSpam = m.folder === 'spam';
  const signed = m.kind === 'internal_in' || m.kind === 'internal_out' || m.kind === 'draft';
  const inlineCids = new Set(Object.keys(inline));
  const visibleAttachments = (m.body?.attachments ?? []).filter((a) => !(a.cid && inlineCids.has(a.cid) && asHtml && html));

  return (
    <article aria-label={h?.subject || t('noSubject')}>
      <div className="reader-toolbar" role="toolbar">
        <button className="btn icon ghost mobile-only" onClick={onBack} aria-label={t('back')}><IconBack /></button>
        {h && m.kind !== 'draft' && (
          <>
            <button className="btn sm" onClick={() => onCompose(buildReply(m, 'reply', client.address, locale))}>{t('reply')}</button>
            <button className="btn sm" onClick={() => onCompose(buildReply(m, 'replyAll', client.address, locale))}>{t('replyAll')}</button>
            <button className="btn sm" onClick={() => onCompose(buildReply(m, 'forward', client.address, locale))}>{t('forward')}</button>
          </>
        )}
        <span className="spacer" />
        {!inTrash && !inSpam && m.folder !== 'archive' && ['internal_in', 'external_in', 'system'].includes(m.kind) && (
          <button className="btn icon ghost" title={t('archive')} aria-label={t('archive')} onClick={() => onAction('archive', m)}><IconArchive /></button>
        )}
        {inSpam ? (
          <button className="btn sm ghost" onClick={() => onAction('notspam', m)}>{t('notSpam')}</button>
        ) : (
          !inTrash && ['internal_in', 'external_in'].includes(m.kind) && <button className="btn icon ghost" title={t('reportSpam')} aria-label={t('reportSpam')} onClick={() => onAction('spam', m)}><IconSpam /></button>
        )}
        <button className="btn icon ghost" aria-pressed={m.starred} title={m.starred ? t('unstar') : t('star')} aria-label={m.starred ? t('unstar') : t('star')} onClick={() => { setM({ ...m, starred: !m.starred }); onAction('star', m); }}>
          <IconStar filled={m.starred} />
        </button>
        <button className="btn sm ghost" onClick={() => onAction('unread', m)}>{t('markUnread')}</button>
        {inTrash ? (
          <>
            <button className="btn sm ghost" onClick={() => onAction('restore', m)}>{t('restore')}</button>
            <button className="btn sm danger" onClick={() => onAction('deleteForever', m)}>{t('deleteForever')}</button>
          </>
        ) : (
          <button className="btn icon ghost" title={t('delete')} aria-label={t('delete')} onClick={() => onAction('trash', m)}><IconTrash /></button>
        )}
      </div>
      <div className="reader-inner">
        {!h ? (
          <div className="notice danger">{t('undecryptable')}</div>
        ) : (
          <>
            <h1 dir="auto">{h.subject || t('noSubject')}</h1>
            <div className="security-strip">
              <SecurityBadge label={m.security} />
              {signed && m.signature === 'valid' && <span className="badge e2ee">✓ {t('signatureValid')}</span>}
              {signed && m.signature === 'invalid' && <span className="badge bad">✕ {t('signatureInvalid')}</span>}
              {signed && (m.signature === 'unknown-key' || m.signature === 'unsigned') && <span className="badge std">{m.signature === 'unsigned' ? t('signatureUnsigned') : t('signatureUnknown')}</span>}
              {m.senderKeyStatus === 'verified' && <span className="badge accent">{t('keyVerified')}</span>}
            </div>
            <p className="explain">{t(`label_${m.security}_help` as never)}</p>
            {m.integrity === 'mismatch' && <p className="notice danger" role="alert">{t('integrityMismatch')}</p>}
            {m.senderKeyStatus === 'changed' && <p className="notice danger" role="alert">{t('keyChangedSender')}</p>}
            <dl className="headers">
              <dt>{t('from')}</dt>
              <dd><span dir="auto">{h.from.name}</span> <span className="muted" dir="ltr">&lt;{h.from.address}&gt;</span></dd>
              {h.to.length > 0 && (<><dt>{t('to')}</dt><dd dir="ltr">{h.to.join(', ')}</dd></>)}
              {h.cc.length > 0 && (<><dt>{t('cc')}</dt><dd dir="ltr">{h.cc.join(', ')}</dd></>)}
              {h.bcc && h.bcc.length > 0 && (<><dt>{t('bcc')}</dt><dd dir="ltr">{h.bcc.join(', ')}</dd></>)}
              <dt>{t('date')}</dt>
              <dd>{formatDate(h.date, locale, true)}</dd>
            </dl>
            {labels.length > 0 && (
              <div className="row wrap" style={{ marginBlockEnd: 14 }}>
                {labels.map((l) => (
                  <label key={l.id} className="chip" style={{ cursor: 'pointer' }}>
                    <input
                      type="checkbox"
                      checked={labelIds.includes(l.id)}
                      onChange={async (e) => {
                        const next = e.target.checked ? [...labelIds, l.id] : labelIds.filter((x) => x !== l.id);
                        setLabelIds(next);
                        await client.setLabels(m.id, next).catch(() => undefined);
                      }}
                    />
                    <span dir="auto">{l.name}</span>
                  </label>
                ))}
              </div>
            )}
            {html && rendered && (
              <div className="stack" style={{ marginBlockEnd: 12 }}>
                <div className="row wrap">
                  <button className="btn sm" onClick={() => setAsHtml(!asHtml)}>{asHtml ? t('showPlain') : t('showHtml')}</button>
                  {asHtml && rendered.blocked > 0 && !allowRemote && (
                    <>
                      <span className="muted small">{t('remoteBlocked', { n: rendered.blocked })}</span>
                      {client.session?.user.remoteImages !== 'never' && (
                        <button className="btn sm" title={t('loadRemoteWarning')} onClick={() => setAllowRemote(true)}>{t('loadRemote')}</button>
                      )}
                    </>
                  )}
                </div>
                {asHtml && rendered.blocked > 0 && !allowRemote && <p className="faint small" style={{ margin: 0 }}>{t('loadRemoteWarning')}</p>}
                {rendered.mismatchedLinks.length > 0 && (
                  <div className="notice warn">
                    {t('linkMismatch')}
                    <ul style={{ margin: '6px 0 0', paddingInlineStart: 18 }}>
                      {rendered.mismatchedLinks.slice(0, 5).map((l, i) => (
                        <li key={i} dir="ltr" className="small">“{l.text}” → <span className="mono">{l.href}</span></li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}
            {html && rendered && asHtml ? (
              <iframe
                ref={frame}
                className="mail-frame"
                title={h.subject || 'message'}
                // No allow-scripts: email content can never execute JavaScript. allow-same-origin (without scripts)
                // only lets VoidMail measure the height; the frame's own CSP blocks all remote loads by default.
                sandbox="allow-same-origin allow-popups allow-popups-to-escape-sandbox"
                referrerPolicy="no-referrer"
                srcDoc={frameDocument(rendered.html, { allowRemote })}
                onLoad={resize}
              />
            ) : (
              <div className="body-text" dir="auto">{linkify(m.body?.text ?? '')}</div>
            )}
            {visibleAttachments.length > 0 && (
              <section aria-label={t('attachments')}>
                <div className="attachments">
                  {visibleAttachments.map((a) => (
                    <button key={a.id} className="attachment" onClick={() => download(a)}>
                      <IconClip size={14} />
                      <span className="name" dir="auto">{a.name}</span>
                      <span className="faint small">{formatBytes(a.size)}</span>
                    </button>
                  ))}
                </div>
              </section>
            )}
            {delivery && delivery.length > 0 && (
              <section className="card" style={{ marginBlockStart: 22 }}>
                <h2>{t('deliveryStatus')}</h2>
                {delivery.map((r) => (
                  <div key={r.address} className="kv small">
                    <span dir="ltr">{r.address}</span>
                    <span className={`badge ${r.status === 'bounced' || r.status === 'failed' ? 'bad' : r.status === 'delivered' ? 'e2ee' : ''}`}>{r.status}</span>
                    {r.diagnostic && <span className="faint mono" style={{ flexBasis: '100%' }}>{r.diagnostic}</span>}
                  </div>
                ))}
              </section>
            )}
            {m.senderKeyStatus && m.senderKeyStatus !== 'self' && signed && m.senderAddress && client.pins()[m.senderAddress] && (
              <p className="faint small" style={{ marginBlockStart: 24 }}>
                {m.senderAddress}: <span className="fingerprint">{formatFingerprint(client.pins()[m.senderAddress].fingerprint)}</span>
              </p>
            )}
          </>
        )}
      </div>
    </article>
  );
}
