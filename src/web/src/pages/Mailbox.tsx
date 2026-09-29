import { useCallback, useEffect, useRef, useState, type ReactElement } from 'react';
import type { ListItem, OpenedMessage } from '../../../shared/client';
import { client, formatBytes } from '../lib/api';
import { errorText, useT, type Key } from '../lib/i18n';
import { go } from '../lib/router';
import { localIndex } from '../lib/search';
import { Compose, emptyDraft, type ComposeDraft } from '../components/Compose';
import { MessageView, type MessageAction } from '../components/MessageView';
import { IconArchive, IconDraft, IconInbox, IconMenu, IconPlus, IconSearch, IconSend, IconSettings, IconShield, IconSpam, IconStar, IconTag, IconTrash } from '../components/Icons';
import { SecurityBadge, Spinner, formatDate, toast } from '../components/ui';
import { Settings } from './Settings';
import { SecurityInfo } from './SecurityInfo';

const FOLDERS: { id: string; icon: ReactElement }[] = [
  { id: 'inbox', icon: <IconInbox /> },
  { id: 'starred', icon: <IconStar /> },
  { id: 'sent', icon: <IconSend /> },
  { id: 'drafts', icon: <IconDraft /> },
  { id: 'archive', icon: <IconArchive /> },
  { id: 'spam', icon: <IconSpam /> },
  { id: 'trash', icon: <IconTrash /> },
];
const LABEL_COLORS: Record<string, string> = { violet: '#9d8cff', blue: '#5aa9e6', green: '#58c39a', amber: '#e0ae50', red: '#ef6b6f', gray: '#8a8a98' };

type Label = { id: string; name: string; color: string };

export function Mailbox({ route }: { route: string[] }) {
  const { t, locale } = useT();
  const [section, a, b] = route;
  const isSettings = section === 'settings';
  const isSecurity = section === 'security';
  const labelId = section === 'l' ? a : undefined;
  const folder = section === 'f' ? a || 'inbox' : labelId ? undefined : 'inbox';
  const openId = section === 'f' || section === 'l' ? b : undefined;
  const base = labelId ? `l/${labelId}` : `f/${folder}`;

  const [items, setItems] = useState<ListItem[]>([]);
  const [next, setNext] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [counts, setCounts] = useState<Record<string, { unread: number; total: number }>>({});
  const [labels, setLabels] = useState<Label[]>([]);
  const [quota, setQuota] = useState<{ used: number; quota: number } | null>(null);
  const [compose, setCompose] = useState<ComposeDraft | null>(null);
  const [drawer, setDrawer] = useState(false);
  const [query, setQuery] = useState('');
  const [indexing, setIndexing] = useState<number | null>(null);
  const [cursor, setCursor] = useState(0);
  const searchRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  const refreshMeta = useCallback(async () => {
    const [c, l, q] = await Promise.all([client.call('GET', '/api/messages/counts'), client.call('GET', '/api/labels'), client.call('GET', '/api/quota')]);
    setCounts(c);
    setLabels(l);
    setQuota(q);
  }, []);

  const load = useCallback(
    async (append = false, before: string | null = null) => {
      setLoading(true);
      setError(null);
      try {
        const page = await client.list({ folder, label: labelId, before });
        page.items.forEach((i) => localIndex.add(i));
        setItems((prev) => (append ? [...prev, ...page.items] : page.items));
        setNext(page.next);
      } catch (e) {
        setError(errorText(t, e));
      } finally {
        setLoading(false);
      }
    },
    [folder, labelId, t],
  );

  useEffect(() => {
    if (isSettings || isSecurity) return;
    setCursor(0);
    void load();
  }, [load, isSettings, isSecurity]);
  useEffect(() => {
    void refreshMeta();
    const id = setInterval(() => {
      void refreshMeta();
      if (!isSettings && !isSecurity && !query) void load();
    }, 20_000);
    return () => clearInterval(id);
  }, [refreshMeta, load, isSettings, isSecurity, query]);

  const shown = query ? localIndex.search(query) : items;

  const act = async (action: MessageAction, m: OpenedMessage | ListItem) => {
    try {
      const ids = [m.id];
      if (action === 'star') await client.update(ids, { starred: !m.starred });
      else if (action === 'unread') await client.update(ids, { unread: true });
      else if (action === 'archive') await client.update(ids, { folder: 'archive' });
      else if (action === 'trash') await client.update(ids, { folder: 'trash' });
      else if (action === 'spam') await client.update(ids, { folder: 'spam' });
      else if (action === 'notspam') await client.update(ids, { folder: 'inbox' });
      else if (action === 'restore') await client.update(ids, { folder: 'restore' });
      else if (action === 'deleteForever') await client.update(ids, { delete: true });
      if (action !== 'star') go(base);
      void load();
      void refreshMeta();
    } catch (e) {
      toast(errorText(t, e));
    }
  };

  const openItem = (it: ListItem) => {
    if (it.kind === 'draft' && it.header) {
      void client.open(it.id).then((m) => {
        const h = m.header!;
        setCompose({
          draftId: it.id,
          to: h.to.join(', '),
          cc: h.cc.join(', '),
          bcc: (h.bcc ?? []).join(', '),
          subject: h.subject,
          text: m.body?.text ?? '',
          attachments: m.body?.attachments ?? [],
          requireTls: m.body?.draft?.requireTls ?? false,
          inReplyTo: m.body?.draft?.inReplyTo,
          references: m.body?.draft?.references,
        });
      });
      return;
    }
    go(`${base}/${it.id}`);
  };

  // Keyboard navigation (ignored while typing).
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const tag = (e.target as HTMLElement).tagName;
      if (['INPUT', 'TEXTAREA', 'SELECT'].includes(tag) || (e.target as HTMLElement).isContentEditable || e.metaKey || e.ctrlKey || e.altKey) return;
      if (compose) return;
      if (e.key === 'c') { e.preventDefault(); setCompose(emptyDraft()); }
      else if (e.key === '/') { e.preventDefault(); searchRef.current?.focus(); }
      else if (e.key === 'j' || e.key === 'k') {
        e.preventDefault();
        const n = Math.max(0, Math.min(shown.length - 1, cursor + (e.key === 'j' ? 1 : -1)));
        setCursor(n);
        (listRef.current?.querySelectorAll('[role="option"]')[n] as HTMLElement | undefined)?.focus();
      } else if ((e.key === 'Enter' || e.key === 'o') && shown[cursor] && !openId) openItem(shown[cursor]);
      else if (e.key === 'Escape' || e.key === 'u') { if (openId) go(base); }
      else if (openId) {
        const cur = shown.find((x) => x.id === openId);
        if (!cur) return;
        if (e.key === 'e') void act('archive', cur);
        else if (e.key === '#') void act('trash', cur);
        else if (e.key === 's') void act('star', cur);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  });

  const indexAll = async () => {
    setIndexing(0);
    let n = 0;
    try {
      for (const f of ['inbox', 'sent', 'drafts', 'archive', 'spam', 'trash']) {
        let before: string | null = null;
        do {
          const page = await client.list({ folder: f, before, limit: 100 });
          for (const it of page.items) {
            const full = await client.open(it.id).catch(() => null);
            localIndex.add(it, full?.body?.text ?? '');
            setIndexing(++n);
          }
          before = page.next;
        } while (before);
      }
    } finally {
      setIndexing(null);
      setQuery((q) => q + '');
    }
  };

  const title = labelId ? labels.find((l) => l.id === labelId)?.name ?? '' : t(folder as Key);
  const view = openId || isSettings || isSecurity ? 'reader' : 'list';

  const nav = (
    <>
      <nav className={`sidebar${drawer ? ' open' : ''}`} aria-label="Folders" onClick={() => setDrawer(false)}>
        <div className="brand"><span className="brand-mark" aria-hidden="true" />VoidMail</div>
        <button className="btn primary compose-btn" onClick={() => setCompose(emptyDraft())}><IconPlus /> {t('compose')}</button>
        {FOLDERS.map((f) => (
          <button key={f.id} className="nav-item" aria-current={folder === f.id && !isSettings && !isSecurity && !labelId ? 'page' : undefined} onClick={() => { if (folder === f.id && !labelId && !isSettings && !isSecurity && !openId) void load(); go(`f/${f.id}`); void refreshMeta(); }}>
            {f.icon}
            {t(f.id as Key)}
            {counts[f.id]?.unread && f.id !== 'sent' && f.id !== 'drafts' ? <span className="count">{counts[f.id].unread}</span> : f.id === 'drafts' && counts.drafts?.total ? <span className="count faint">{counts.drafts.total}</span> : null}
          </button>
        ))}
        <div className="nav-section">{t('labels')}</div>
        {labels.map((l) => (
          <button key={l.id} className="nav-item" aria-current={labelId === l.id ? 'page' : undefined} onClick={() => go(`l/${l.id}`)}>
            <span className="label-dot" style={{ background: LABEL_COLORS[l.color] ?? LABEL_COLORS.violet }} />
            <span dir="auto">{l.name}</span>
          </button>
        ))}
        <button
          className="nav-item"
          onClick={async (e) => {
            e.stopPropagation();
            const name = prompt(t('newLabel'))?.trim();
            if (name) await client.call('POST', '/api/labels', { name }).then(refreshMeta, (err) => toast(errorText(t, err)));
          }}
        >
          <IconTag /> {t('newLabel')}
        </button>
        <div className="nav-section" />
        <button className="nav-item" aria-current={isSettings ? 'page' : undefined} onClick={() => go('settings')}><IconSettings /> {t('settings')}</button>
        <button className="nav-item" aria-current={isSecurity ? 'page' : undefined} onClick={() => go('security')}><IconShield /> {t('securityInfo')}</button>
        <div className="sidebar-foot">
          <div dir="ltr" style={{ overflow: 'hidden', textOverflow: 'ellipsis' }}>{client.address}</div>
          {quota && (
            <>
              <div style={{ marginBlockStart: 6 }}>{t('storageUsed', { used: formatBytes(quota.used), quota: formatBytes(quota.quota) })}</div>
              <div className="quota-bar" aria-hidden="true"><i style={{ width: `${Math.min(100, (quota.used / quota.quota) * 100)}%` }} /></div>
            </>
          )}
        </div>
      </nav>
      {drawer && <div className="scrim" onClick={() => setDrawer(false)} />}
    </>
  );

  return (
    <div className="app" data-view={view}>
      <div className="topbar">
        <button className="btn icon ghost" onClick={() => setDrawer(true)} aria-label="Menu"><IconMenu /></button>
        <strong>{isSettings ? t('settings') : isSecurity ? t('securityInfo') : title}</strong>
        <span className="spacer" />
        <button className="btn icon primary" onClick={() => setCompose(emptyDraft())} aria-label={t('compose')}><IconPlus /></button>
      </div>
      {nav}
      {isSettings ? (
        <section className="settings"><Settings onChanged={refreshMeta} /></section>
      ) : isSecurity ? (
        <section className="settings"><SecurityInfo /></section>
      ) : (
        <>
          <section className="list-pane" aria-label={title}>
            <div className="list-head">
              <div className="search" role="search">
                <IconSearch />
                <input ref={searchRef} className="input" type="search" placeholder={t('searchPlaceholder')} aria-label={t('search')} value={query} onChange={(e) => setQuery(e.target.value)} dir="auto" />
              </div>
            </div>
            {query && (
              <div className="notice" style={{ margin: 10, fontSize: 12.5 }}>
                <div>{t('searchPrivacy')}</div>
                <div className="row" style={{ marginBlockStart: 8 }}>
                  <span className="muted">{t('searchResults')}: {shown.length} · {localIndex.size}</span>
                  <span className="spacer" />
                  {indexing !== null ? <Spinner label={`${t('searchIndexing')} ${indexing}`} /> : <button className="btn sm" onClick={indexAll}>{t('searchAll')}</button>}
                  <button className="btn sm ghost" onClick={() => setQuery('')}>{t('clearSearch')}</button>
                </div>
              </div>
            )}
            <div className="list" role="listbox" aria-label={title} ref={listRef}>
              {error && <div className="empty error">{error}</div>}
              {!error && !loading && shown.length === 0 && (
                <div className="empty"><div className="ring" />{folder === 'inbox' && !query ? t('emptyInbox') : t('emptyFolder')}</div>
              )}
              {shown.map((it, i) => {
                const h = it.header;
                const who = folder === 'sent' || folder === 'drafts' ? (h ? [...h.to, ...h.cc].join(', ') : '') : h ? h.from.name || h.from.address : '';
                return (
                  <div
                    key={it.id}
                    role="option"
                    tabIndex={i === cursor ? 0 : -1}
                    aria-selected={it.id === openId}
                    className={`msg-row${it.unread ? ' unread' : ''}`}
                    onClick={() => { setCursor(i); openItem(it); }}
                    onKeyDown={(e) => e.key === 'Enter' && openItem(it)}
                  >
                    <span className="who" dir="auto">{h ? who || '—' : t('undecryptable')}</span>
                    <span className="when">{formatDate(it.receivedAt, locale)}</span>
                    <span className="subj" dir="auto">{h ? h.subject || t('noSubject') : ''}</span>
                    {h?.snippet && <span className="snip" dir="auto">{h.snippet}</span>}
                    <span className="meta">
                      {it.security !== 'draft' && <SecurityBadge label={it.security} />}
                      {it.starred && <span style={{ color: 'var(--warn)' }}><IconStar size={13} filled /></span>}
                      {h?.hasAttachments && <span className="faint small">📎</span>}
                    </span>
                  </div>
                );
              })}
              {loading && <div className="empty"><Spinner label={t('loading')} /></div>}
              {!query && next && !loading && (
                <div style={{ padding: 14, textAlign: 'center' }}>
                  <button className="btn" onClick={() => load(true, next)}>{t('loadMore')}</button>
                </div>
              )}
            </div>
          </section>
          <section className="reader" aria-live="polite">
            {openId ? (
              <MessageView id={openId} onBack={() => go(base)} onAction={act} onCompose={setCompose} labels={labels} />
            ) : (
              <div className="empty"><div className="ring" />{t('selectMessage')}</div>
            )}
          </section>
        </>
      )}
      {compose && (
        <Compose
          key={compose.draftId ?? JSON.stringify(compose).length}
          initial={compose}
          onClose={() => { setCompose(null); void load(); void refreshMeta(); }}
          onSent={() => { setCompose(null); void load(); void refreshMeta(); }}
        />
      )}
    </div>
  );
}
