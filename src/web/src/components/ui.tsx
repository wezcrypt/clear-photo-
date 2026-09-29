import { useEffect, useState, type ReactNode } from 'react';
import type { SecurityLabel } from '../../../shared/mail';
import { useT, type Key } from '../lib/i18n';
import { IconGlobe, IconLock, IconShield } from './Icons';

export function SecurityBadge({ label, withHelp = false }: { label: SecurityLabel; withHelp?: boolean }) {
  const { t } = useT();
  const cls = label === 'e2ee' || label === 'draft' ? 'e2ee' : label === 'external_encrypted_on_arrival' || label === 'system' ? 'ext' : 'std';
  const icon = label === 'e2ee' || label === 'draft' ? <IconLock size={12} /> : label === 'system' ? <IconShield size={12} /> : <IconGlobe size={12} />;
  return (
    <>
      <span className={`badge ${cls}`} title={t(`label_${label}_help` as Key)}>
        {icon}
        {t(`label_${label}` as Key)}
      </span>
      {withHelp && <p className="explain">{t(`label_${label}_help` as Key)}</p>}
    </>
  );
}

export function Modal({ title, children, onClose, labelledBy = 'modal-title' }: { title: string; children: ReactNode; onClose?: () => void; labelledBy?: string }) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose?.();
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);
  return (
    <div className="modal-bg" onMouseDown={(e) => e.target === e.currentTarget && onClose?.()}>
      <div className="modal" role="dialog" aria-modal="true" aria-labelledby={labelledBy}>
        <h2 id={labelledBy}>{title}</h2>
        {children}
      </div>
    </div>
  );
}

let toastSetter: ((s: string | null) => void) | null = null;
export function toast(msg: string) {
  toastSetter?.(msg);
}
export function ToastHost() {
  const [msg, setMsg] = useState<string | null>(null);
  useEffect(() => {
    toastSetter = setMsg;
    return () => {
      toastSetter = null;
    };
  }, []);
  useEffect(() => {
    if (!msg) return;
    const id = setTimeout(() => setMsg(null), 3200);
    return () => clearTimeout(id);
  }, [msg]);
  return msg ? (
    <div className="toast" role="status" aria-live="polite">
      {msg}
    </div>
  ) : null;
}

export function Spinner({ label }: { label?: string }) {
  return (
    <span className="row" role="status">
      <span className="spinner" aria-hidden="true" />
      {label && <span className="muted small">{label}</span>}
    </span>
  );
}

export function CopyButton({ text }: { text: string }) {
  const { t } = useT();
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      className="btn sm"
      onClick={async () => {
        await navigator.clipboard?.writeText(text).catch(() => undefined);
        setDone(true);
        setTimeout(() => setDone(false), 1500);
      }}
    >
      {done ? t('copied') : t('copy')}
    </button>
  );
}

export function formatDate(iso: string, locale: string, full = false): string {
  const d = new Date(iso);
  const now = new Date();
  const loc = locale === 'ar' ? 'ar' : 'en';
  if (full) return d.toLocaleString(loc, { dateStyle: 'medium', timeStyle: 'short' });
  if (d.toDateString() === now.toDateString()) return d.toLocaleTimeString(loc, { hour: '2-digit', minute: '2-digit' });
  if (d.getFullYear() === now.getFullYear()) return d.toLocaleDateString(loc, { month: 'short', day: 'numeric' });
  return d.toLocaleDateString(loc, { year: 'numeric', month: 'short', day: 'numeric' });
}
