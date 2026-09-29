import { useEffect, useState, type ReactNode } from 'react';
import QRCode from 'qrcode';
import { formatFingerprint } from '../../../shared/crypto';
import { client, formatBytes, saveBytes } from '../lib/api';
import { errorText, useT, type Key } from '../lib/i18n';
import { localIndex } from '../lib/search';
import { CopyButton, Spinner, formatDate, toast } from '../components/ui';

function Card({ title, help, children }: { title: string; help?: string; children: ReactNode }) {
  return (
    <section className="card">
      <h2>{title}</h2>
      {help && <p className="help">{help}</p>}
      {children}
    </section>
  );
}

function useAction() {
  const { t } = useT();
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const run = async (name: string, fn: () => Promise<void>) => {
    setBusy(name);
    setError(null);
    try {
      await fn();
    } catch (e) {
      setError(errorText(t, e));
    } finally {
      setBusy(null);
    }
  };
  return { busy, error, run, setError };
}

export function Settings({ onChanged }: { onChanged: () => void }) {
  const { t, locale, setLocale } = useT();
  const s = client.session!;
  const { busy, error, run } = useAction();
  const [profile, setProfile] = useState({ displayName: s.user.displayName, recoveryEmail: s.user.recoveryEmail ?? '' });
  const [pw, setPw] = useState({ current: '', next: '', confirm: '' });
  const [totp, setTotp] = useState<{ secret: string; qr: string } | null>(null);
  const [totpCode, setTotpCode] = useState('');
  const [codes, setCodes] = useState<string[] | null>(null);
  const [disable, setDisable] = useState({ password: '', code: '' });
  const [recPw, setRecPw] = useState('');
  const [newRecovery, setNewRecovery] = useState<string | null>(null);
  const [sessions, setSessions] = useState<any[]>([]);
  const [events, setEvents] = useState<any[]>([]);
  const [pins, setPins] = useState(client.pins());
  const [quota, setQuota] = useState<{ used: number; quota: number } | null>(null);
  const [exporting, setExporting] = useState<number | null>(null);
  const [del, setDel] = useState({ password: '', confirm: '' });
  const [, force] = useState(0);

  const reload = async () => {
    setSessions(await client.call('GET', '/api/sessions'));
    setEvents(await client.call('GET', '/api/security/events'));
    setQuota(await client.call('GET', '/api/quota'));
    setPins(client.pins());
  };
  useEffect(() => {
    void reload();
  }, []);

  const patch = async (body: Record<string, unknown>) => {
    await client.call('PATCH', '/api/settings', body);
    await client.refreshSession();
    toast(t('saved'));
    onChanged();
    force((n) => n + 1);
  };

  const active = s.keys.find((k) => k.status === 'active')!;

  return (
    <div className="settings-inner">
      <h1>{t('settings')}</h1>
      {error && <p className="notice danger" role="alert">{error}</p>}

      <Card title={t('profile')}>
        <div className="stack">
          <p className="muted" dir="ltr">{s.user.address}</p>
          <label className="field"><span>{t('displayName')}</span><input className="input" value={profile.displayName} maxLength={64} onChange={(e) => setProfile({ ...profile, displayName: e.target.value })} /></label>
          <label className="field">
            <span>{t('recoveryEmailSetting')}</span>
            <input className="input" type="email" dir="ltr" value={profile.recoveryEmail} onChange={(e) => setProfile({ ...profile, recoveryEmail: e.target.value })} aria-describedby="s-re-help" />
          </label>
          <p className="help" id="s-re-help">{t('recoveryEmailHelp')}</p>
          <button className="btn" disabled={busy === 'profile'} onClick={() => run('profile', () => patch({ displayName: profile.displayName, recoveryEmail: profile.recoveryEmail.trim() || null }))}>{t('save')}</button>
        </div>
      </Card>

      <Card title={t('appearance')}>
        <div className="grid2">
          <label className="field">
            <span>{t('language')}</span>
            <select className="input" value={locale} onChange={(e) => { setLocale(e.target.value as 'en' | 'ar'); void patch({ locale: e.target.value }); }}>
              <option value="en">English</option>
              <option value="ar">العربية</option>
            </select>
          </label>
          <label className="field">
            <span>{t('theme')}</span>
            <select className="input" value={s.user.theme} onChange={(e) => run('theme', () => patch({ theme: e.target.value }))}>
              <option value="system">{t('themeSystem')}</option>
              <option value="dark">{t('themeDark')}</option>
              <option value="light">{t('themeLight')}</option>
            </select>
          </label>
        </div>
      </Card>

      <Card title={t('privacy')}>
        <label className="field">
          <span>{t('remoteImagesSetting')}</span>
          <select className="input" value={s.user.remoteImages} onChange={(e) => run('ri', () => patch({ remoteImages: e.target.value }))}>
            <option value="ask">{t('remoteAsk')}</option>
            <option value="never">{t('remoteNever')}</option>
          </select>
        </label>
        <p className="help">{t('loadRemoteWarning')}</p>
      </Card>

      <Card title={t('changePassword')} help={t('changePasswordHelp')}>
        <form
          className="stack"
          onSubmit={(e) => {
            e.preventDefault();
            if (pw.next.length < 10) return toast(t('weakPassword'));
            if (pw.next !== pw.confirm) return toast(t('passwordsDontMatch'));
            void run('pw', async () => {
              await client.changePassword(pw.current, pw.next);
              setPw({ current: '', next: '', confirm: '' });
              toast(t('saved'));
              await reload();
            });
          }}
        >
          <label className="field"><span>{t('currentPassword')}</span><input className="input" type="password" autoComplete="current-password" value={pw.current} onChange={(e) => setPw({ ...pw, current: e.target.value })} /></label>
          <div className="grid2">
            <label className="field"><span>{t('newPassword')}</span><input className="input" type="password" autoComplete="new-password" value={pw.next} onChange={(e) => setPw({ ...pw, next: e.target.value })} /></label>
            <label className="field"><span>{t('confirmPassword')}</span><input className="input" type="password" autoComplete="new-password" value={pw.confirm} onChange={(e) => setPw({ ...pw, confirm: e.target.value })} /></label>
          </div>
          <button className="btn" disabled={busy === 'pw' || !pw.current || !pw.next}>{busy === 'pw' ? <Spinner label={t('derivingKeys')} /> : t('changePassword')}</button>
        </form>
      </Card>

      <Card title={t('twoFactor')}>
        <div className="kv"><span>{s.user.totpEnabled ? t('twoFactorOn') : t('twoFactorOff')}</span>
          {!s.user.totpEnabled && !totp && (
            <button className="btn sm" onClick={() => run('totp', async () => {
              const r = await client.totpSetup();
              setTotp({ secret: r.secret, qr: await QRCode.toDataURL(r.uri, { margin: 1, width: 180 }) });
            })}>{t('enable')}</button>
          )}
        </div>
        {totp && !s.user.totpEnabled && (
          <div className="stack">
            <p className="help">{t('scanQr')}</p>
            <img src={totp.qr} width={180} height={180} alt="TOTP QR code" style={{ background: '#fff', borderRadius: 8, padding: 6 }} />
            <p className="small muted">{t('manualSecret')}: <span className="mono" dir="ltr">{totp.secret}</span> <CopyButton text={totp.secret} /></p>
            <div className="row">
              <input className="input mono" style={{ maxWidth: 160 }} inputMode="numeric" autoComplete="one-time-code" value={totpCode} onChange={(e) => setTotpCode(e.target.value)} dir="ltr" aria-label={t('twoFactorCode')} />
              <button className="btn primary" onClick={() => run('totp', async () => {
                setCodes(await client.totpEnable(totpCode.trim()));
                await client.refreshSession();
                setTotp(null);
                setTotpCode('');
              })}>{t('verify')}</button>
            </div>
          </div>
        )}
        {codes && (
          <div className="stack">
            <p className="notice warn">{t('recoveryCodes')}</p>
            <div className="codes" dir="ltr">{codes.map((c) => <span key={c}>{c}</span>)}</div>
            <div className="row"><CopyButton text={codes.join('\n')} /><button className="btn sm" onClick={() => saveBytes('voidmail-2fa-recovery-codes.txt', codes.join('\n') + '\n', 'text/plain')}>{t('download')}</button></div>
          </div>
        )}
        {s.user.totpEnabled && (
          <div className="stack">
            <div className="grid2">
              <input className="input" type="password" placeholder={t('password')} aria-label={t('password')} value={disable.password} onChange={(e) => setDisable({ ...disable, password: e.target.value })} />
              <input className="input mono" placeholder={t('twoFactorCode')} aria-label={t('twoFactorCode')} value={disable.code} onChange={(e) => setDisable({ ...disable, code: e.target.value })} dir="ltr" />
            </div>
            <button className="btn danger" disabled={!disable.password || !disable.code} onClick={() => run('totpoff', async () => {
              await client.totpDisable(disable.password, disable.code.trim());
              await client.refreshSession();
              setDisable({ password: '', code: '' });
              setCodes(null);
            })}>{t('disable')}</button>
          </div>
        )}
      </Card>

      <Card title={t('regenerateRecoveryKey')} help={t('regenerateRecoveryKeyHelp')}>
        {newRecovery ? (
          <div className="stack">
            <p className="notice warn">{t('recoveryKeyHelp')}</p>
            <div className="recovery-key">{newRecovery}</div>
            <div className="row"><CopyButton text={newRecovery} /><button className="btn sm" onClick={() => saveBytes('voidmail-recovery-key.txt', newRecovery + '\n', 'text/plain')}>{t('download')}</button><button className="btn sm" onClick={() => setNewRecovery(null)}>{t('close')}</button></div>
          </div>
        ) : (
          <div className="row wrap">
            <input className="input" style={{ maxWidth: 280 }} type="password" placeholder={t('currentPassword')} aria-label={t('currentPassword')} value={recPw} onChange={(e) => setRecPw(e.target.value)} />
            <button className="btn" disabled={!recPw || busy === 'rec'} onClick={() => run('rec', async () => {
              setNewRecovery(await client.regenerateRecoveryKey(recPw));
              setRecPw('');
            })}>{busy === 'rec' ? <Spinner /> : t('regenerateRecoveryKey')}</button>
          </div>
        )}
      </Card>

      <Card title={t('sessions')}>
        {sessions.map((x) => (
          <div className="kv" key={x.id}>
            <span>
              {x.device} {x.current && <span className="badge accent">{t('thisDevice')}</span>}
              <br />
              <span className="faint small">{t('lastActive')}: {formatDate(x.lastSeenAt, locale, true)}</span>
            </span>
            {!x.current && <button className="btn sm" onClick={() => run('rev', async () => { await client.call('DELETE', `/api/sessions/${x.id}`); await reload(); })}>{t('revoke')}</button>}
          </div>
        ))}
        {sessions.length > 1 && <button className="btn sm danger" style={{ marginBlockStart: 10 }} onClick={() => run('revall', async () => { await client.call('POST', '/api/sessions/revoke-others'); await reload(); })}>{t('revokeOthers')}</button>}
      </Card>

      <Card title={t('encryptionKeys')} help={t('fingerprintHelp')}>
        <div className="stack">
          <div>
            <div className="small muted">{t('yourFingerprint')}</div>
            <div className="fingerprint">{formatFingerprint(active.fingerprint)}</div>
          </div>
          {s.keys.filter((k) => k.status !== 'active').map((k) => (
            <div key={k.id} className="kv small">
              <span className="fingerprint faint">{formatFingerprint(k.fingerprint)}</span>
              <span className="badge">{t(`keyStatus_${k.status}` as Key)}</span>
            </div>
          ))}
          <p className="help">{t('rotateKeyHelp')}</p>
          <button className="btn" disabled={busy === 'rotate'} onClick={() => run('rotate', async () => { await client.rotateKey(); toast(t('saved')); force((n) => n + 1); })}>{busy === 'rotate' ? <Spinner /> : t('rotateKey')}</button>
        </div>
      </Card>

      <Card title={t('contacts')} help={t('contactsHelp')}>
        {client.vaultProblem && <p className="notice danger">{t('vaultProblem')}</p>}
        {Object.keys(pins).length === 0 && <p className="muted">{t('noContacts')}</p>}
        {Object.entries(pins).map(([addr, p]) => (
          <div className="kv" key={addr}>
            <span>
              <span dir="ltr">{addr}</span> {p.verified && <span className="badge accent">{t('keyVerified')}</span>}
              <br />
              <span className="fingerprint small faint">{formatFingerprint(p.fingerprint)}</span>
            </span>
            <button className="btn sm" onClick={() => run('pin', async () => { await client.setVerified(addr, !p.verified); setPins(client.pins()); })}>{p.verified ? t('unverify') : t('markVerified')}</button>
          </div>
        ))}
      </Card>

      <Card title={t('data')}>
        {quota && <p className="muted">{t('storageUsed', { used: formatBytes(quota.used), quota: formatBytes(quota.quota) })}</p>}
        <p className="help">{t('exportHelp')}</p>
        <button className="btn" disabled={exporting !== null} onClick={() => run('export', async () => {
          setExporting(0);
          try {
            const data = await client.exportAll((n) => setExporting(n));
            saveBytes(`voidmail-export-${new Date().toISOString().slice(0, 10)}.json`, JSON.stringify(data, null, 2), 'application/json');
          } finally {
            setExporting(null);
          }
        })}>{exporting !== null ? <Spinner label={t('exporting', { n: exporting })} /> : t('exportData')}</button>
      </Card>

      <Card title={t('securityEvents')}>
        {events.slice(0, 15).map((e, i) => (
          <div className="kv small" key={i}>
            <span className="mono">{e.type}</span>
            <span className="faint">{formatDate(e.at, locale, true)} {e.ipPrefix && <span dir="ltr">· {e.ipPrefix}</span>}</span>
          </div>
        ))}
      </Card>

      <Card title={t('deleteAccount')} help={t('deleteAccountHelp')}>
        <div className="grid2">
          <input className="input" type="password" placeholder={t('password')} aria-label={t('password')} value={del.password} onChange={(e) => setDel({ ...del, password: e.target.value })} />
          <input className="input mono" placeholder={t('deleteConfirm')} aria-label={t('deleteConfirm')} value={del.confirm} onChange={(e) => setDel({ ...del, confirm: e.target.value })} dir="ltr" />
        </div>
        <button className="btn danger" style={{ marginBlockStart: 12 }} disabled={del.confirm !== 'DELETE' || !del.password || busy === 'del'} onClick={() => run('del', async () => {
          await client.deleteAccount(del.password);
          localIndex.clear();
          location.hash = '#/login';
          location.reload();
        })}>{busy === 'del' ? <Spinner /> : t('deleteAccount')}</button>
      </Card>

      <button className="btn ghost" onClick={() => void client.logout().then(() => { localIndex.clear(); location.hash = '#/login'; location.reload(); })}>{t('signOut')}</button>
    </div>
  );
}
