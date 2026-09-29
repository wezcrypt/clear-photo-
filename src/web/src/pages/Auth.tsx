import { useState, type FormEvent, type ReactNode } from 'react';
import { client, saveBytes } from '../lib/api';
import { errorText, useT } from '../lib/i18n';
import { go, scrubHash } from '../lib/router';
import { CopyButton, Spinner } from '../components/ui';

function Shell({ children, wide }: { children: ReactNode; wide?: boolean }) {
  const { locale, setLocale } = useT();
  return (
    <main className="auth">
      <button className="btn sm ghost lang-switch" onClick={() => setLocale(locale === 'en' ? 'ar' : 'en')} lang={locale === 'en' ? 'ar' : 'en'}>
        {locale === 'en' ? 'العربية' : 'English'}
      </button>
      <div className={`auth-card${wide ? ' wide' : ''}`}>
        <div className="brand">
          <span className="brand-mark" aria-hidden="true" />
          VoidMail
        </div>
        {children}
      </div>
    </main>
  );
}

function useBusy() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const { t } = useT();
  const run = async (fn: () => Promise<void>) => {
    setBusy(true);
    setError(null);
    try {
      await fn();
    } catch (e) {
      setError(errorText(t, e));
    } finally {
      setBusy(false);
    }
  };
  return { busy, error, setError, run };
}

export function Login({ onDone }: { onDone: () => void }) {
  const { t } = useT();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [challenge, setChallenge] = useState<string | null>(null);
  const [code, setCode] = useState('');
  const { busy, error, run } = useBusy();

  const submit = (e: FormEvent) => {
    e.preventDefault();
    void run(async () => {
      if (challenge) {
        await client.loginTotp(challenge, code);
        onDone();
        return;
      }
      const r = await client.login(username, password);
      if (r.mfaRequired) setChallenge(r.challenge);
      else onDone();
    });
  };

  return (
    <Shell>
      <h1>{t('signIn')}</h1>
      <p className="sub">{t('tagline')}</p>
      <form onSubmit={submit} noValidate>
        {!challenge ? (
          <>
            <label className="field">
              <span>{t('username')}</span>
              <input className="input" autoComplete="username" autoCapitalize="none" spellCheck={false} value={username} onChange={(e) => setUsername(e.target.value)} required dir="ltr" />
            </label>
            <label className="field">
              <span>{t('password')}</span>
              <input className="input" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required />
            </label>
          </>
        ) : (
          <label className="field">
            <span>{t('twoFactorCode')}</span>
            <input className="input mono" inputMode="text" autoComplete="one-time-code" value={code} onChange={(e) => setCode(e.target.value)} autoFocus dir="ltr" />
          </label>
        )}
        {error && <p className="error" role="alert">{error}</p>}
        <button className="btn primary block" disabled={busy || (!challenge && (!username || !password))}>
          {busy ? <Spinner label={challenge ? t('working') : t('derivingKeys')} /> : challenge ? t('verify') : t('signIn')}
        </button>
      </form>
      <div className="foot">
        <button className="linkbtn" onClick={() => go('recover')}>{t('forgotPassword')}</button>
        <span className="spacer" />
        <span>{t('noAccount')}</span>
        <button className="linkbtn" onClick={() => go('register')}>{t('createAccount')}</button>
      </div>
    </Shell>
  );
}

export function RecoveryKeyScreen({ recoveryKey, onDone, title }: { recoveryKey: string; onDone: () => void; title?: string }) {
  const { t } = useT();
  const [ack, setAck] = useState(false);
  return (
    <Shell wide>
      <h1>{title ?? t('recoveryKeyTitle')}</h1>
      <p className="sub">{t('recoveryKeyHelp')}</p>
      <div className="recovery-key" aria-label={t('recoveryKey')}>{recoveryKey}</div>
      <div className="row" style={{ marginBlock: 12 }}>
        <CopyButton text={recoveryKey} />
        <button className="btn sm" onClick={() => saveBytes('voidmail-recovery-key.txt', `VoidMail recovery key for ${client.session?.user.address}\n\n${recoveryKey}\n`, 'text/plain')}>
          {t('download')}
        </button>
      </div>
      <label className="check">
        <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} />
        <span>{t('recoveryKeySaved')}</span>
      </label>
      <button className="btn primary block" style={{ marginBlockStart: 16 }} disabled={!ack} onClick={onDone}>
        {t('continue')}
      </button>
    </Shell>
  );
}

export function Register({ onDone }: { onDone: () => void }) {
  const { t } = useT();
  const [f, setF] = useState({ username: '', displayName: '', password: '', confirm: '', recoveryEmail: '' });
  const [recoveryKey, setRecoveryKey] = useState<string | null>(null);
  const { busy, error, setError, run } = useBusy();
  if (recoveryKey) return <RecoveryKeyScreen recoveryKey={recoveryKey} onDone={onDone} />;
  const set = (k: keyof typeof f) => (e: React.ChangeEvent<HTMLInputElement>) => setF({ ...f, [k]: e.target.value });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (f.password.length < 10) return setError(t('weakPassword'));
    if (f.password !== f.confirm) return setError(t('passwordsDontMatch'));
    void run(async () => {
      const r = await client.register({ username: f.username.trim().toLowerCase(), password: f.password, displayName: f.displayName.trim(), recoveryEmail: f.recoveryEmail.trim() || null });
      setRecoveryKey(r.recoveryKey);
    });
  };
  return (
    <Shell>
      <h1>{t('createAccount')}</h1>
      <p className="sub">{t('tagline')}</p>
      <form onSubmit={submit} noValidate>
        <label className="field">
          <span>{t('username')}</span>
          <input className="input" autoComplete="username" autoCapitalize="none" spellCheck={false} value={f.username} onChange={set('username')} dir="ltr" />
        </label>
        <label className="field">
          <span>{t('displayName')}</span>
          <input className="input" autoComplete="name" value={f.displayName} onChange={set('displayName')} />
        </label>
        <label className="field">
          <span>{t('password')}</span>
          <input className="input" type="password" autoComplete="new-password" value={f.password} onChange={set('password')} aria-describedby="pw-help" />
        </label>
        <p className="help" id="pw-help">{t('passwordHelp')}</p>
        <label className="field">
          <span>{t('confirmPassword')}</span>
          <input className="input" type="password" autoComplete="new-password" value={f.confirm} onChange={set('confirm')} />
        </label>
        <label className="field">
          <span>{t('recoveryEmailOptional')}</span>
          <input className="input" type="email" autoComplete="email" value={f.recoveryEmail} onChange={set('recoveryEmail')} dir="ltr" aria-describedby="re-help" />
        </label>
        <p className="help" id="re-help">{t('recoveryEmailHelp')}</p>
        {error && <p className="error" role="alert">{error}</p>}
        <button className="btn primary block" disabled={busy || !f.username || !f.password}>
          {busy ? <Spinner label={t('derivingKeys')} /> : t('createAccount')}
        </button>
      </form>
      <div className="foot">
        <span>{t('haveAccount')}</span>
        <button className="linkbtn" onClick={() => go('login')}>{t('signIn')}</button>
      </div>
    </Shell>
  );
}

export function Recover({ onDone }: { onDone: () => void }) {
  const { t } = useT();
  const [mode, setMode] = useState<'key' | 'email'>('key');
  const [f, setF] = useState({ username: '', key: '', password: '', confirm: '' });
  const [sent, setSent] = useState(false);
  const [newKey, setNewKey] = useState<string | null>(null);
  const { busy, error, setError, run } = useBusy();
  if (newKey) return <RecoveryKeyScreen recoveryKey={newKey} onDone={onDone} title={t('newRecoveryKey')} />;
  const set = (k: keyof typeof f) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => setF({ ...f, [k]: e.target.value });
  const submitKey = (e: FormEvent) => {
    e.preventDefault();
    if (f.password.length < 10) return setError(t('weakPassword'));
    if (f.password !== f.confirm) return setError(t('passwordsDontMatch'));
    void run(async () => setNewKey(await client.recoverWithKey(f.username.trim().toLowerCase(), f.key, f.password)));
  };
  const submitEmail = (e: FormEvent) => {
    e.preventDefault();
    void run(async () => {
      await client.requestEmailReset(f.username.trim().toLowerCase());
      setSent(true);
    });
  };
  return (
    <Shell wide>
      <h1>{t('recoverTitle')}</h1>
      <div className="row wrap" role="tablist" style={{ marginBlock: 14 }}>
        <button role="tab" aria-selected={mode === 'key'} className={`btn sm ${mode === 'key' ? 'primary' : ''}`} onClick={() => setMode('key')}>{t('recoverWithKey')}</button>
        <button role="tab" aria-selected={mode === 'email'} className={`btn sm ${mode === 'email' ? 'primary' : ''}`} onClick={() => setMode('email')}>{t('recoverWithEmail')}</button>
      </div>
      {mode === 'key' ? (
        <form onSubmit={submitKey} noValidate>
          <p className="notice ok">{t('recoverWithKeyHelp')}</p>
          <label className="field"><span>{t('username')}</span><input className="input" value={f.username} onChange={set('username')} autoCapitalize="none" dir="ltr" /></label>
          <label className="field"><span>{t('recoveryKey')}</span><textarea className="input mono" rows={3} value={f.key} onChange={set('key')} spellCheck={false} dir="ltr" /></label>
          <label className="field"><span>{t('newPassword')}</span><input className="input" type="password" autoComplete="new-password" value={f.password} onChange={set('password')} /></label>
          <label className="field"><span>{t('confirmPassword')}</span><input className="input" type="password" autoComplete="new-password" value={f.confirm} onChange={set('confirm')} /></label>
          {error && <p className="error" role="alert">{error}</p>}
          <button className="btn primary block" disabled={busy || !f.username || !f.key}>{busy ? <Spinner label={t('derivingKeys')} /> : t('continue')}</button>
        </form>
      ) : (
        <form onSubmit={submitEmail} noValidate>
          <p className="notice warn">{t('recoverWithEmailHelp')}</p>
          <label className="field"><span>{t('username')}</span><input className="input" value={f.username} onChange={set('username')} autoCapitalize="none" dir="ltr" /></label>
          {error && <p className="error" role="alert">{error}</p>}
          {sent ? <p className="notice" role="status">{t('resetRequested')}</p> : <button className="btn primary block" disabled={busy || !f.username}>{t('sendResetLink')}</button>}
        </form>
      )}
      <div className="foot">
        <button className="linkbtn" onClick={() => go('login')}>{t('back')}</button>
      </div>
    </Shell>
  );
}

export function EmailReset({ token, onDone }: { token: string; onDone: () => void }) {
  const { t } = useT();
  const [tok] = useState(() => {
    scrubHash('reset'); // keep the token out of history once read
    return token;
  });
  const [f, setF] = useState({ username: '', password: '', confirm: '', totp: '', confirmText: '' });
  const [newKey, setNewKey] = useState<string | null>(null);
  const { busy, error, setError, run } = useBusy();
  if (newKey) return <RecoveryKeyScreen recoveryKey={newKey} onDone={onDone} title={t('newRecoveryKey')} />;
  const set = (k: keyof typeof f) => (e: React.ChangeEvent<HTMLInputElement>) => setF({ ...f, [k]: e.target.value });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (f.password.length < 10) return setError(t('weakPassword'));
    if (f.password !== f.confirm) return setError(t('passwordsDontMatch'));
    void run(async () =>
      setNewKey(await client.completeEmailReset({ token: tok, username: f.username.trim().toLowerCase(), newPassword: f.password, totpCode: f.totp || undefined })),
    );
  };
  return (
    <Shell wide>
      <h1>{t('resetTitle')}</h1>
      <p className="notice danger" role="alert">{t('resetWarning')}</p>
      <form onSubmit={submit} noValidate style={{ marginBlockStart: 14 }}>
        <label className="field"><span>{t('username')}</span><input className="input" value={f.username} onChange={set('username')} autoCapitalize="none" dir="ltr" /></label>
        <div className="grid2">
          <label className="field"><span>{t('newPassword')}</span><input className="input" type="password" autoComplete="new-password" value={f.password} onChange={set('password')} /></label>
          <label className="field"><span>{t('confirmPassword')}</span><input className="input" type="password" autoComplete="new-password" value={f.confirm} onChange={set('confirm')} /></label>
        </div>
        <label className="field"><span>{t('totpIfEnabled')}</span><input className="input mono" value={f.totp} onChange={set('totp')} dir="ltr" /></label>
        <label className="field"><span>{t('resetConfirmLabel')}</span><input className="input mono" value={f.confirmText} onChange={set('confirmText')} dir="ltr" /></label>
        {error && <p className="error" role="alert">{error}</p>}
        <button className="btn danger block" disabled={busy || f.confirmText !== 'RESET' || !f.username}>{busy ? <Spinner label={t('derivingKeys')} /> : t('resetAccount')}</button>
      </form>
    </Shell>
  );
}

export function Unlock({ onDone }: { onDone: () => void }) {
  const { t } = useT();
  const [password, setPassword] = useState('');
  const { busy, error, run } = useBusy();
  return (
    <Shell>
      <h1>{t('unlockTitle')}</h1>
      <p className="sub">{t('unlockHelp')}</p>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void run(async () => {
            await client.unlock(password);
            onDone();
          });
        }}
      >
        <p className="muted small" dir="ltr">{client.session?.user.address}</p>
        <label className="field">
          <span>{t('password')}</span>
          <input className="input" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} autoFocus />
        </label>
        {error && <p className="error" role="alert">{error}</p>}
        <button className="btn primary block" disabled={busy || !password}>{busy ? <Spinner label={t('derivingKeys')} /> : t('unlock')}</button>
      </form>
      <div className="foot">
        <button className="linkbtn" onClick={() => void client.logout().then(() => { go('login'); location.reload(); })}>{t('signOut')}</button>
      </div>
    </Shell>
  );
}
