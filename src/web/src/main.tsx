import { StrictMode, useCallback, useEffect, useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';
import './styles.css';
import { client } from './lib/api';
import { I18nContext, translate, type Key, type Locale } from './lib/i18n';
import { go, useHashRoute } from './lib/router';
import { localIndex } from './lib/search';
import { EmailReset, Login, Recover, Register, Unlock } from './pages/Auth';
import { Mailbox } from './pages/Mailbox';
import { Spinner, ToastHost } from './components/ui';

type Phase = 'boot' | 'anon' | 'locked' | 'ready';

function initialLocale(): Locale {
  try {
    const saved = localStorage.getItem('vm-locale');
    if (saved === 'ar' || saved === 'en') return saved;
  } catch {
    /* storage unavailable */
  }
  return navigator.language?.startsWith('ar') ? 'ar' : 'en';
}

function App() {
  const route = useHashRoute();
  const [phase, setPhase] = useState<Phase>('boot');
  const [locale, setLocaleState] = useState<Locale>(initialLocale);
  const [theme, setTheme] = useState<'system' | 'dark' | 'light'>('system');

  const setLocale = useCallback((l: Locale) => {
    setLocaleState(l);
    try {
      localStorage.setItem('vm-locale', l); // UI preference only; no personal data
    } catch {
      /* ignore */
    }
  }, []);

  useEffect(() => {
    document.documentElement.lang = locale;
    document.documentElement.dir = locale === 'ar' ? 'rtl' : 'ltr';
  }, [locale]);

  useEffect(() => {
    const apply = () => {
      const dark = theme === 'dark' || (theme === 'system' && window.matchMedia('(prefers-color-scheme: dark)').matches);
      document.documentElement.dataset.theme = dark ? 'dark' : 'light';
    };
    apply();
    const mq = window.matchMedia('(prefers-color-scheme: dark)');
    mq.addEventListener('change', apply);
    return () => mq.removeEventListener('change', apply);
  }, [theme]);

  const syncPrefs = useCallback(() => {
    const u = client.session?.user;
    if (!u) return;
    setTheme(u.theme);
    setLocale(u.locale);
  }, [setLocale]);

  useEffect(() => {
    client
      .resume()
      .then((ok) => {
        if (ok) syncPrefs();
        setPhase(ok ? 'locked' : 'anon');
      })
      .catch(() => setPhase('anon'));
  }, [syncPrefs]);

  // Keep theme in sync after settings changes.
  useEffect(() => {
    const id = setInterval(() => client.session && setTheme(client.session.user.theme), 1000);
    return () => clearInterval(id);
  }, []);

  // Lock the mailbox (drop keys from memory) when the session ends elsewhere.
  useEffect(() => {
    const onUnload = () => {
      client.lock();
      localIndex.clear();
    };
    window.addEventListener('pagehide', onUnload);
    return () => window.removeEventListener('pagehide', onUnload);
  }, []);

  const i18n = useMemo(() => ({ locale, setLocale, t: (k: Key, v?: Record<string, string | number>) => translate(locale, k, v) }), [locale, setLocale]);

  const ready = () => {
    syncPrefs();
    setPhase('ready');
    if (['login', 'register', 'recover', 'reset'].includes(route[0] ?? '')) go('f/inbox');
  };

  let content;
  if (phase === 'boot') content = <div className="auth"><Spinner /></div>;
  else if (route[0] === 'reset' && route[1]) content = <EmailReset token={route[1]} onDone={ready} />;
  else if (phase === 'anon') {
    if (route[0] === 'register') content = <Register onDone={ready} />;
    else if (route[0] === 'recover') content = <Recover onDone={ready} />;
    else content = <Login onDone={ready} />;
  } else if (phase === 'locked') content = <Unlock onDone={ready} />;
  else content = <Mailbox route={route.length ? route : ['f', 'inbox']} />;

  return (
    <I18nContext.Provider value={i18n}>
      {content}
      <ToastHost />
    </I18nContext.Provider>
  );
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
