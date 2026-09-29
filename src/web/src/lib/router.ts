import { useEffect, useState } from 'react';

/** Hash routing keeps secrets (e.g. reset tokens) out of server-visible URLs and access logs. */
export function useHashRoute(): string[] {
  const read = () => window.location.hash.replace(/^#\/?/, '').split('/').filter(Boolean).map(decodeURIComponent);
  const [parts, setParts] = useState(read);
  useEffect(() => {
    const on = () => setParts(read());
    window.addEventListener('hashchange', on);
    return () => window.removeEventListener('hashchange', on);
  }, []);
  return parts;
}

export function go(path: string): void {
  window.location.hash = '#/' + path.replace(/^\/+/, '');
}

/** Removes a secret from the address bar and history after reading it. */
export function scrubHash(replacement: string): void {
  history.replaceState(null, '', '#/' + replacement);
}
