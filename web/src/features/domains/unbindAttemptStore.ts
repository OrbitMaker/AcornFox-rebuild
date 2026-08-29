export interface StorageLike { getItem(key: string): string | null; setItem(key: string, value: string): void; removeItem(key: string): void; key(index: number): string | null; readonly length: number; }

const prefix = 'open-card:unbind:';
const memory = new Map<string, string>();
const keyFor = (applicationId: string, domainId: string) => `${prefix}${applicationId}:${domainId}`;

function defaultStorage(): StorageLike | undefined {
  try {
    return typeof window === 'undefined' ? undefined : window.sessionStorage;
  } catch {
    return undefined;
  }
}

export function createUnbindAttemptStore(storage: StorageLike | undefined = defaultStorage()) {
  const read = (key: string) => { try { return storage?.getItem(key) ?? memory.get(key); } catch { return memory.get(key); } };
  const write = (key: string, value: string) => { memory.set(key, value); try { storage?.setItem(key, value); } catch { /* fallback retained */ } };
  const clearKey = (key: string) => { memory.delete(key); try { storage?.removeItem(key); } catch { /* fallback cleared */ } };
  const keys = () => { const result = new Set([...memory.keys()]); try { for (let i = 0; i < (storage?.length ?? 0); i++) { const key = storage?.key(i); if (key) result.add(key); } } catch { /* memory only */ } return result; };
  return {
    getOrCreate(applicationId: string, domainId: string, create: () => string) { const key = keyFor(applicationId, domainId); const value = read(key); if (value) return value; const next = create(); write(key, next); return next; },
    clear(applicationId: string, domainId: string) { clearKey(keyFor(applicationId, domainId)); },
    reconcileApplication(applicationId: string, active: ReadonlySet<string>) { for (const key of keys()) { if (!key.startsWith(`${prefix}${applicationId}:`)) continue; const domainId = key.slice(`${prefix}${applicationId}:`.length); if (!active.has(domainId)) clearKey(key); } },
  };
}
