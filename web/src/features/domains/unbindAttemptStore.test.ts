import { describe, expect, it } from 'vitest';
import { createUnbindAttemptStore, type StorageLike } from './unbindAttemptStore';

class FakeStorage implements StorageLike {
  private readonly values = new Map<string, string>();
  get length() { return this.values.size; }
  getItem(key: string) { return this.values.get(key) ?? null; }
  setItem(key: string, value: string) { this.values.set(key, value); }
  removeItem(key: string) { this.values.delete(key); }
  key(index: number) { return [...this.values.keys()][index] ?? null; }
}

class ThrowingStorage implements StorageLike {
  get length(): number { throw new Error('storage unavailable'); }
  getItem(): string | null { throw new Error('storage unavailable'); }
  setItem(): void { throw new Error('storage unavailable'); }
  removeItem(): void { throw new Error('storage unavailable'); }
  key(): string | null { throw new Error('storage unavailable'); }
}

describe('unbind attempt store', () => {
  it('shares explicit attempts across instances and reconciles only one application namespace', () => {
    const storage = new FakeStorage();
    const first = createUnbindAttemptStore(storage);
    const second = createUnbindAttemptStore(storage);
    expect(first.getOrCreate('app-a', 'domain-1', () => 'attempt-a')).toBe('attempt-a');
    expect(second.getOrCreate('app-a', 'domain-1', () => 'unexpected')).toBe('attempt-a');
    first.getOrCreate('app-a', 'domain-2', () => 'attempt-b');
    first.getOrCreate('app-b', 'domain-1', () => 'attempt-other-app');
    second.reconcileApplication('app-a', new Set(['domain-1']));
    expect(first.getOrCreate('app-a', 'domain-1', () => 'unexpected')).toBe('attempt-a');
    expect(first.getOrCreate('app-a', 'domain-2', () => 'fresh-b')).toBe('fresh-b');
    expect(first.getOrCreate('app-b', 'domain-1', () => 'unexpected')).toBe('attempt-other-app');
    first.clear('app-a', 'domain-1');
    expect(second.getOrCreate('app-a', 'domain-1', () => 'fresh-a')).toBe('fresh-a');
  });

  it('keeps module-shared fallback stable when storage throws and clears stale keys', () => {
    const first = createUnbindAttemptStore(new ThrowingStorage());
    const second = createUnbindAttemptStore(new ThrowingStorage());
    expect(first.getOrCreate('throwing-app', 'active', () => 'fallback-active')).toBe('fallback-active');
    expect(second.getOrCreate('throwing-app', 'active', () => 'unexpected')).toBe('fallback-active');
    first.getOrCreate('throwing-app', 'failed', () => 'fallback-failed');
    first.reconcileApplication('throwing-app', new Set(['active']));
    expect(second.getOrCreate('throwing-app', 'failed', () => 'fresh-failed')).toBe('fresh-failed');
    first.reconcileApplication('throwing-app', new Set());
    expect(second.getOrCreate('throwing-app', 'active', () => 'fresh-active')).toBe('fresh-active');
  });
});
