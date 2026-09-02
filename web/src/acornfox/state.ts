/** An accepted command has one explicit authoritative read; convergence stays manual. */
export async function refetchAfterAccepted<T>(
  refresh: () => Promise<T>,
): Promise<T> {
  return refresh();
}

/** Keeps only the most recent request in one independently observable region. */
export class LatestRequest {
  #generation = 0;

  begin(): () => boolean {
    const generation = ++this.#generation;
    return () => generation === this.#generation;
  }

  invalidate(): void {
    this.#generation += 1;
  }
}

/** Coordinates one user scope and prevents stale action completions. */
export class ActionScope {
  #generation = 0;
  #pending = false;

  begin(): { current: () => boolean; finish: () => boolean } | undefined {
    if (this.#pending) return undefined;
    this.#pending = true;
    const generation = ++this.#generation;
    return {
      current: () => generation === this.#generation,
      finish: () => {
        if (generation !== this.#generation) return false;
        this.#pending = false;
        return true;
      },
    };
  }

  invalidate(): void {
    this.#generation += 1;
    this.#pending = false;
  }
}
