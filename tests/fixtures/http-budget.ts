// SPDX-License-Identifier: Apache-2.0
import { setTimeout as delay } from 'node:timers/promises';

/** Test traffic stays below the real 300/minute limit; responses are never retried. */
export const HTTP_ADMISSION_INTERVAL_MS = 500;
export type AdmissionClock = { now(): number; sleep(milliseconds: number, signal?: AbortSignal): Promise<void> };

function waitForAdmission(turn: Promise<void>, signal?: AbortSignal): Promise<void> {
  if (!signal) return turn;
  return new Promise((resolve, reject) => {
    const abort = () => reject(signal.reason);
    signal.addEventListener('abort', abort, { once: true });
    turn.then(() => { signal.removeEventListener('abort', abort); resolve(); },
      error => { signal.removeEventListener('abort', abort); reject(error); });
    if (signal.aborted) abort();
  });
}

/** Serialize admission only: concurrent in-flight requests retain their normal behavior. */
export function createPacedFetch(transport: typeof globalThis.fetch, clock: AdmissionClock): typeof globalThis.fetch {
  let admission = Promise.resolve();
  let lastStartedAt: number | null = null;
  return async (input, init) => {
    const signal = init?.signal === null ? undefined : init?.signal ?? (input instanceof Request ? input.signal : undefined);
    signal?.throwIfAborted();
    const turn = admission.then(async () => {
      signal?.throwIfAborted();
      while (lastStartedAt !== null) {
        const remaining = HTTP_ADMISSION_INTERVAL_MS - (clock.now() - lastStartedAt);
        if (remaining <= 0) break;
        try { await clock.sleep(remaining, signal); }
        catch (error) { signal?.throwIfAborted(); throw error; }
        signal?.throwIfAborted();
      }
      lastStartedAt = clock.now();
    });
    // A cancelled admission cannot poison later requests or consume a future slot.
    admission = turn.catch(() => {});
    await waitForAdmission(turn, signal);
    signal?.throwIfAborted();
    return transport(input, init);
  };
}

// The integration runner enforces --test-concurrency=1 across files. Every HTTP
// file explicitly imports this wrapper; there is no production/global fetch patch.
export const pacedFetch = createPacedFetch(globalThis.fetch, {
  now: () => performance.now(),
  sleep: async (milliseconds, signal) => { await delay(milliseconds, undefined, { signal }); },
});
