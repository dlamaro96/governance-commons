// SPDX-License-Identifier: Apache-2.0
/** Deterministic scheduler controls, not real HTTP/API qualification. */
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createPacedFetch, HTTP_ADMISSION_INTERVAL_MS, type AdmissionClock } from '../fixtures/http-budget.ts';

class Clock implements AdmissionClock {
  time = 0;
  pending = new Set<{ deadline: number; finish(): void }>();
  now = () => this.time;
  sleep = (milliseconds: number, signal?: AbortSignal): Promise<void> => new Promise((resolve, reject) => {
    const finish = () => { this.pending.delete(item); signal?.removeEventListener('abort', abort); resolve(); };
    const abort = () => { this.pending.delete(item); signal?.removeEventListener('abort', abort); reject(signal?.reason); };
    const item = { deadline: this.time + milliseconds, finish };
    this.pending.add(item); signal?.addEventListener('abort', abort, { once: true });
    if (signal?.aborted) abort();
  });
  advance(time: number) {
    assert.ok(time >= this.time); this.time = time;
    for (const item of [...this.pending]) if (item.deadline <= time) item.finish();
  }
}
async function flush() { for (let index = 0; index < 12; index++) await Promise.resolve(); }
const url = 'https://synthetic.invalid/example';

test('HTTP budget admits concurrent requests 500ms apart without serializing responses or retrying 429', async () => {
  const clock = new Clock(), starts: number[] = [], finish: ((response: Response) => void)[] = [];
  const fetch = createPacedFetch(async () => { starts.push(clock.time); return new Promise(resolve => finish.push(resolve)); }, clock);
  const requests = [fetch(url), fetch(url), fetch(url)];
  await flush(); assert.deepEqual(starts, [0]);
  clock.advance(499); await flush(); assert.deepEqual(starts, [0]);
  clock.advance(500); await flush(); assert.deepEqual(starts, [0, 500]);
  clock.advance(1000); await flush(); assert.deepEqual(starts, [0, 500, 1000]);
  assert.equal(HTTP_ADMISSION_INTERVAL_MS, 500);
  const responses = [new Response(null, { status: 200 }), new Response(null, { status: 429 }), new Response(null, { status: 503 })];
  finish[2](responses[2]); finish[0](responses[0]); finish[1](responses[1]);
  const observed = await Promise.all(requests);
  observed.forEach((response, index) => assert.equal(response, responses[index]));
  assert.equal(starts.length, 3);
});

test('HTTP budget rechecks monotonic time after an early timer wake', async () => {
  const clock = new Clock(), starts: number[] = [];
  const fetch = createPacedFetch(async () => { starts.push(clock.time); return new Response(); }, clock);
  await fetch(url); const next = fetch(url); await flush();
  clock.advance(250); [...clock.pending][0].finish(); await flush();
  assert.deepEqual(starts, [0]); assert.equal([...clock.pending][0].deadline, 500);
  clock.advance(500); await next; assert.deepEqual(starts, [0, 500]);
});

test('HTTP budget preserves abort reasons immediately and cancelled admissions do not delay later requests', async () => {
  const clock = new Clock(), starts: number[] = [];
  const fetch = createPacedFetch(async () => { starts.push(clock.time); return new Response(); }, clock);
  const already = new AbortController(), earlyReason = new Error('synthetic pre-admission cancellation'); already.abort(earlyReason);
  await assert.rejects(fetch(url, { signal: already.signal }), error => error === earlyReason); assert.deepEqual(starts, []);
  await fetch(url);
  const controller = new AbortController(), reason = new Error('synthetic waiting cancellation');
  const cancelled = fetch(url, { signal: controller.signal });
  const rejected = assert.rejects(cancelled, error => error === reason);
  const next = fetch(url); await flush();
  controller.abort(reason); await rejected; await flush();
  assert.deepEqual(starts, [0]); assert.equal(clock.pending.size, 1);
  clock.advance(500); await next; assert.deepEqual(starts, [0, 500]);
});

test('HTTP budget preserves Request inputs, explicit signal overrides, init identity and in-flight abort behavior', async () => {
  const clock = new Clock(), controller = new AbortController(), reason = new Error('synthetic in-flight cancellation');
  const request = new Request(url, { method: 'POST', body: 'synthetic', signal: controller.signal });
  const init: RequestInit = { headers: { 'X-Synthetic': 'unchanged' }, signal: controller.signal };
  let count = 0;
  const fetch = createPacedFetch(async (input, options) => {
    count++; assert.equal(input, request); assert.equal(options, init);
    return new Promise((_resolve, reject) => options!.signal!.addEventListener('abort', () => reject(options!.signal!.reason), { once: true }));
  }, clock);
  const pending = fetch(request, init), rejected = assert.rejects(pending, error => error === reason);
  await flush(); controller.abort(reason); await rejected; assert.equal(count, 1);
  await assert.rejects(fetch(request), error => error === reason); assert.equal(count, 1);
  const replacement = new Response(null, { status: 202 });
  const override = createPacedFetch(async (input, options) => { assert.equal(input, request); assert.equal(options?.signal, null); return replacement; }, clock);
  assert.equal(await override(request, { signal: null }), replacement);
});

test('HTTP budget rejects a queued abort before the preceding admission finishes', async () => {
  const clock = new Clock(), starts: number[] = [];
  const fetch = createPacedFetch(async () => { starts.push(clock.time); return new Response(); }, clock);
  await fetch(url); const preceding = fetch(url);
  const controller = new AbortController(), reason = new Error('synthetic queued cancellation');
  const cancelled = fetch(url, { signal: controller.signal }), rejected = assert.rejects(cancelled, error => error === reason);
  const following = fetch(url); await flush(); controller.abort(reason);
  await rejected; assert.equal(clock.time, 0); assert.deepEqual(starts, [0]);
  clock.advance(500); await preceding; await flush(); assert.deepEqual(starts, [0, 500]);
  clock.advance(1000); await following; assert.deepEqual(starts, [0, 500, 1000]);
});

test('HTTP budget preserves transport rejection and keeps later admission usable without retries', async () => {
  const clock = new Clock(), reason = new Error('synthetic transport failure'); let calls = 0;
  const fetch = createPacedFetch(async () => { calls++; if (calls === 1) throw reason; return new Response(); }, clock);
  await assert.rejects(fetch(url), error => error === reason);
  const next = fetch(url); await flush(); assert.equal(calls, 1);
  clock.advance(500); await next; assert.equal(calls, 2);
});
