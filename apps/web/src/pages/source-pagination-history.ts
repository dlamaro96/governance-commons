// SPDX-License-Identifier: Apache-2.0
/** Page predecessors belong to the URL selector, not to the last button click.
 * Keeping entries lets browser Back/Forward reuse the correct predecessor. */
export function sourcePageHistory() {
  const predecessors = new Map<string, string>();
  const key = (query: string, cursor: string) => JSON.stringify([query, cursor]);
  return {
    remember(query: string, currentCursor: string, nextCursor: string) {
      const next = key(query, nextCursor);
      predecessors.delete(next);
      predecessors.set(next, currentCursor);
      if (predecessors.size > 128) predecessors.delete(predecessors.keys().next().value!);
    },
    previous(query: string, cursor: string): string {
      return predecessors.get(key(query, cursor)) ?? '';
    },
  };
}
