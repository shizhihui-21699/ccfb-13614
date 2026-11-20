// Thin browser-side client for the dumb relay server.
// Only transports opaque JSON; all crypto lives in crypto/*.

import type { GroupCommit, GroupEvent, StoredEvent } from "../crypto/protocol.js";

export class RelayClient {
  constructor(private base = "") {}

  async listGroups(): Promise<string[]> {
    const r = await fetch(`${this.base}/api/groups`);
    if (!r.ok) throw new Error(`listGroups failed: ${r.status}`);
    return ((await r.json()) as { groups: string[] }).groups;
  }

  async fetchEvents(groupId: string, after = 0): Promise<StoredEvent[]> {
    const r = await fetch(`${this.base}/api/groups/${encodeURIComponent(groupId)}/events?after=${after}`);
    if (!r.ok) throw new Error(`fetchEvents failed: ${r.status}`);
    return ((await r.json()) as { events: StoredEvent[] }).events;
  }

  async postEvent(groupId: string, event: GroupEvent): Promise<StoredEvent> {
    const r = await fetch(`${this.base}/api/groups/${encodeURIComponent(groupId)}/events`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ event }),
    });
    if (!r.ok) throw new Error(`postEvent failed: ${r.status} ${await r.text()}`);
    return ((await r.json()) as { stored: StoredEvent }).stored;
  }

  /** Full server dump — used by the in-page attacker panel. */
  async dump(): Promise<StoredEvent[]> {
    const r = await fetch(`${this.base}/api/dump`);
    if (!r.ok) throw new Error(`dump failed: ${r.status}`);
    return ((await r.json()) as { events: StoredEvent[] }).events;
  }

  /** Live SSE stream for a group. Returns an unsubscribe function. */
  stream(groupId: string, onEvent: (stored: StoredEvent) => void): () => void {
    const es = new EventSource(
      `${this.base}/api/groups/${encodeURIComponent(groupId)}/stream`,
    );
    es.addEventListener("event", (ev: MessageEvent) => {
      onEvent(JSON.parse(ev.data) as StoredEvent);
    });
    return () => es.close();
  }
}

export type { GroupCommit };
