// Relay server storage: an append-only, per-group event log.
// The server treats every event as an opaque JSON blob. It never sees
// plaintext, epoch secrets, or private keys — those are sealed client-side.
//
// Persistence is a simple write-through JSON file (data/store.json), sufficient
// for a local demo / single-node relay. Swap this module for a database in
// production without touching any crypto code.

import { readFileSync, writeFileSync, mkdirSync, existsSync, renameSync } from "node:fs";
import { dirname } from "node:path";
import type { GroupEvent } from "../client/crypto/protocol.js";

export interface StoredEvent {
  eventId: string;
  timestamp: number;
  event: GroupEvent;
}

interface StoreShape {
  groups: Record<string, StoredEvent[]>;
  counters: Record<string, number>;
}

export class RelayStore {
  private data: StoreShape = { groups: {}, counters: {} };

  constructor(private readonly file?: string) {
    if (file && existsSync(file)) {
      try {
        this.data = JSON.parse(readFileSync(file, "utf8")) as StoreShape;
      } catch {
        this.data = { groups: {}, counters: {} };
      }
    }
  }

  listGroups(): string[] {
    return Object.keys(this.data.groups);
  }

  events(groupId: string, after = 0): StoredEvent[] {
    const all = this.data.groups[groupId] ?? [];
    return all.filter((_, i) => i >= after);
  }

  allEvents(): StoredEvent[] {
    const out: StoredEvent[] = [];
    for (const g of Object.keys(this.data.groups)) out.push(...this.data.groups[g]!);
    return out.sort((a, b) => a.timestamp - b.timestamp || a.eventId.localeCompare(b.eventId));
  }

  append(groupId: string, event: GroupEvent): StoredEvent {
    const n = (this.data.counters[groupId] ?? 0) + 1;
    this.data.counters[groupId] = n;
    const stored: StoredEvent = {
      eventId: `evt_${groupId}_${n.toString().padStart(6, "0")}`,
      timestamp: Date.now(),
      event,
    };
    (this.data.groups[groupId] ??= []).push(stored);
    this.persist();
    return stored;
  }

  /** Full dump used by the side-channel attacker ("compromised server disk"). */
  dump(): StoredEvent[] {
    return this.allEvents();
  }

  private persist() {
    if (!this.file) return;
    mkdirSync(dirname(this.file), { recursive: true });
    const tmp = `${this.file}.tmp`;
    writeFileSync(tmp, JSON.stringify(this.data));
    renameSync(tmp, this.file); // atomic on POSIX
  }
}
