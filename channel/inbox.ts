import { closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { randomUUID } from 'node:crypto';
import type { ReceiveEvent } from '@corpollc/qntm';

/** Replace private state atomically; never expose a partially written journal. */
export function saveJson(path: string, value: unknown): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = `${path}.${randomUUID()}.tmp`;
  const fd = openSync(temporary, 'wx', 0o600);
  try {
    writeFileSync(fd, JSON.stringify(value) + '\n');
    fsyncSync(fd);
  } finally { closeSync(fd); }
  try { renameSync(temporary, path); }
  finally { if (existsSync(temporary)) unlinkSync(temporary); }
  const directory = openSync(dirname(path), 'r');
  try { fsyncSync(directory); } finally { closeSync(directory); }
}

interface State { version: 1; cursor: number; pending: ReceiveEvent[]; received_event_ids?: string[] }

/** One bridge owns this journal. CLI cursors and seen state never acknowledge it. */
export class ChannelInbox {
  private state: State;
  private draining?: Promise<void>;

  constructor(private path: string, initialCursor = 0) {
    this.state = existsSync(path)
      ? JSON.parse(readFileSync(path, 'utf8')) as State
      : { version: 1, cursor: initialCursor, pending: [] };
    if (this.state.version !== 1 || !Number.isSafeInteger(this.state.cursor) || this.state.cursor < 0 || !Array.isArray(this.state.pending)) {
      throw new Error('Invalid channel inbox; refusing to discard pending notifications');
    }
    this.state.received_event_ids ??= this.state.pending.map(event => event.event_id);
    if (!Array.isArray(this.state.received_event_ids) || this.state.received_event_ids.some(id => typeof id !== 'string')) {
      throw new Error('Invalid channel delivery history');
    }
    saveJson(path, this.state);
  }

  get cursor(): number { return this.state.cursor; }
  get pending(): readonly ReceiveEvent[] { return this.state.pending; }

  capture(sequence: number, event?: ReceiveEvent): void {
    if (sequence <= this.state.cursor) return;
    const pending = [...this.state.pending];
    const received = [...this.state.received_event_ids!];
    if (event && !received.includes(event.event_id)) {
      pending.push(event);
      received.push(event.event_id);
    }
    const next: State = { version: 1, cursor: sequence, pending, received_event_ids: received };
    saveJson(this.path, next);
    this.state = next;
  }

  /** A failed handoff retains the event. A crash after send can cause a duplicate. */
  drain(deliver: (event: ReceiveEvent) => Promise<void>): Promise<void> {
    if (this.draining) return this.draining;
    this.draining = this.deliverPending(deliver).finally(() => { this.draining = undefined; });
    return this.draining;
  }

  private async deliverPending(deliver: (event: ReceiveEvent) => Promise<void>): Promise<void> {
    while (this.state.pending.length) {
      const event = this.state.pending[0];
      await deliver(event);
      // Capture can append while the transport is awaiting. Preserve those events.
      const next: State = { ...this.state, pending: this.state.pending.slice(1) };
      saveJson(this.path, next);
      this.state = next;
    }
  }
}
