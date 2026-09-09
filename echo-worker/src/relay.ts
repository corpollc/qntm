import type { SubscriptionMessage } from '@corpollc/qntm';

/** Bounded replay with per-envelope cursors; never acknowledges deferred work. */
export async function readRelayBatch(relay: string, conversationId: string, cursor: number, limit = 32): Promise<{ messages: SubscriptionMessage[]; sequence: number }> {
  const url = new URL('/v1/subscribe', relay);
  url.searchParams.set('conv_id', conversationId);
  url.searchParams.set('from_seq', String(cursor));
  const response = await fetch(url, { headers: { Upgrade: 'websocket' } });
  const socket = response.webSocket;
  if (!socket) throw new Error(`Relay did not accept subscription (${response.status})`);
  return new Promise((resolve, reject) => {
    const messages: SubscriptionMessage[] = [];
    let sequence = cursor, settled = false;
    const timer = setTimeout(() => finish(new Error('Relay replay timed out')), 15_000);
    function finish(error?: Error) {
      if (settled) return;
      settled = true; clearTimeout(timer);
      try { socket!.close(1000, 'bounded replay complete'); } catch { /* Best effort. */ }
      if (error) reject(error); else resolve({ messages, sequence });
    }
    socket.addEventListener('message', event => {
      if (settled) return;
      try {
        if (typeof event.data !== 'string') throw new Error('Expected text relay frame');
        const frame = JSON.parse(event.data);
        if (frame.type === 'message') {
          if (!Number.isSafeInteger(frame.seq) || frame.seq <= sequence) throw new Error('Invalid relay sequence');
          const envelope = Uint8Array.from(atob(frame.envelope_b64), c => c.charCodeAt(0));
          messages.push({ seq: frame.seq, envelope }); sequence = frame.seq;
          if (messages.length >= limit) finish();
        } else if (frame.type === 'ready') {
          if (!Number.isSafeInteger(frame.head_seq) || frame.head_seq < sequence) throw new Error('Invalid relay head');
          sequence = frame.head_seq; finish();
        } else throw new Error('Unexpected relay frame');
      } catch { finish(new Error('Invalid relay replay frame')); }
    });
    socket.addEventListener('error', () => finish(new Error('Relay subscription failed')));
    socket.addEventListener('close', () => finish(new Error('Relay closed before replay completed')));
    socket.accept();
  });
}
