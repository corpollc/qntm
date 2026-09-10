/** Transparent local proxy: record actual send attempts without changing wire data. */
import { createServer, request } from 'node:http';
import { connect, type Socket } from 'node:net';
import { once } from 'node:events';

export async function recordingRelay(upstreamUrl: string, options: {
  /** Observe durable client state before the exact request reaches the relay. */
  onSend?: (send: { conv_id: string; envelope_b64: string }) => void;
} = {}) {
  const relay = new URL(upstreamUrl), sockets = new Set<Socket>();
  const sends: Array<{ conv_id: string; envelope_b64: string }> = [];
  let dropAcknowledgement = false;
  let droppedAcknowledgements = 0;
  let pauseReplayAfterDrop = false;
  let replayPaused = false;
  let blockedReplays = 0;
  const server = createServer(async (incoming, outgoing) => {
    const chunks: Buffer[] = [];
    for await (const chunk of incoming) chunks.push(Buffer.from(chunk));
    const body = Buffer.concat(chunks);
    const isSend = incoming.method === 'POST' && incoming.url === '/v1/send';
    if (isSend) {
      const send = JSON.parse(body.toString());
      sends.push(send);
      options.onSend?.(send);
    }
    const drop = isSend && dropAcknowledgement;
    if (drop) dropAcknowledgement = false;
    const upstream = request(new URL(incoming.url!, relay), {
      method: incoming.method, headers: { ...incoming.headers, host: relay.host },
    }, response => {
      if (drop && response.statusCode === 201) {
        // Drain the real relay's ACK, proving it committed before losing the
        // client response. Do not resend or alter the request ciphertext.
        response.resume();
        response.once('end', () => {
          droppedAcknowledgements++;
          replayPaused = pauseReplayAfterDrop;
          outgoing.destroy();
        });
      } else { outgoing.writeHead(response.statusCode!, response.headers); response.pipe(outgoing); }
    });
    upstream.on('error', () => outgoing.destroy());
    upstream.end(body);
  });
  server.on('connection', socket => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
  server.on('upgrade', (incoming, socket, head) => {
    if (replayPaused) {
      blockedReplays++;
      socket.end('HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n');
      return;
    }
    const upstream = connect(Number(relay.port), relay.hostname, () => {
      const headers = { ...incoming.headers, host: relay.host };
      upstream.write(`${incoming.method} ${incoming.url} HTTP/1.1\r\n${Object.entries(headers).map(([key, value]) => `${key}: ${value}`).join('\r\n')}\r\n\r\n`);
      if (head.length) upstream.write(head);
      socket.pipe(upstream); upstream.pipe(socket);
    });
    sockets.add(upstream); upstream.on('close', () => sockets.delete(upstream));
    upstream.on('error', () => socket.destroy()); socket.on('error', () => upstream.destroy());
    upstream.on('close', () => socket.destroy()); socket.on('close', () => upstream.destroy());
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  return {
    url: `http://127.0.0.1:${(server.address() as { port: number }).port}`,
    sends,
    loseNextSendAcknowledgement(options: { pauseReplay?: boolean } = {}) {
      dropAcknowledgement = true;
      pauseReplayAfterDrop = options.pauseReplay ?? false;
    },
    resumeReplay() { replayPaused = false; },
    get droppedAcknowledgements() { return droppedAcknowledgements; },
    get blockedReplays() { return blockedReplays; },
    async stop() {
      for (const socket of sockets) socket.destroy();
      server.closeAllConnections();
      await new Promise<void>(resolve => server.close(() => resolve()));
    },
  };
}
