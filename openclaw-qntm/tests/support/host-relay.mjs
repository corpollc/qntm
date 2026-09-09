import { createServer } from 'node:http';
import { WebSocketServer } from 'ws';

// A wire-level relay fixture. The smoke test uses the real OpenClaw executable,
// plugin loader, routing, session store, reply dispatcher and qntm encryption.
export async function createHostRelay() {
  const conversations = new Map();
  const get = (id) => {
    if (!conversations.has(id)) conversations.set(id, { messages: [], sockets: new Set() });
    return conversations.get(id);
  };
  const server = createServer(async (req, res) => {
    if (req.method !== 'POST' || req.url !== '/v1/send') {
      res.writeHead(404).end(); return;
    }
    try {
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const body = JSON.parse(Buffer.concat(chunks).toString());
      const conv = get(body.conv_id);
      const message = { type: 'message', seq: conv.messages.length + 1, envelope_b64: body.envelope_b64 };
      conv.messages.push(message);
      for (const socket of conv.sockets) socket.send(JSON.stringify(message));
      res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ seq: message.seq }));
    } catch { res.writeHead(400).end(); }
  });
  const wss = new WebSocketServer({ noServer: true });
  server.on('upgrade', (req, socket, head) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    if (url.pathname !== '/v1/subscribe') { socket.destroy(); return; }
    const conv = get(url.searchParams.get('conv_id'));
    const cursor = Number(url.searchParams.get('from_seq') ?? 0);
    wss.handleUpgrade(req, socket, head, (ws) => {
      conv.sockets.add(ws);
      ws.on('close', () => conv.sockets.delete(ws));
      for (const message of conv.messages.filter((m) => m.seq > cursor)) ws.send(JSON.stringify(message));
      ws.send(JSON.stringify({ type: 'ready', head_seq: conv.messages.length }));
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return {
    url: `http://127.0.0.1:${server.address().port}`,
    conversations,
    async close() {
      for (const conv of conversations.values()) for (const ws of conv.sockets) ws.terminate();
      await new Promise((resolve) => wss.close(resolve));
      await new Promise((resolve) => server.close(resolve));
    },
  };
}
