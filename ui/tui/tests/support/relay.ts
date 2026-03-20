import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { Buffer } from 'node:buffer';
import type { AddressInfo } from 'node:net';
import { deserializeEnvelope } from '@corpollc/qntm';

interface RelayMessage {
  seq: number;
  msgIdHex: string;
  envelopeB64: string;
}

interface RelayConversation {
  nextSeq: number;
  messages: RelayMessage[];
  receipts: Map<string, Set<string>>;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

async function readJson(req: IncomingMessage): Promise<any> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  const raw = Buffer.concat(chunks).toString('utf8');
  return raw ? JSON.parse(raw) : {};
}

function sendJson(res: ServerResponse, statusCode: number, body: unknown): void {
  res.statusCode = statusCode;
  res.setHeader('Content-Type', 'application/json');
  res.end(JSON.stringify(body));
}

function decodeEnvelopeMsgId(envelopeB64: string): string {
  const bytes = new Uint8Array(Buffer.from(envelopeB64, 'base64'));
  const envelope = deserializeEnvelope(bytes);
  return toHex(envelope.msg_id);
}

export class TestRelayServer {
  private readonly server: Server;
  readonly conversations = new Map<string, RelayConversation>();
  url = '';

  constructor() {
    this.server = createServer(async (req, res) => {
      try {
        if (req.method === 'POST' && req.url === '/v1/send') {
          const body = await readJson(req);
          const conv = this.getConversation(body.conv_id);
          const seq = conv.nextSeq++;
          conv.messages.push({
            seq,
            msgIdHex: decodeEnvelopeMsgId(body.envelope_b64),
            envelopeB64: body.envelope_b64,
          });
          sendJson(res, 200, { seq });
          return;
        }

        if (req.method === 'POST' && req.url === '/v1/poll') {
          const body = await readJson(req);
          const maxMessages = typeof body.max_messages === 'number' ? body.max_messages : Number.MAX_SAFE_INTEGER;
          const conversations = (body.conversations ?? []).map((entry: any) => {
            const conv = this.getConversation(entry.conv_id);
            const fromSeq = Number(entry.from_seq ?? 0);
            const messages = conv.messages
              .filter((message) => message.seq > fromSeq)
              .slice(0, maxMessages)
              .map((message) => ({
                seq: message.seq,
                envelope_b64: message.envelopeB64,
              }));
            const upToSeq = conv.nextSeq > 1 ? conv.nextSeq - 1 : fromSeq;
            return {
              conv_id: entry.conv_id,
              up_to_seq: upToSeq,
              messages,
            };
          });
          sendJson(res, 200, { conversations });
          return;
        }

        if (req.method === 'POST' && req.url === '/v1/receipt') {
          const body = await readJson(req);
          const conv = this.getConversation(body.conv_id);
          const msgIdHex = String(body.msg_id);
          const readerKid = String(body.reader_kid);
          const requiredAcks = Number(body.required_acks ?? 0);
          const readers = conv.receipts.get(msgIdHex) ?? new Set<string>();
          const beforeSize = readers.size;
          readers.add(readerKid);
          conv.receipts.set(msgIdHex, readers);

          const deleted = readers.size >= requiredAcks
            ? this.deleteMessage(body.conv_id, msgIdHex)
            : false;

          sendJson(res, 200, {
            recorded: readers.size !== beforeSize,
            deleted,
            receipts: readers.size,
            required_acks: requiredAcks,
          });
          return;
        }

        sendJson(res, 404, { error: 'not found' });
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        sendJson(res, 500, { error: message });
      }
    });
  }

  async start(): Promise<void> {
    await new Promise<void>((resolve) => {
      this.server.listen(0, '127.0.0.1', () => resolve());
    });
    const address = this.server.address() as AddressInfo;
    this.url = `http://127.0.0.1:${address.port}`;
  }

  async close(): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      this.server.close((error) => {
        if (error) reject(error);
        else resolve();
      });
    });
  }

  messageCount(convId: string): number {
    return this.getConversation(convId).messages.length;
  }

  private getConversation(convId: string): RelayConversation {
    let conversation = this.conversations.get(convId);
    if (!conversation) {
      conversation = {
        nextSeq: 1,
        messages: [],
        receipts: new Map(),
      };
      this.conversations.set(convId, conversation);
    }
    return conversation;
  }

  private deleteMessage(convId: string, msgIdHex: string): boolean {
    const conv = this.getConversation(convId);
    const before = conv.messages.length;
    conv.messages = conv.messages.filter((message) => message.msgIdHex !== msgIdHex);
    return conv.messages.length !== before;
  }
}
