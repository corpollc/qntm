import { createServer, type IncomingMessage, type ServerResponse } from 'node:http'
import { WebSocketServer, WebSocket } from 'ws'

interface StoredMessage {
  seq: number
  envelope_b64: string
  conv_id: string
}

/**
 * Minimal dropbox relay stub for e2e tests.
 * Implements the same wire protocol as the real dropbox relay:
 * - POST /v1/send — store envelope, return { seq }
 * - POST /v1/receipt — record receipt, return { recorded: true }
 * - WebSocket /v1/subscribe?conv_id=HEX&from_seq=N — replay + stream
 */
export class RelayStub {
  private messages: StoredMessage[] = []
  private nextSeq = 1
  private server: ReturnType<typeof createServer> | null = null
  private wss: WebSocketServer | null = null
  private subscribers: Map<string, Set<WebSocket>> = new Map()
  port = 0

  get url(): string {
    return `http://localhost:${this.port}`
  }

  async start(): Promise<void> {
    return new Promise((resolve) => {
      this.server = createServer((req, res) => this.handleHttp(req, res))
      this.wss = new WebSocketServer({ server: this.server })
      this.wss.on('connection', (ws, req) => this.handleWs(ws, req))
      this.server.listen(0, () => {
        const addr = this.server!.address()
        if (addr && typeof addr === 'object') {
          this.port = addr.port
        }
        resolve()
      })
    })
  }

  async stop(): Promise<void> {
    for (const subs of this.subscribers.values()) {
      for (const ws of subs) ws.close()
    }
    this.wss?.close()
    return new Promise((resolve) => {
      if (this.server) this.server.close(() => resolve())
      else resolve()
    })
  }

  reset(): void {
    this.messages = []
    this.nextSeq = 1
  }

  private handleHttp(req: IncomingMessage, res: ServerResponse): void {
    res.setHeader('Access-Control-Allow-Origin', '*')
    res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS')
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type')

    if (req.method === 'OPTIONS') {
      res.writeHead(204)
      res.end()
      return
    }

    if (req.method === 'POST' && req.url === '/v1/send') {
      this.handleSend(req, res)
      return
    }

    if (req.method === 'POST' && req.url === '/v1/receipt') {
      this.handleReceipt(req, res)
      return
    }

    res.writeHead(404)
    res.end(JSON.stringify({ error: 'not found' }))
  }

  private handleSend(req: IncomingMessage, res: ServerResponse): void {
    let body = ''
    req.on('data', (chunk: string) => { body += chunk })
    req.on('end', () => {
      try {
        const parsed = JSON.parse(body)
        const seq = this.nextSeq++
        const msg: StoredMessage = {
          seq,
          envelope_b64: parsed.envelope_b64,
          conv_id: parsed.conv_id,
        }
        this.messages.push(msg)

        const subs = this.subscribers.get(parsed.conv_id)
        if (subs) {
          const frame = JSON.stringify({ type: 'message', seq: msg.seq, envelope_b64: msg.envelope_b64 })
          for (const ws of subs) {
            if (ws.readyState === WebSocket.OPEN) ws.send(frame)
          }
        }

        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ seq }))
      } catch {
        res.writeHead(400)
        res.end(JSON.stringify({ error: 'bad request' }))
      }
    })
  }

  private handleReceipt(_req: IncomingMessage, res: ServerResponse): void {
    let body = ''
    _req.on('data', (chunk: string) => { body += chunk })
    _req.on('end', () => {
      res.writeHead(200, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ recorded: true, deleted: false, receipts: 1, required_acks: 1 }))
    })
  }

  private handleWs(ws: WebSocket, req: IncomingMessage): void {
    const url = new URL(req.url || '', `http://localhost:${this.port}`)
    const convId = url.searchParams.get('conv_id') || ''
    const fromSeq = parseInt(url.searchParams.get('from_seq') || '0', 10)

    if (!this.subscribers.has(convId)) {
      this.subscribers.set(convId, new Set())
    }
    this.subscribers.get(convId)!.add(ws)

    ws.on('close', () => {
      this.subscribers.get(convId)?.delete(ws)
    })

    const replay = this.messages.filter(m => m.conv_id === convId && m.seq > fromSeq)
    for (const msg of replay) {
      ws.send(JSON.stringify({ type: 'message', seq: msg.seq, envelope_b64: msg.envelope_b64 }))
    }

    const headSeq = this.messages.filter(m => m.conv_id === convId).at(-1)?.seq ?? fromSeq
    ws.send(JSON.stringify({ type: 'ready', head_seq: headSeq }))
  }
}
