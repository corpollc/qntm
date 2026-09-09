// Vite 6's normal listen() treats port 0 as its default port. Bind the public
// HTTP server ourselves and use Vite's supported middleware/HMR integration.
import { createServer } from 'node:http';
import { createServer as createViteServer } from 'vite';

const portIndex = process.argv.indexOf('--port');
const port = portIndex < 0 ? 0 : Number(process.argv[portIndex + 1]);
if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error('Invalid test listener port');

const http = createServer();
const vite = await createViteServer({
  root: process.cwd(),
  server: { middlewareMode: true, hmr: { server: http }, host: '127.0.0.1' },
});
http.on('request', (request, response) => vite.middlewares(request, response, () => {
  response.writeHead(404).end();
}));

let closing = false;
async function close() {
  if (closing) return;
  closing = true;
  await vite.close();
  http.closeAllConnections();
  await new Promise((resolve, reject) => http.close(error => error ? reject(error) : resolve()));
}
for (const signal of ['SIGTERM', 'SIGINT']) {
  process.once(signal, () => void close().then(() => process.exit(0), error => {
    console.error(error);
    process.exit(1);
  }));
}
try {
  await new Promise((resolve, reject) => {
    http.once('error', reject);
    http.listen(port, '127.0.0.1', resolve);
  });
  console.log(`Local: http://127.0.0.1:${http.address().port}`);
} catch (error) {
  await vite.close();
  throw error;
}
