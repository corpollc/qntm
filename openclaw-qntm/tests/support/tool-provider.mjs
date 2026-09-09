import assert from 'node:assert/strict';
import { createServer } from 'node:http';

/** Deterministic local model fixture: exercises the actual host tool-call loop. */
export async function createToolProvider() {
  const outcomes = new Map(), failures = [];
  const server = createServer(async (request, response) => {
    try {
      assert.equal(request.url, '/v1/chat/completions');
      let raw = '';
      for await (const chunk of request) { raw += chunk; assert.ok(raw.length < 2 * 1024 * 1024); }
      const body = JSON.parse(raw);
      const text = value => typeof value === 'string' ? value : (value ?? []).map(part => part.text ?? '').join('\n');
      let index = body.messages.length - 1;
      while (index >= 0 && !(body.messages[index].role === 'user' && text(body.messages[index].content).includes('gateway-tool-smoke:'))) index--;
      const marker = text(body.messages[index]?.content).match(/gateway-tool-smoke:([A-Za-z0-9_-]+)/);
      assert.ok(marker, 'native inbound test marker must reach the model: ' + JSON.stringify(body.messages.filter(message => message.role === 'user').map(message => text(message.content).slice(0, 512))));
      const plan = JSON.parse(Buffer.from(marker[1], 'base64url').toString());
      const names = body.tools?.map(tool => tool.function?.name) ?? [];
      assert.ok(names.includes('qntm_gateway'), `optional native tool absent: ${names.join(',')}`);
      const results = body.messages.slice(index + 1).filter(message => message.role === 'tool').map(message => JSON.parse(text(message.content)));
      let args;
      if (results.length === 0) args = { operation: 'status' };
      else if (results.length === 1) {
        assert.equal(results[0].status, 'accepted');
        args = { operation: 'prepare', action: plan.action, options: plan.options };
      } else if (results.length === 2) {
        assert.equal(results[1].status, 'review_required', JSON.stringify(results[1]));
        args = { operation: 'commit', reviewToken: results[1].reviewToken, reviewHash: results[1].reviewHash };
      } else {
        assert.equal(results.length, 3);
        assert.equal(results[2].status, 'submitted', JSON.stringify(results[2]));
        outcomes.set(plan.id, results);
      }
      const delta = args ? { role: 'assistant', tool_calls: [{ index: 0, id: `call_${plan.id}_${results.length}`, type: 'function',
        function: { name: 'qntm_gateway', arguments: JSON.stringify(args) } }] }
        : { role: 'assistant', content: `gateway-tool-complete:${plan.id}` };
      const chunk = { id: `chatcmpl-${plan.id}`, object: 'chat.completion.chunk', created: Math.floor(Date.now() / 1000), model: 'fixture',
        choices: [{ index: 0, delta, finish_reason: null }] };
      response.writeHead(200, { 'Content-Type': 'text/event-stream' });
      response.write(`data: ${JSON.stringify(chunk)}\n\n`);
      response.write(`data: ${JSON.stringify({ ...chunk, choices: [{ index: 0, delta: {}, finish_reason: args ? 'tool_calls' : 'stop' }],
        usage: { prompt_tokens: 100, completion_tokens: 30, total_tokens: 130 } })}\n\n`);
      response.end('data: [DONE]\n\n');
    } catch (error) {
      failures.push(String(error)); response.writeHead(500, { 'Content-Type': 'application/json' });
      response.end(JSON.stringify({ error: { message: String(error), type: 'fixture_error' } }));
    }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return { url: `http://127.0.0.1:${server.address().port}/v1`, outcomes, failures,
    close: () => new Promise((resolve, reject) => { server.close(error => error ? reject(error) : resolve()); server.closeAllConnections(); }) };
}
