/**
 * Mock for cloudflare:workers — provides a minimal DurableObject base class
 * so gateway DO tests can run outside the Cloudflare runtime.
 */
export class DurableObject<E = unknown> {
  protected ctx: DurableObjectState;
  protected env: E;

  constructor(ctx: DurableObjectState, env: E) {
    this.ctx = ctx;
    this.env = env;
  }
}
