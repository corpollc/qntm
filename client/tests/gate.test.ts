import { describe, it, expect } from 'vitest';
import {
  GateMessagePromote,
  GateMessageConfig,
  GateMessageSecret,
  GateMessageResult,
  resolveRecipe,
} from '../src/gate/index.js';
import type {
  Recipe,
  RecipeParam,
  RecipeCatalog,
  PromotePayload,
  ConfigPayload,
  SecretPayload,
  GateConversationMessage,
} from '../src/types.js';

// === 1. Gate Message Type Constants ===
describe('Gate Message Type Constants', () => {
  it('has gate.promote constant', () => {
    expect(GateMessagePromote).toBe('gate.promote');
  });

  it('has gate.config constant', () => {
    expect(GateMessageConfig).toBe('gate.config');
  });

  it('has gate.secret constant', () => {
    expect(GateMessageSecret).toBe('gate.secret');
  });

  it('has gate.result constant', () => {
    expect(GateMessageResult).toBe('gate.result');
  });
});

// === 2. Recipe Types ===
describe('Recipe Types', () => {
  it('RecipeParam structure is well-typed', () => {
    const param: RecipeParam = {
      name: 'owner',
      description: 'Repository owner',
      required: true,
      type: 'string',
    };
    expect(param.name).toBe('owner');
    expect(param.required).toBe(true);
    expect(param.type).toBe('string');
    expect(param.default).toBeUndefined();
  });

  it('RecipeParam with default value', () => {
    const param: RecipeParam = {
      name: 'per_page',
      description: 'Results per page',
      required: false,
      default: '30',
      type: 'integer',
    };
    expect(param.default).toBe('30');
    expect(param.required).toBe(false);
  });

  it('Recipe structure is well-typed', () => {
    const recipe: Recipe = {
      name: 'github.list-repos',
      description: 'List repositories for a user',
      service: 'github',
      verb: 'GET',
      endpoint: '/users/{owner}/repos',
      target_url: 'https://api.github.com/users/{owner}/repos',
      risk_tier: 'read',
      threshold: 1,
      path_params: [
        { name: 'owner', description: 'GitHub username', required: true, type: 'string' },
      ],
      query_params: [
        { name: 'per_page', description: 'Results per page', required: false, default: '30', type: 'integer' },
      ],
    };
    expect(recipe.name).toBe('github.list-repos');
    expect(recipe.service).toBe('github');
    expect(recipe.path_params).toHaveLength(1);
    expect(recipe.query_params).toHaveLength(1);
  });

  it('Recipe with body_schema', () => {
    const recipe: Recipe = {
      name: 'github.create-issue',
      description: 'Create an issue',
      service: 'github',
      verb: 'POST',
      endpoint: '/repos/{owner}/{repo}/issues',
      target_url: 'https://api.github.com/repos/{owner}/{repo}/issues',
      risk_tier: 'write',
      threshold: 2,
      path_params: [
        { name: 'owner', description: 'Repo owner', required: true, type: 'string' },
        { name: 'repo', description: 'Repo name', required: true, type: 'string' },
      ],
      body_schema: {
        type: 'object',
        properties: {
          title: { type: 'string' },
          body: { type: 'string' },
        },
        required: ['title'],
      },
    };
    expect(recipe.body_schema).toBeDefined();
    expect((recipe.body_schema as Record<string, unknown>).type).toBe('object');
  });

  it('RecipeCatalog structure is well-typed', () => {
    const catalog: RecipeCatalog = {
      profiles: {},
      recipes: {},
    };
    expect(catalog.profiles).toEqual({});
    expect(catalog.recipes).toEqual({});
  });
});

// === 3. ResolveRecipe ===
describe('resolveRecipe', () => {
  it('substitutes path params in endpoint and target_url', () => {
    const recipe: Recipe = {
      name: 'test.get',
      description: 'Test',
      service: 'test',
      verb: 'GET',
      endpoint: '/users/{owner}/repos',
      target_url: 'https://api.example.com/users/{owner}/repos',
      risk_tier: 'read',
      threshold: 1,
      path_params: [
        { name: 'owner', description: 'Owner', required: true, type: 'string' },
      ],
    };

    const result = resolveRecipe(recipe, { owner: 'octocat' });
    expect(result.endpoint).toBe('/users/octocat/repos');
    expect(result.target_url).toBe('https://api.example.com/users/octocat/repos');
    expect(result.body).toBeUndefined();
  });

  it('substitutes multiple path params', () => {
    const recipe: Recipe = {
      name: 'test.multi',
      description: 'Test multi params',
      service: 'test',
      verb: 'GET',
      endpoint: '/repos/{owner}/{repo}/issues',
      target_url: 'https://api.example.com/repos/{owner}/{repo}/issues',
      risk_tier: 'read',
      threshold: 1,
      path_params: [
        { name: 'owner', description: 'Owner', required: true, type: 'string' },
        { name: 'repo', description: 'Repo', required: true, type: 'string' },
      ],
    };

    const result = resolveRecipe(recipe, { owner: 'octocat', repo: 'hello-world' });
    expect(result.endpoint).toBe('/repos/octocat/hello-world/issues');
    expect(result.target_url).toBe('https://api.example.com/repos/octocat/hello-world/issues');
  });

  it('throws on missing required path param', () => {
    const recipe: Recipe = {
      name: 'test.missing',
      description: 'Test',
      service: 'test',
      verb: 'GET',
      endpoint: '/users/{owner}/repos',
      target_url: 'https://api.example.com/users/{owner}/repos',
      risk_tier: 'read',
      threshold: 1,
      path_params: [
        { name: 'owner', description: 'Owner', required: true, type: 'string' },
      ],
    };

    expect(() => resolveRecipe(recipe, {})).toThrow('missing required path parameter "owner"');
  });

  it('uses default for missing optional path param', () => {
    const recipe: Recipe = {
      name: 'test.default',
      description: 'Test',
      service: 'test',
      verb: 'GET',
      endpoint: '/users/{owner}/repos',
      target_url: 'https://api.example.com/users/{owner}/repos',
      risk_tier: 'read',
      threshold: 1,
      path_params: [
        { name: 'owner', description: 'Owner', required: true, default: 'defaultuser', type: 'string' },
      ],
    };

    const result = resolveRecipe(recipe, {});
    expect(result.endpoint).toBe('/users/defaultuser/repos');
  });

  it('appends query params to target_url', () => {
    const recipe: Recipe = {
      name: 'test.query',
      description: 'Test',
      service: 'test',
      verb: 'GET',
      endpoint: '/items',
      target_url: 'https://api.example.com/items',
      risk_tier: 'read',
      threshold: 1,
      query_params: [
        { name: 'per_page', description: 'Per page', required: false, default: '30', type: 'integer' },
        { name: 'page', description: 'Page number', required: false, type: 'integer' },
      ],
    };

    const result = resolveRecipe(recipe, { per_page: '10', page: '2' });
    expect(result.target_url).toContain('?');
    expect(result.target_url).toContain('per_page=10');
    expect(result.target_url).toContain('page=2');
  });

  it('uses default value for query params not provided', () => {
    const recipe: Recipe = {
      name: 'test.querydefault',
      description: 'Test',
      service: 'test',
      verb: 'GET',
      endpoint: '/items',
      target_url: 'https://api.example.com/items',
      risk_tier: 'read',
      threshold: 1,
      query_params: [
        { name: 'per_page', description: 'Per page', required: false, default: '30', type: 'integer' },
      ],
    };

    const result = resolveRecipe(recipe, {});
    expect(result.target_url).toContain('per_page=30');
  });

  it('throws on missing required query param', () => {
    const recipe: Recipe = {
      name: 'test.reqquery',
      description: 'Test',
      service: 'test',
      verb: 'GET',
      endpoint: '/items',
      target_url: 'https://api.example.com/items',
      risk_tier: 'read',
      threshold: 1,
      query_params: [
        { name: 'api_key', description: 'API key', required: true, type: 'string' },
      ],
    };

    expect(() => resolveRecipe(recipe, {})).toThrow('missing required query parameter "api_key"');
  });

  it('builds body from body_schema with properties for POST', () => {
    const recipe: Recipe = {
      name: 'test.post',
      description: 'Test',
      service: 'test',
      verb: 'POST',
      endpoint: '/repos/{owner}/{repo}/issues',
      target_url: 'https://api.example.com/repos/{owner}/{repo}/issues',
      risk_tier: 'write',
      threshold: 2,
      path_params: [
        { name: 'owner', description: 'Owner', required: true, type: 'string' },
        { name: 'repo', description: 'Repo', required: true, type: 'string' },
      ],
      body_schema: {
        type: 'object',
        properties: {
          title: { type: 'string' },
          body: { type: 'string' },
        },
        required: ['title'],
      },
    };

    const result = resolveRecipe(recipe, {
      owner: 'octocat',
      repo: 'hello-world',
      title: 'Bug report',
      body: 'Something is broken',
    });

    expect(result.endpoint).toBe('/repos/octocat/hello-world/issues');
    expect(result.body).toBeDefined();
    const parsed = JSON.parse(new TextDecoder().decode(result.body));
    expect(parsed.title).toBe('Bug report');
    expect(parsed.body).toBe('Something is broken');
  });

  it('throws on missing required body param', () => {
    const recipe: Recipe = {
      name: 'test.reqbody',
      description: 'Test',
      service: 'test',
      verb: 'POST',
      endpoint: '/items',
      target_url: 'https://api.example.com/items',
      risk_tier: 'write',
      threshold: 1,
      body_schema: {
        type: 'object',
        properties: {
          title: { type: 'string' },
        },
        required: ['title'],
      },
    };

    expect(() => resolveRecipe(recipe, {})).toThrow('missing required body parameter "title"');
  });

  it('handles empty args object', () => {
    const recipe: Recipe = {
      name: 'test.noargs',
      description: 'Test',
      service: 'test',
      verb: 'GET',
      endpoint: '/health',
      target_url: 'https://api.example.com/health',
      risk_tier: 'read',
      threshold: 1,
    };

    const result = resolveRecipe(recipe, {});
    expect(result.endpoint).toBe('/health');
    expect(result.target_url).toBe('https://api.example.com/health');
    expect(result.body).toBeUndefined();
  });

  it('handles undefined args', () => {
    const recipe: Recipe = {
      name: 'test.noargs',
      description: 'Test',
      service: 'test',
      verb: 'GET',
      endpoint: '/health',
      target_url: 'https://api.example.com/health',
      risk_tier: 'read',
      threshold: 1,
    };

    const result = resolveRecipe(recipe);
    expect(result.endpoint).toBe('/health');
  });

  it('leaves unresolved placeholders when no matching arg', () => {
    const recipe: Recipe = {
      name: 'test.unresolved',
      description: 'Test',
      service: 'test',
      verb: 'GET',
      endpoint: '/users/{owner}/{extra}',
      target_url: 'https://api.example.com/users/{owner}/{extra}',
      risk_tier: 'read',
      threshold: 1,
      path_params: [
        { name: 'owner', description: 'Owner', required: true, type: 'string' },
      ],
    };

    // {extra} is not in path_params, so it's not required - just won't be substituted
    const result = resolveRecipe(recipe, { owner: 'octocat' });
    expect(result.endpoint).toBe('/users/octocat/{extra}');
  });

  it('appends query params with & when URL already has ?', () => {
    const recipe: Recipe = {
      name: 'test.existing-query',
      description: 'Test',
      service: 'test',
      verb: 'GET',
      endpoint: '/items',
      target_url: 'https://api.example.com/items?format=json',
      risk_tier: 'read',
      threshold: 1,
      query_params: [
        { name: 'page', description: 'Page', required: false, type: 'integer' },
      ],
    };

    const result = resolveRecipe(recipe, { page: '2' });
    expect(result.target_url).toBe('https://api.example.com/items?format=json&page=2');
  });
});

// === 4. Payload Types ===
describe('Payload Types', () => {
  it('PromotePayload structure is conversation-scoped', () => {
    const payload: PromotePayload = {
      type: 'gate.promote',
      conv_id: 'test-conv',
      gateway_kid: 'gw-kid1',
      rules: [
        { service: '*', endpoint: '', verb: '', m: 1 },
      ],
    };
    expect(payload.type).toBe('gate.promote');
    expect(payload.conv_id).toBe('test-conv');
    expect(payload.gateway_kid).toBe('gw-kid1');
    expect(payload.rules).toHaveLength(1);
  });

  it('ConfigPayload structure matches Go', () => {
    const payload: ConfigPayload = {
      type: 'gate.config',
      rules: [
        { service: 'github', endpoint: '', verb: '', m: 2 },
      ],
    };
    expect(payload.type).toBe('gate.config');
    expect(payload.rules).toHaveLength(1);
  });

  it('SecretPayload structure matches Go', () => {
    const payload: SecretPayload = {
      type: 'gate.secret',
      secret_id: 'sec-123',
      service: 'github',
      header_name: 'Authorization',
      header_template: 'Bearer {value}',
      encrypted_blob: new Uint8Array([1, 2, 3]),
      sender_kid: 'kid1',
    };
    expect(payload.type).toBe('gate.secret');
    expect(payload.secret_id).toBe('sec-123');
    expect(payload.service).toBe('github');
    expect(payload.header_template).toBe('Bearer {value}');
  });

  it('PromotePayload JSON serialization', () => {
    const payload: PromotePayload = {
      type: 'gate.promote',
      conv_id: 'conv-1',
      gateway_kid: 'gw-kid1',
      rules: [
        { service: '*', endpoint: '', verb: '', m: 1 },
      ],
    };
    const json = JSON.stringify(payload);
    const parsed = JSON.parse(json);
    expect(parsed.type).toBe('gate.promote');
    expect(parsed.conv_id).toBe('conv-1');
    expect(parsed.gateway_kid).toBe('gw-kid1');
  });

  it('ConfigPayload JSON serialization', () => {
    const payload: ConfigPayload = {
      type: 'gate.config',
      rules: [
        { service: 'deploy', endpoint: '/prod', verb: 'POST', m: 3 },
      ],
    };
    const json = JSON.stringify(payload);
    const parsed = JSON.parse(json);
    expect(parsed.type).toBe('gate.config');
    expect(parsed.rules[0].m).toBe(3);
  });
});

// === 5. GateConversationMessage with recipe fields ===
describe('GateConversationMessage recipe fields', () => {
  it('supports recipe_name and arguments', () => {
    const msg: GateConversationMessage = {
      type: 'gate.request',
      conv_id: 'test-conv',
      request_id: 'req-1',
      verb: 'GET',
      target_endpoint: '/users/octocat/repos',
      target_service: 'github',
      target_url: 'https://api.github.com/users/octocat/repos',
      signer_kid: 'kid1',
      signature: 'sig123',
      recipe_name: 'github.list-repos',
      arguments: { owner: 'octocat' },
    };
    expect(msg.recipe_name).toBe('github.list-repos');
    expect(msg.arguments).toEqual({ owner: 'octocat' });
  });

  it('recipe_name and arguments are optional', () => {
    const msg: GateConversationMessage = {
      type: 'gate.request',
      conv_id: 'test-conv',
      request_id: 'req-1',
      signer_kid: 'kid1',
      signature: 'sig123',
    };
    expect(msg.recipe_name).toBeUndefined();
    expect(msg.arguments).toBeUndefined();
  });
});
