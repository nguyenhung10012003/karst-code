/**
 * Saving a new key, in a session and from a shell. A key in a variable takes precedence over a
 * saved one, so saving while one is set must say so rather than appear to work.
 */
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterAll, afterEach, beforeAll, beforeEach, describe, it } from 'bun:test';
import { providerCommand } from '../src/commands/provider.ts';
import type { CommandIO } from '../src/commands/slash.ts';
import { createRuntime } from '../src/core/runtime.ts';
import type { Runtime } from '../src/core/runtime.ts';
import { createProvider } from '../src/providers/index.ts';
import { keyOverride } from '../src/providers/manage.ts';
import type { Prompter } from '../src/tools/types.ts';

const CLI = resolve(import.meta.dirname, '../src/cli.ts');
const KEY_VARS = ['ANTHROPIC_API_KEY', 'ANTHROPIC_AUTH_TOKEN', 'ANTHROPIC_BASE_URL', 'KARST_HOME'];

const sentKeys: (string | null)[] = [];
let server: ReturnType<typeof Bun.serve>;
let base: string;

beforeAll(() => {
  server = Bun.serve({
    port: 0,
    fetch(request) {
      // This SDK sends an API key as a bearer token; older ones used x-api-key.
      sentKeys.push(request.headers.get('x-api-key') ?? request.headers.get('authorization')?.replace(/^Bearer /, '') ?? null);
      return Response.json({ type: 'error', error: { type: 'authentication_error', message: 'invalid x-api-key' } }, { status: 401 });
    },
  });
  base = `http://127.0.0.1:${server.port}`;
});

afterAll(() => server.stop(true));

let saved: Record<string, string | undefined>;

beforeEach(() => {
  saved = Object.fromEntries(KEY_VARS.map((name) => [name, process.env[name]]));
  for (const name of KEY_VARS) delete process.env[name];
  process.env.KARST_HOME = realpathSync(mkdtempSync(join(tmpdir(), 'karst-keys-home-')));
  sentKeys.length = 0;
});

afterEach(() => {
  for (const [name, value] of Object.entries(saved)) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
});

describe('keyOverride', () => {
  it('says nothing when no variable holds a key', () => {
    assert.equal(keyOverride('anthropic', {}), undefined);
  });

  it('names the variable that wins, and where it was set', () => {
    process.env.ANTHROPIC_API_KEY = 'sk-env';
    assert.match(keyOverride('anthropic', {})!, /ANTHROPIC_API_KEY is set in your environment and takes precedence/);
    delete process.env.ANTHROPIC_API_KEY;

    assert.match(keyOverride('anthropic', {}, { ANTHROPIC_AUTH_TOKEN: 'tok' })!, /ANTHROPIC_AUTH_TOKEN is set in the "env" block of your settings/);
  });

  it('follows the variable a provider is configured to read', () => {
    const config = { type: 'openai-chat', baseUrl: 'https://api.example.com/v1', apiKeyEnv: 'EXAMPLE_KEY' };
    assert.equal(keyOverride('example', config), undefined);
    process.env.EXAMPLE_KEY = 'k';
    try {
      assert.match(keyOverride('example', config)!, /EXAMPLE_KEY is set/);
    } finally {
      delete process.env.EXAMPLE_KEY;
    }
  });
});

describe('/provider key', () => {
  const prompter: Prompter = { permission: async () => ({ behavior: 'allow' }), questions: async () => null, approvePlan: async () => true };
  const config = () => ({ baseUrl: base, maxRetries: 0 });

  async function session(): Promise<Runtime> {
    const dir = realpathSync(mkdtempSync(join(tmpdir(), 'karst-keys-')));
    const runtime = await createRuntime({ cwd: dir, prompter, provider: createProvider('anthropic', config()), trust: true, persist: false });
    runtime.configureProvider('anthropic', config());
    return runtime;
  }

  function typing(key: string): CommandIO {
    return { choose: async () => null, ask: async () => key };
  }

  async function sentKey(runtime: Runtime): Promise<string | null> {
    const stream = runtime.provider.stream({ model: 'claude-opus-5-5', system: [], messages: [{ role: 'user', content: [{ type: 'text', text: 'hi' }] }], tools: [], maxTokens: 10 });
    await assert.rejects(async () => {
      for await (const _event of stream) {
        // Drain until the scripted 401.
      }
    });
    return sentKeys.at(-1) ?? null;
  }

  it('sends the new key from the next request on', async () => {
    const runtime = await session();
    try {
      const result = await providerCommand('key anthropic', runtime, typing('sk-new'));
      assert.equal(result.output, 'Saved the key for anthropic.');
      assert.equal(await sentKey(runtime), 'sk-new');
    } finally {
      await runtime.shutdown();
    }
  });

  it('warns that a key in the environment still wins', async () => {
    process.env.ANTHROPIC_API_KEY = 'sk-old-from-env';
    const runtime = await session();
    try {
      const result = await providerCommand('key anthropic', runtime, typing('sk-new'));
      assert.match(result.output!, /^Saved the key for anthropic\.\nWarning: ANTHROPIC_API_KEY is set in your environment and takes precedence/);
      assert.equal(await sentKey(runtime), 'sk-old-from-env');
    } finally {
      await runtime.shutdown();
    }
  });
});

describe('karst provider key', () => {
  function saveKey(extraEnv: Record<string, string>) {
    const env: NodeJS.ProcessEnv = { ...process.env, ...extraEnv };
    return spawnSync(process.execPath, [CLI, 'provider', 'key', 'anthropic', '--stdin'], {
      cwd: realpathSync(mkdtempSync(join(tmpdir(), 'karst-keys-cli-'))),
      env,
      encoding: 'utf8',
      input: 'sk-new\n',
      timeout: 30_000,
    });
  }

  it('saves quietly when nothing overrides the key', () => {
    const result = saveKey({});
    assert.equal(result.status, 0);
    assert.match(result.stdout, /Saved the key for anthropic/);
    assert.equal(result.stderr, '');
  });

  it('warns when a variable will keep overriding it', () => {
    const result = saveKey({ ANTHROPIC_API_KEY: 'sk-old-from-env' });
    assert.equal(result.status, 0);
    assert.match(result.stderr, /Warning: ANTHROPIC_API_KEY is set in your environment and takes precedence/);
  });
});
