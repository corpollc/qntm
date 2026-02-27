import assert from 'node:assert/strict'
import test from 'node:test'
import {
  createQntmInvocationResolver,
  findExecutableInPath,
} from './qntm-invocation.mjs'

test('uses explicit profile qntm binary when provided', async () => {
  const resolver = createQntmInvocationResolver({
    repoRoot: '/repo',
    dataRoot: '/data',
    env: { PATH: '' },
    fileExists: () => false,
    runBuild: async () => {
      throw new Error('should not build')
    },
  })

  const invocation = await resolver({ qntmBin: '/custom/qntm' })
  assert.deepEqual(invocation, { command: '/custom/qntm', prefixArgs: [] })
})

test('uses QNTM_BIN when profile qntm binary is not set', async () => {
  const resolver = createQntmInvocationResolver({
    repoRoot: '/repo',
    dataRoot: '/data',
    env: { PATH: '', QNTM_BIN: '/env/qntm' },
    fileExists: () => false,
    runBuild: async () => {
      throw new Error('should not build')
    },
  })

  const invocation = await resolver({})
  assert.deepEqual(invocation, { command: '/env/qntm', prefixArgs: [] })
})

test('prefers repo binary over system path binary', async () => {
  const existing = new Set(['/repo/qntm', '/usr/local/bin/qntm'])
  const resolver = createQntmInvocationResolver({
    repoRoot: '/repo',
    dataRoot: '/data',
    env: { PATH: '/usr/local/bin:/usr/bin' },
    fileExists: (targetPath) => existing.has(targetPath),
    runBuild: async () => {
      throw new Error('should not build')
    },
  })

  const invocation = await resolver({})
  assert.deepEqual(invocation, { command: '/repo/qntm', prefixArgs: [] })
})

test('uses cached built binary before system path binary', async () => {
  const existing = new Set(['/data/bin/qntm', '/usr/local/bin/qntm'])
  const resolver = createQntmInvocationResolver({
    repoRoot: '/repo',
    dataRoot: '/data',
    env: { PATH: '/usr/local/bin:/usr/bin' },
    fileExists: (targetPath) => existing.has(targetPath),
    runBuild: async () => {
      throw new Error('should not build')
    },
  })

  const invocation = await resolver({})
  assert.deepEqual(invocation, { command: '/data/bin/qntm', prefixArgs: [] })
})

test('uses system qntm binary when available in PATH', async () => {
  const resolver = createQntmInvocationResolver({
    repoRoot: '/repo',
    dataRoot: '/data',
    env: { PATH: '/usr/local/bin:/usr/bin' },
    fileExists: (targetPath) => targetPath === '/usr/local/bin/qntm',
    runBuild: async () => {
      throw new Error('should not build')
    },
  })

  const invocation = await resolver({})
  assert.deepEqual(invocation, { command: '/usr/local/bin/qntm', prefixArgs: [] })
})

test('builds a cached binary once and reuses it', async () => {
  let buildCalls = 0
  let hasCachedBinary = false

  const resolver = createQntmInvocationResolver({
    repoRoot: '/repo',
    dataRoot: '/data',
    env: { PATH: '' },
    fileExists: (targetPath) => targetPath === '/data/bin/qntm' && hasCachedBinary,
    runBuild: async ({ outputPath }) => {
      buildCalls += 1
      assert.equal(outputPath, '/data/bin/qntm')
      hasCachedBinary = true
    },
  })

  const firstInvocation = await resolver({})
  const secondInvocation = await resolver({})

  assert.deepEqual(firstInvocation, { command: '/data/bin/qntm', prefixArgs: [] })
  assert.deepEqual(secondInvocation, { command: '/data/bin/qntm', prefixArgs: [] })
  assert.equal(buildCalls, 1)
})

test('falls back to go run when build fails', async () => {
  let buildCalls = 0

  const resolver = createQntmInvocationResolver({
    repoRoot: '/repo',
    dataRoot: '/data',
    env: { PATH: '' },
    fileExists: () => false,
    runBuild: async () => {
      buildCalls += 1
      throw new Error('go build failed')
    },
  })

  const firstInvocation = await resolver({})
  const secondInvocation = await resolver({})

  assert.deepEqual(firstInvocation, { command: 'go', prefixArgs: ['run', './cmd/qntm'] })
  assert.deepEqual(secondInvocation, { command: 'go', prefixArgs: ['run', './cmd/qntm'] })
  assert.equal(buildCalls, 1)
})

test('findExecutableInPath resolves windows executable extensions', () => {
  const existing = new Set(['C:\\tools\\qntm.exe'])
  const resolved = findExecutableInPath('qntm', 'C:\\tools;D:\\bin', {
    platform: 'win32',
    fileExists: (targetPath) => existing.has(targetPath),
  })

  assert.equal(resolved, 'C:\\tools\\qntm.exe')
})
