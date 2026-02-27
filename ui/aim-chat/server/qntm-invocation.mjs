import fs from 'fs'
import os from 'os'
import path from 'path'
import { execFile } from 'child_process'
import { promisify } from 'util'

const execFileAsync = promisify(execFile)

function getPathModule(platform) {
  return platform === 'win32' ? path.win32 : path.posix
}

function defaultFileExists(targetPath) {
  try {
    fs.accessSync(targetPath, fs.constants.F_OK)
    return true
  } catch {
    return false
  }
}

export function expandHome(inputPath, options = {}) {
  const platform = options.platform || process.platform
  const homeDir = options.homeDir || os.homedir()

  if (!inputPath) {
    return inputPath
  }

  if (inputPath.startsWith('~/')) {
    return getPathModule(platform).join(homeDir, inputPath.slice(2))
  }

  if (platform === 'win32' && inputPath.startsWith('~\\')) {
    return getPathModule(platform).join(homeDir, inputPath.slice(2))
  }

  return inputPath
}

export function findExecutableInPath(command, envPath, options = {}) {
  const platform = options.platform || process.platform
  const pathModule = getPathModule(platform)
  const fileExists = options.fileExists || defaultFileExists

  if (!command) {
    return ''
  }

  if (command.includes('/') || command.includes('\\')) {
    return fileExists(command) ? command : ''
  }

  const separator = platform === 'win32' ? ';' : ':'
  const extensions = platform === 'win32' ? ['', '.exe', '.cmd', '.bat'] : ['']
  const segments = String(envPath || '')
    .split(separator)
    .filter((entry) => entry)

  for (const segment of segments) {
    for (const extension of extensions) {
      const candidate = pathModule.join(segment, `${command}${extension}`)
      if (fileExists(candidate)) {
        return candidate
      }
    }
  }

  return ''
}

async function buildQntmBinary(options) {
  const outputPath = options.outputPath
  const repoRoot = options.repoRoot

  await fs.promises.mkdir(path.dirname(outputPath), { recursive: true })
  await execFileAsync('go', ['build', '-o', outputPath, './cmd/qntm'], {
    cwd: repoRoot,
    maxBuffer: 8 * 1024 * 1024,
  })
}

export function createQntmInvocationResolver(options) {
  const repoRoot = options.repoRoot
  const dataRoot = options.dataRoot
  const env = options.env || process.env
  const platform = options.platform || process.platform
  const fileExists = options.fileExists || defaultFileExists
  const runBuild = options.runBuild || buildQntmBinary
  const pathModule = getPathModule(platform)
  const binaryName = platform === 'win32' ? 'qntm.exe' : 'qntm'
  const repoBinary = pathModule.join(repoRoot, binaryName)
  const cachedBinary = pathModule.join(dataRoot, 'bin', binaryName)
  let buildAttempted = false

  return async function resolveQntmInvocation(profile = {}) {
    const explicit = expandHome(profile.qntmBin || env.QNTM_BIN || '', { platform })
    if (explicit) {
      return { command: explicit, prefixArgs: [] }
    }

    if (fileExists(repoBinary)) {
      return { command: repoBinary, prefixArgs: [] }
    }

    if (fileExists(cachedBinary)) {
      return { command: cachedBinary, prefixArgs: [] }
    }

    const systemBinary = findExecutableInPath('qntm', env.PATH || '', {
      platform,
      fileExists,
    })
    if (systemBinary) {
      return { command: systemBinary, prefixArgs: [] }
    }

    if (!buildAttempted) {
      buildAttempted = true

      try {
        await runBuild({
          repoRoot,
          outputPath: cachedBinary,
        })
      } catch {
        // Ignore build failures and fall back to `go run`.
      }
    }

    if (fileExists(cachedBinary)) {
      return { command: cachedBinary, prefixArgs: [] }
    }

    return { command: 'go', prefixArgs: ['run', './cmd/qntm'] }
  }
}
