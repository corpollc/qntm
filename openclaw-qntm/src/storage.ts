import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';

export function readBoundedFile(filename: string, limit: number): Buffer {
  const fd = fs.openSync(filename, 'r');
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || stat.size > limit) throw new Error('qntm local file exceeds its size limit or is not a regular file');
    const bytes = Buffer.alloc(Math.min(stat.size + 1, limit + 1));
    let length = 0;
    while (length < bytes.length) {
      const count = fs.readSync(fd, bytes, length, bytes.length - length, length);
      if (!count) break;
      length += count;
    }
    if (length > stat.size || length > limit) throw new Error('qntm local file changed while reading');
    return bytes.subarray(0, length);
  } finally { fs.closeSync(fd); }
}

/** Readers see the old complete file or the new complete file. One writer owns a profile. */
export function writePrivateJSON(filename: string, value: unknown, limit: number): void {
  const data = JSON.stringify(value) + '\n';
  if (Buffer.byteLength(data) > limit) throw new Error('qntm checkpoint exceeds its size limit');
  fs.mkdirSync(path.dirname(filename), { recursive: true, mode: 0o700 });
  fs.chmodSync(path.dirname(filename), 0o700);
  const temporary = `${filename}.${randomUUID()}.tmp`;
  let fd: number | undefined;
  try {
    fd = fs.openSync(temporary, 'wx', 0o600);
    fs.writeFileSync(fd, data);
    fs.fsyncSync(fd);
    fs.closeSync(fd); fd = undefined;
    fs.renameSync(temporary, filename);
    const directory = fs.openSync(path.dirname(filename), 'r');
    try { fs.fsyncSync(directory); } finally { fs.closeSync(directory); }
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
    try { fs.unlinkSync(temporary); } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    }
  }
}
