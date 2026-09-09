"""Test-only PTY bridge: JSON on stdin, base64 terminal frames on stdout."""
import base64
import fcntl
import json
import os
import pty
import select
import signal
import struct
import sys
import termios

pid, fd = pty.fork()
if pid == 0:
    os.environ.update(TERM="xterm-256color", FORCE_COLOR="0", CI="false")
    os.execv(sys.argv[1], sys.argv[1:])
fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 48, 120, 0, 0))
print(json.dumps({"pid": pid}), flush=True)
pending = b""
input_fd = sys.stdin.fileno()
try:
    while True:
        readable, _, _ = select.select([fd, input_fd], [], [], 1)
        if fd in readable:
            try:
                data = os.read(fd, 65536)
            except OSError:
                break
            if not data:
                break
            print(json.dumps({"output": base64.b64encode(data).decode()}), flush=True)
        if input_fd in readable:
            data = os.read(input_fd, 65536)
            if not data:
                break
            # TextIO.readline can prefetch a second JSON line and strand it
            # while select waits for new kernel bytes. Frame raw reads instead.
            pending += data
            while b"\n" in pending:
                line, pending = pending.split(b"\n", 1)
                command = json.loads(line)
                if "write" in command:
                    payload = command["write"].encode()
                    while payload:
                        payload = payload[os.write(fd, payload):]
                if "resize" in command:
                    rows, columns = command["resize"]
                    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, columns, 0, 0))
finally:
    os.close(fd)
    try:
        os.kill(pid, signal.SIGCONT)
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    os.waitpid(pid, 0)
