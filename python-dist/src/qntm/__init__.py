"""qntm - secure messaging protocol CLI."""

__version__ = "0.0.0"


import os
import platform
import subprocess
import sys


def _get_binary_name():
    """Return the platform-specific binary name."""
    system = platform.system().lower()
    machine = platform.machine().lower()

    # Normalize arch
    arch_map = {
        "x86_64": "amd64",
        "amd64": "amd64",
        "aarch64": "arm64",
        "arm64": "arm64",
    }
    arch = arch_map.get(machine)
    if not arch:
        return None

    # Normalize OS
    os_map = {
        "linux": "linux",
        "darwin": "darwin",
        "windows": "windows",
    }
    osname = os_map.get(system)
    if not osname:
        return None

    name = f"qntm-{osname}-{arch}"
    if osname == "windows":
        name += ".exe"
    return name


def _find_binary():
    """Find the Go binary bundled in this package."""
    bin_dir = os.path.join(os.path.dirname(__file__), "bin")
    name = _get_binary_name()
    if not name:
        return None
    path = os.path.join(bin_dir, name)
    if os.path.isfile(path):
        return path
    return None


def main():
    """Entry point: exec the bundled Go binary."""
    binary = _find_binary()
    if not binary:
        plat = f"{platform.system()}/{platform.machine()}"
        print(
            f"qntm: no pre-built binary for {plat}.\n"
            f"Build from source: https://github.com/corpollc/qntm",
            file=sys.stderr,
        )
        sys.exit(1)

    os.execv(binary, [binary] + sys.argv[1:])
