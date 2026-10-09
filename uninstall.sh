#!/bin/sh
# Remove only this checkout's command launchers; retain keys, runtime and archives.
set -eu
here=$(cd -P "$(dirname "$0")" && pwd)
# Run a probe: a venv whose base Python was removed is executable but cannot start.
usable() {
    [ -x "$1" ] && "$1" -I -c 'import sys; sys.exit(sys.version_info < (3, 12))'
} 2>/dev/null
if usable "$here/.venv/bin/python"; then
    python=$here/.venv/bin/python
else
    python=$(command -v python3) && usable "$python" || {
        printf '%s\n' 'uninstall.sh: Python 3.12 or later is required' >&2
        exit 1
    }
fi
exec "$python" -I "$here/scripts/install_commands.py" uninstall "$@"
