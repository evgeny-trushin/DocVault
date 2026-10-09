#!/bin/sh
# Create a verified solid archive with the default encrypted key file.
set -eu
here=$(cd -P "$(dirname "$0")" && pwd)
exec "$here/docvault" encrypt "$@"
