#!/bin/bash

#disables apport from handling core dumps

set -euo pipefail

echo "/core_dumps/core.%e.%p" > /proc/sys/kernel/core_pattern
mkdir -p /core_dumps
chmod 777 /core_dumps
ulimit -c unlimited


exec "$@"
