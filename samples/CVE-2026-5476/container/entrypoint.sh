#!/bin/bash
mkdir -p /dev/mqueue
mount -t mqueue none /dev/mqueue 2>/dev/null || true

mount -o remount,rw /proc/sys || echo "WARNING: /proc/sys remount failed"
echo 64 > /proc/sys/fs/mqueue/msg_max

(cd /opt/cfs/draco && exec ./core-cpu1 2>&1 | sed -u 's/^/[draco] /' | tee /tmp/cfs-draco.log) &
(cd /opt/cfs/v7   && exec ./core-cpu1 2>&1 | sed -u 's/^/[v7] /'   | tee /tmp/cfs-v7.log) &
exec python3 /opt/cfs/leakd.py
