#!/bin/sh
set -eu

capture_dir=/data/simadmin/beta9-sip-capture
sniffer=/opt/simadmin/beta9-sip-sniffer
mkdir -p "$capture_dir"

echo "$(date -Is) capture service started" >> "$capture_dir/service.log"
while :; do
    if [ -x "$sniffer" ] && ip link show wwan1 2>/dev/null | grep -q '<.*UP'; then
        stamp=$(date +%Y%m%d-%H%M%S)
        timeout 900 "$sniffer" >> "$capture_dir/sip-$stamp.log" 2>> "$capture_dir/service.log" || true
        echo "$(date -Is) capture window ended" >> "$capture_dir/service.log"
        sleep 5
    else
        echo "$(date -Is) waiting for wwan1/sniffer" >> "$capture_dir/service.log"
        sleep 5
    fi
done
