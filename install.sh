#!/bin/sh
# Portable bootstrap for Debian / Ubuntu / Alpine. Run: sudo sh install.sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "请用 root / sudo 运行。" >&2
    exit 1
fi
if [ ! -r /etc/os-release ]; then
    echo "无法识别操作系统。" >&2
    exit 1
fi
. /etc/os-release
case "$ID" in
    alpine)
        if ! command -v bash >/dev/null 2>&1; then
            apk add --no-cache bash
        fi
        ;;
    debian|ubuntu)
        if ! command -v bash >/dev/null 2>&1; then
            export DEBIAN_FRONTEND=noninteractive
            apt-get update
            apt-get install -y --no-install-recommends bash
        fi
        ;;
    *)
        echo "只支持 Debian / Ubuntu / Alpine，当前系统：$ID" >&2
        exit 1
        ;;
esac

DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SCRIPT="$DIR/ipt-inbound-guard.sh"
if [ ! -r "$SCRIPT" ]; then
    echo "缺少脚本：$SCRIPT（请使用完整仓库）" >&2
    exit 1
fi
exec bash "$SCRIPT" install
