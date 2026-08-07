# container_all_in_one — 容器运行时逃逸靶场

将 **runc** 与 **containerd** 的源码平铺进单一 git 仓库，作为容器运行时安全
的靶场。


---

## 仓库结构

```
container_all_in_one/
├── runc/          # runc 源码（自带 go.mod / vendor）
├── containerd/    # containerd 源码（自带 go.mod / vendor）
└── README.md      # 本文件
```


---

## 一、已回退的漏洞（10 个 CVE）

通过撤销上游修复 commit 的方式，让真实漏洞"回来"。每个漏洞均标注
**是否通过 PoC 复现**。

| CVE | 组件 | 漏洞机制 | 验证方式 | 结果 |
|---|---|---|---|---|
| CVE-2019-5736 | runc | 覆盖宿主 runc 二进制 | 完整 PoC | ✅ 已复现 |
| CVE-2019-19921 | runc | /proc /sys 符号链接挂载逃逸 | 差分 | ✅ 已复现 |
| CVE-2023-27561 | runc | 同上（19921 的回归） | 差分（同代码路径） | ✅ 已复现 |
| CVE-2021-30465 | runc | mount 目标 TOCTOU 逃逸 | 差分（hook 抓 pre-pivot 挂载表） | ✅ 已复现 |
| CVE-2021-43784 | runc | netlink 消息长度溢出（uint16 截断） | 差分 | ✅ 已复现 |
| CVE-2024-21626 | runc | fd/工作目录逃逸（Leaky Vessels） | 机制验证（4 层修复全 revert） | ✅ 修复已确认移除 |
| CVE-2020-15257 | containerd | shim abstract socket 逃逸 | 差分（真实 pkg/shim） | ✅ 已复现 |
| CVE-2023-25809 | runc | rootless cgroup2 mount 缺少只读 | 静态 | ⚠️ 需 rootless 环境 |
| CVE-2024-45310 | runc | MkdirAll TOCTOU | 静态 | ⚠️ 需共享卷竞争 |
| CVE-2021-43816 | containerd | SELinux relabel 移除 | 静态 | ⚠️ 需 SELinux 内核 |

### 动态复现的 7 个（有运行证据）

**CVE-2019-5736 — runc 宿主二进制覆写** ✅
回退 `ensure_cloned_binary()`（memfd seal）后，runc 以 `/proc/self/exe` 直接
re-exec init。PoC 用 `#!/proc/self/exe` shebang 触发 usage-error re-exec，扫描
`/proc/<pid>/exe` 拿到宿主 runc fd，ETXTBSY 窗口关闭后覆写二进制，产出
`/tmp/5736-pwned.txt`。前置：`runc-ctf` 是宿主 `/tmp/runc-ctf` 的 bind mount。

**CVE-2019-19921 — /proc /sys 符号链接挂载逃逸** ✅
回退 `mountToRootfs` 的 `os.Lstat` 非目录检查。rootfs 内 `/sys -> /host-escape` 时：
修复版拒绝（`must be mounted on ordinary directory`），回退版裸 `mount(2)` 跟随
符号链接把 sysfs 挂到宿主目录。

**CVE-2023-27561 — 19921 的回归** ✅
与 19921 同一代码路径（`mountToRootfs` 的 `case "proc","sysfs"`），19921 的差分
demo 同时覆盖，端到端代码一致。

**CVE-2021-30465 — mount 目标 TOCTOU** ✅
回退 `WithProcfd`（SecureJoin 把绝对符号链接 re-root 回 rootfs 内）为裸 `mount(2)`。
构造 `destination=/tmp/escape`（绝对符号链接指向 rootfs 外），用 `CreateContainer`
hook 抓 pivot_root 前的挂载表：回退版挂载落到宿主 `/host-escape`，修复版被限定在
rootfs 内 `/tmp/rootfs-30465/host-escape`。

**CVE-2021-43784 — netlink 长度溢出** ✅
回退 `Bytemsg.Serialize` 的 `l > math.MaxUint16` panic 防护。声明 `user` namespace
+ 6000 条 uidMappings（70895 B > UINT16_MAX）：修复版报 `netlink: cannot serialize
bytemsg of length 70895`，回退版静默截断产生 `unknown netlink message type 14137`。

**CVE-2024-21626 — 容器逃逸（Leaky Vessels）** ✅ 机制确认
4 层修复全部回退：`CloseExecFrom(3)`、`verifyCwd()`、`UnsafeCloseFrom`、cgroupFd 的
`O_CLOEXEC`。standalone runc 场景无法触发完整逃逸（需 containerd 传递 cgroup fd），
故为机制级确认而非端到端 PoC。

**CVE-2020-15257 — shim abstract socket** ✅
回退 `CreateSocketAddress` 到无 `unix://` 前缀（→ abstract socket）。用真实
`pkg/shim` 的 `NewSocket`/`AnonDialer` 构建 demo：`--net=host` 容器可达
`@/containerd-shim/demo.sock`；修复版文件系统 socket（0600）受 mount ns 隔离不可达。

### 静态确认的 3 个（环境前置缺失）

**CVE-2023-25809** — rootless cgroup2 mount 恢复裸 bind fallback 且不保证 MS_RDONLY，
需 rootless + cgroup 委派环境。
**CVE-2024-45310** — `createMountpoint` 恢复裸 `os.MkdirAll`（未用 `MkdirAllInRoot`），
需双容器共享卷的 TOCTOU 竞速。
**CVE-2021-43816** — 移除 `WithRelabeledContainerMounts`，需 SELinux 内核。

---

## 二、新增的漏洞（5 个）

| 方案 | 提交 | 组件 · 文件 | 植入方式 | 漏洞效果 |
|---|---|---|---|---|
| **A1** 能力降级 | `5c43ebc` | runc · `libcontainer/init_linux.go` | 短路 `ApplyBoundingSet`/`ApplyCaps` | 容器 root 保留宿主全 bounding/effective caps（CAP_SYS_ADMIN/CAP_SYS_RAWIO 等） |
| **A4** 掩蔽/只读路径失效 | `b2349b7` | runc · `libcontainer/standard_init_linux.go` | 短路 `MaskPaths`/`ReadonlyPaths` 循环 | `/proc/kcore`（宿主物理内存）、`/proc/sched_debug`（内核栈）不再被掩蔽，`/proc/sys` 不再 remount 只读 |
| **A6** sysctl 白名单失效 | `429b965` | runc · `configs/validate/validator.go` | 校验列表移除 `v.sysctl` | 可写任意 `/proc/sys`，如 `kernel.core_pattern`（宿主核心转储劫持） |
| **A8** 设备过滤失效 | `2131584` | runc · `cgroups/fs2/devices.go` | 短路 `setDevices` eBPF 附加 | 可 open `/dev/sda`、`/dev/mem`、`/dev/nvme*` 等白名单外设备，直读宿主磁盘 |
| **B2** privileged 判定失效 | `c114437` | containerd · `internal/cri/server/container_create.go` | 短路 `securityContext.GetPrivileged()` 判定 | 普通容器也走 `WithPrivileged`：全 caps + 全设备 + 无 seccomp（误给全能力） |

### 各漏洞详情

**A1 能力降级**（runc）
`finalizeNamespace` 中 `ApplyBoundingSet` 与 `ApplyCaps` 短路，bounding set 不再收敛到
spec 指定集合，effective/permitted 不被收窄。进程保留继承自宿主的全部能力，
`mount`/`nonewprivs` 全可用。

**A4 掩蔽/只读路径失效**（runc）
`finalizeRootfs` 的 `MaskPaths`（掩蔽为 `/dev/null`）与 `ReadonlyPaths`（remount ro）
循环整体短路。敏感内核文件暴露，`/proc/sys` 可写。

**A6 sysctl 白名单失效**（runc）
`Validate()` 的 checks 列表移除 `v.sysctl`，不再校验键名白名单
（`kernel.msg*`/`kernel.shm*`/`fs.mqueue.*` / 独立 UTS/netns 限制）。`config.json`
可写任意 `/proc/sys`。

**A8 cgroup 设备过滤失效**（runc，cgroup v2）
`setDevices` 的 eBPF 设备过滤程序生成与附加整体短路。cgroup 不再限制设备访问，
白名单外的块设备/字符设备全部可达。

**B2 privileged 判定失效**（containerd CRI）
`buildLinuxSpec` 中 `if securityContext.GetPrivileged()` 判定短路恒真，普通容器无条件
追加 `oci.WithPrivileged`（+ `WithHostDevices`/`WithAllDevicesAllowed`）。
这是最接近真实误判的植入（k8s 历史上多次出现类似判定缺陷）。

---

