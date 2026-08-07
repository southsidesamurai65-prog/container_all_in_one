# runc 相关容器运行时 CVE 修复 diff 汇总

> 生成自本地 git 历史（`runc` + `containerd` 两个克隆），用于 CTF 学习漏洞机制与防御。
> 共 17 个 CVE。其中 **8 个的修复在 runc 仓库内、2 个在 containerd 仓库内**（均附完整
> git diff），这 10 个已在对应仓库的 `ctf-learn` 分支逐个回退（修改处标注 `--CTF-learn--`，
> 见第三部分）；**其余 7 个**的修复在 podman/rootlesskit、cri-o、buildah、crun、moby、
> cloud-lab（仅列版本/机制/修复 commit 链接，未回退）。

## 总览表

| CVE | 所属项目 | 修复版本 | 修复在 runc 仓库? | 核心修复 commit / PR |
|---|---|---|---|---|
| CVE-2018-15664 | Docker / Moby (`docker cp`) | Docker 18.09.2 | ❌ | moby/moby@`364f9bce` (PR #39292) |
| CVE-2019-5736 | **runc** | 1.0.0-rc6 | ✅ | `0a8e4117` `bb7d8b1f` (merge `6635b4f0`) |
| CVE-2019-19921 | **runc** | v1.0.0-rc10 | ✅ | `3291d66b` (PR #2207) |
| CVE-2020-15257 | containerd | 1.3.9 / 1.4.3 | ❌ | containerd@`4a4bb851` (GHSA-36xw-fx78-c5r4) |
| CVE-2021-20199 | Podman / rootlesskit | Podman 3.0.0 | ❌ | rootlesskit PR #206 |
| CVE-2021-30465 | **runc** | v1.0.0-rc95 | ✅ | `0ca91f44` |
| CVE-2021-43784 | **runc** | v1.0.3 | ✅ | `d72d057b` |
| CVE-2021-43816 | containerd | 1.5.9 | ❌ | containerd@`9b0303913` (GHSA-mvff-h3cj-wj9c) |
| CVE-2022-0811 | CRI-O | 1.19.6 ~ 1.23.2 | ❌ | cri-o sysctl 校验 |
| CVE-2022-42150 | TinyLab cloud-lab | 无正式版本 | ❌ | seccomp profile 补丁 |
| CVE-2023-25809 | **runc** | 1.1.5 | ✅ | `df4eae45` (merge `0d62b950`) |
| CVE-2023-27561 | **runc** | 1.1.5 | ✅ | `0abab45c` (PR #3785) |
| CVE-2024-1753 | Buildah / Podman build | 1.35.1 等 | ❌ | buildah@`9de9c20` |
| CVE-2024-5154 | CRI-O | 1.30.1 / 1.29.5 / 1.28.7 | ❌ | cri-o 目录遍历修复 |
| CVE-2024-21626 | **runc** | 1.1.12 | ✅ | 7 commits (merge `a9833ff`) |
| CVE-2024-45310 | **runc** | 1.1.14 / 1.2.0-rc.3 | ✅ | `63c29081` (PR #4359) |
| CVE-2025-24965 | crun | 1.20 | ❌ | crun@`0aec82c` |

> **回退状态（`ctf-learn` 分支）：**
> - ✅ runc 8 个 —— `container_all_in_one/runc` `ctf-learn` 分支，8 个 commit（5736 / 19921 / 30465 / 43784 / 25809 / 27561 / 21626 / 45310）
> - ✅ containerd 2 个 —— `container_all_in_one/containerd` `ctf-learn` 分支，2 个 commit（15257 / 43816）
> - ⬜ 其余 7 个（moby 2018-15664、podman/rootlesskit 2019、cri-o 0811/5154、buildah 1753、crun 24965、cloud-lab 42150）未回退

---

# 一、runc 仓库内修复的 CVE（附完整 git diff）

## CVE-2019-5736 — runc 容器逃逸（覆盖宿主 runc 二进制）

- **GHSA:** GHSA-gxmr-w5mj-v8hh
- **修复版本:** runc 1.0.0-rc6（Docker 18.09.2 首发）
- **机制:** 容器内以 root 运行的进程可以 `open()` 宿主上 runc 进程的 `/proc/self/exe`（指向宿主磁盘上的 runc 二进制）。在 `runc exec` 切换到容器进程的瞬间，攻击者向该 fd 写入，覆盖宿主 runc 二进制，从而在宿主获得 root 代码执行（容器逃逸）。攻击前提是能在容器内以 root 执行任意命令。
- **防御/修复:** 在 re-exec 前先把 runc 自身二进制复制到密封的 memfd（`memfd_create` + seal），再从 memfd `fexecve`，使容器内看到的 `/proc/self/exe` 是临时副本而非宿主磁盘二进制；`nsenter` 不再解析 environ 以杜绝环境变量注入。现代版本进一步用 `runc-dmz` 小 C 程序承载该逻辑。
- **修复 commit:** `0a8e4117`（nsenter: clone /proc/self/exe to avoid exposing host binary to container）、`bb7d8b1f`（nsexec: avoid parsing environ）、merge `6635b4f0`；相关后续 `0e9a3358`、`dac41717`、`e67725c0`。

```diff
commit 0a8e4117e7f715d5fbeef398405813ce8e88558b
Author: Aleksa Sarai <asarai@suse.de>
Date:   Wed Jan 9 13:40:01 2019 +1100

    nsenter: clone /proc/self/exe to avoid exposing host binary to container
    
    There are quite a few circumstances where /proc/self/exe pointing to a
    pretty important container binary is a _bad_ thing, so to avoid this we
    have to make a copy (preferably doing self-clean-up and not being
    writeable).
    
    We require memfd_create(2) -- though there is an O_TMPFILE fallback --
    but we can always extend this to use a scratch MNT_DETACH overlayfs or
    tmpfs. The main downside to this approach is no page-cache sharing for
    the runc binary (which overlayfs would give us) but this is far less
    complicated.
    
    This is only done during nsenter so that it happens transparently to the
    Go code, and any libcontainer users benefit from it. This also makes
    ExtraFiles and --preserve-fds handling trivial (because we don't need to
    worry about it).
    
    Fixes: CVE-2019-5736
    Co-developed-by: Christian Brauner <christian.brauner@ubuntu.com>
    Signed-off-by: Aleksa Sarai <asarai@suse.de>

diff --git a/libcontainer/nsenter/cloned_binary.c b/libcontainer/nsenter/cloned_binary.c
new file mode 100644
index 00000000..c8a42c23
--- /dev/null
+++ b/libcontainer/nsenter/cloned_binary.c
@@ -0,0 +1,268 @@
+/*
+ * Copyright (C) 2019 Aleksa Sarai <cyphar@cyphar.com>
+ * Copyright (C) 2019 SUSE LLC
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *     http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#define _GNU_SOURCE
+#include <unistd.h>
+#include <stdio.h>
+#include <stdlib.h>
+#include <stdbool.h>
+#include <string.h>
+#include <limits.h>
+#include <fcntl.h>
+#include <errno.h>
+
+#include <sys/types.h>
+#include <sys/stat.h>
+#include <sys/vfs.h>
+#include <sys/mman.h>
+#include <sys/sendfile.h>
+#include <sys/syscall.h>
+
+/* Use our own wrapper for memfd_create. */
+#if !defined(SYS_memfd_create) && defined(__NR_memfd_create)
+#  define SYS_memfd_create __NR_memfd_create
+#endif
+#ifdef SYS_memfd_create
+#  define HAVE_MEMFD_CREATE
+/* memfd_create(2) flags -- copied from <linux/memfd.h>. */
+#  ifndef MFD_CLOEXEC
+#    define MFD_CLOEXEC       0x0001U
+#    define MFD_ALLOW_SEALING 0x0002U
+#  endif
+int memfd_create(const char *name, unsigned int flags)
+{
+	return syscall(SYS_memfd_create, name, flags);
+}
+#endif
+
+/* This comes directly from <linux/fcntl.h>. */
+#ifndef F_LINUX_SPECIFIC_BASE
+#  define F_LINUX_SPECIFIC_BASE 1024
+#endif
+#ifndef F_ADD_SEALS
+#  define F_ADD_SEALS (F_LINUX_SPECIFIC_BASE + 9)
+#  define F_GET_SEALS (F_LINUX_SPECIFIC_BASE + 10)
+#endif
+#ifndef F_SEAL_SEAL
+#  define F_SEAL_SEAL   0x0001	/* prevent further seals from being set */
+#  define F_SEAL_SHRINK 0x0002	/* prevent file from shrinking */
+#  define F_SEAL_GROW   0x0004	/* prevent file from growing */
+#  define F_SEAL_WRITE  0x0008	/* prevent writes */
+#endif
+
+#define RUNC_SENDFILE_MAX 0x7FFFF000 /* sendfile(2) is limited to 2GB. */
+#ifdef HAVE_MEMFD_CREATE
+#  define RUNC_MEMFD_COMMENT "runc_cloned:/proc/self/exe"
+#  define RUNC_MEMFD_SEALS \
+	(F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE)
+#endif
+
+static void *must_realloc(void *ptr, size_t size)
+{
+	void *old = ptr;
+	do {
+		ptr = realloc(old, size);
+	} while(!ptr);
+	return ptr;
+}
+
+/*
+ * Verify whether we are currently in a self-cloned program (namely, is
+ * /proc/self/exe a memfd). F_GET_SEALS will only succeed for memfds (or rather
+ * for shmem files), and we want to be sure it's actually sealed.
+ */
+static int is_self_cloned(void)
+{
+	int fd, ret, is_cloned = 0;
+
+	fd = open("/proc/self/exe", O_RDONLY|O_CLOEXEC);
+	if (fd < 0)
+		return -ENOTRECOVERABLE;
+
+#ifdef HAVE_MEMFD_CREATE
+	ret = fcntl(fd, F_GET_SEALS);
+	is_cloned = (ret == RUNC_MEMFD_SEALS);
+#else
+	struct stat statbuf = {0};
+	ret = fstat(fd, &statbuf);
+	if (ret >= 0)
+		is_cloned = (statbuf.st_nlink == 0);
+#endif
+	close(fd);
+	return is_cloned;
+}
+
+/*
+ * Basic wrapper around mmap(2) that gives you the file length so you can
+ * safely treat it as an ordinary buffer. Only gives you read access.
+ */
+static char *read_file(char *path, size_t *length)
+{
+	int fd;
+	char buf[4096], *copy = NULL;
+
+	if (!length)
+		return NULL;
+
+	fd = open(path, O_RDONLY | O_CLOEXEC);
+	if (fd < 0)
+		return NULL;
+
+	*length = 0;
+	for (;;) {
+		int n;
+
+		n = read(fd, buf, sizeof(buf));
+		if (n < 0)
+			goto error;
+		if (!n)
+			break;
+
+		copy = must_realloc(copy, (*length + n) * sizeof(*copy));
+		memcpy(copy + *length, buf, n);
+		*length += n;
+	}
+	close(fd);
+	return copy;
+
+error:
+	close(fd);
+	free(copy);
+	return NULL;
+}
+
+/*
+ * A poor-man's version of "xargs -0". Basically parses a given block of
+ * NUL-delimited data, within the given length and adds a pointer to each entry
+ * to the array of pointers.
+ */
+static int parse_xargs(char *data, int data_length, char ***output)
+{
+	int num = 0;
+	char *cur = data;
+
+	if (!data || *output != NULL)
+		return -1;
+
+	while (cur < data + data_length) {
+		num++;
+		*output = must_realloc(*output, (num + 1) * sizeof(**output));
+		(*output)[num - 1] = cur;
+		cur += strlen(cur) + 1;
+	}
+	(*output)[num] = NULL;
+	return num;
+}
+
+/*
+ * "Parse" out argv and envp from /proc/self/cmdline and /proc/self/environ.
+ * This is necessary because we are running in a context where we don't have a
+ * main() that we can just get the arguments from.
+ */
+static int fetchve(char ***argv, char ***envp)
+{
+	char *cmdline = NULL, *environ = NULL;
+	size_t cmdline_size, environ_size;
+
+	cmdline = read_file("/proc/self/cmdline", &cmdline_size);
+	if (!cmdline)
+		goto error;
+	environ = read_file("/proc/self/environ", &environ_size);
+	if (!environ)
+		goto error;
+
+	if (parse_xargs(cmdline, cmdline_size, argv) <= 0)
+		goto error;
+	if (parse_xargs(environ, environ_size, envp) <= 0)
+		goto error;
+
+	return 0;
+
+error:
+	free(environ);
+	free(cmdline);
+	return -EINVAL;
+}
+
+static int clone_binary(void)
+{
+	int binfd, memfd;
+	ssize_t sent = 0;
+
+#ifdef HAVE_MEMFD_CREATE
+	memfd = memfd_create(RUNC_MEMFD_COMMENT, MFD_CLOEXEC | MFD_ALLOW_SEALING);
+#else
+	memfd = open("/tmp", O_TMPFILE | O_EXCL | O_RDWR | O_CLOEXEC, 0711);
+#endif
+	if (memfd < 0)
+		return -ENOTRECOVERABLE;
+
+	binfd = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
+	if (binfd < 0)
+		goto error;
+
+	sent = sendfile(memfd, binfd, NULL, RUNC_SENDFILE_MAX);
+	close(binfd);
+	if (sent < 0)
+		goto error;
+
+#ifdef HAVE_MEMFD_CREATE
+	int err = fcntl(memfd, F_ADD_SEALS, RUNC_MEMFD_SEALS);
+	if (err < 0)
+		goto error;
+#else
+	/* Need to re-open "memfd" as read-only to avoid execve(2) giving -EXTBUSY. */
+	int newfd;
+	char *fdpath = NULL;
+
+	if (asprintf(&fdpath, "/proc/self/fd/%d", memfd) < 0)
+		goto error;
+	newfd = open(fdpath, O_RDONLY | O_CLOEXEC);
+	free(fdpath);
+	if (newfd < 0)
+		goto error;
+
+	close(memfd);
+	memfd = newfd;
+#endif
+	return memfd;
+
+error:
+	close(memfd);
+	return -EIO;
+}
+
+int ensure_cloned_binary(void)
+{
+	int execfd;
+	char **argv = NULL, **envp = NULL;
+
+	/* Check that we're not self-cloned, and if we are then bail. */
+	int cloned = is_self_cloned();
+	if (cloned > 0 || cloned == -ENOTRECOVERABLE)
+		return cloned;
+
+	if (fetchve(&argv, &envp) < 0)
+		return -EINVAL;
+
+	execfd = clone_binary();
+	if (execfd < 0)
+		return -EIO;
+
+	fexecve(execfd, argv, envp);
+	return -ENOEXEC;
+}
diff --git a/libcontainer/nsenter/nsexec.c b/libcontainer/nsenter/nsexec.c
index 28269dfc..7750af35 100644
--- a/libcontainer/nsenter/nsexec.c
+++ b/libcontainer/nsenter/nsexec.c
@@ -534,6 +534,9 @@ void join_namespaces(char *nslist)
 	free(namespaces);
 }
 
+/* Defined in cloned_binary.c. */
+extern int ensure_cloned_binary(void);
+
 void nsexec(void)
 {
 	int pipenum;
@@ -549,6 +552,14 @@ void nsexec(void)
 	if (pipenum == -1)
 		return;
 
+	/*
+	 * We need to re-exec if we are not in a cloned binary. This is necessary
+	 * to ensure that containers won't be able to access the host binary
+	 * through /proc/self/exe. See CVE-2019-5736.
+	 */
+	if (ensure_cloned_binary() < 0)
+		bail("could not ensure we are a cloned binary");
+
 	/* Parse all of the netlink configuration. */
 	nl_parse(pipenum, &config);
 
```

<details>
<summary>bb7d8b1f — nsexec (CVE-2019-5736): avoid parsing environ（点击展开）</summary>

```diff
commit bb7d8b1f41f7bf0399204d54009d6da57c3cc775
Author: Christian Brauner <christian.brauner@ubuntu.com>
Date:   Thu Feb 14 15:56:26 2019 +0100

    nsexec (CVE-2019-5736): avoid parsing environ
    
    My first attempt to simplify this and make it less costly focussed on
    the way constructors are called. I was under the impression that the ELF
    specification mandated that arg, argv, and actually even envp need to be
    passed to functions located in the .init_arry section (aka
    "constructors"). Actually, the specifications is (cf. [2]):
    
    SHT_INIT_ARRAY
    This section contains an array of pointers to initialization functions,
    as described in ``Initialization and Termination Functions'' in Chapter
    5. Each pointer in the array is taken as a parameterless procedure with
    a void return.
    
    which means that this becomes a libc specific decision. Glibc passes
    down those args, musl doesn't. So this approach can't work. However, we
    can at least remove the environment parsing part based on POSIX since
    [1] mandates that there should be an environ variable defined in
    unistd.h which provides access to the environment. See also the relevant
    Open Group specification [1].
    
    [1]: http://pubs.opengroup.org/onlinepubs/9699919799/
    [2]: http://www.sco.com/developers/gabi/latest/ch4.sheader.html#init_array
    
    Fixes: CVE-2019-5736
    Signed-off-by: Christian Brauner <christian.brauner@ubuntu.com>

diff --git a/libcontainer/nsenter/cloned_binary.c b/libcontainer/nsenter/cloned_binary.c
index c8a42c23..c97dfcb7 100644
--- a/libcontainer/nsenter/cloned_binary.c
+++ b/libcontainer/nsenter/cloned_binary.c
@@ -169,31 +169,25 @@ static int parse_xargs(char *data, int data_length, char ***output)
 }
 
 /*
- * "Parse" out argv and envp from /proc/self/cmdline and /proc/self/environ.
+ * "Parse" out argv from /proc/self/cmdline.
  * This is necessary because we are running in a context where we don't have a
  * main() that we can just get the arguments from.
  */
-static int fetchve(char ***argv, char ***envp)
+static int fetchve(char ***argv)
 {
-	char *cmdline = NULL, *environ = NULL;
-	size_t cmdline_size, environ_size;
+	char *cmdline = NULL;
+	size_t cmdline_size;
 
 	cmdline = read_file("/proc/self/cmdline", &cmdline_size);
 	if (!cmdline)
 		goto error;
-	environ = read_file("/proc/self/environ", &environ_size);
-	if (!environ)
-		goto error;
 
 	if (parse_xargs(cmdline, cmdline_size, argv) <= 0)
 		goto error;
-	if (parse_xargs(environ, environ_size, envp) <= 0)
-		goto error;
 
 	return 0;
 
 error:
-	free(environ);
 	free(cmdline);
 	return -EINVAL;
 }
@@ -246,23 +240,26 @@ error:
 	return -EIO;
 }
 
+/* Get cheap access to the environment. */
+extern char **environ;
+
 int ensure_cloned_binary(void)
 {
 	int execfd;
-	char **argv = NULL, **envp = NULL;
+	char **argv = NULL;
 
 	/* Check that we're not self-cloned, and if we are then bail. */
 	int cloned = is_self_cloned();
 	if (cloned > 0 || cloned == -ENOTRECOVERABLE)
 		return cloned;
 
-	if (fetchve(&argv, &envp) < 0)
+	if (fetchve(&argv) < 0)
 		return -EINVAL;
 
 	execfd = clone_binary();
 	if (execfd < 0)
 		return -EIO;
 
-	fexecve(execfd, argv, envp);
+	fexecve(execfd, argv, environ);
 	return -ENOEXEC;
 }
```
</details>
---

## CVE-2019-19921 — runc /proc 挂载配置竞争（符号链接攻击）

- **GHSA:** GHSA-fh74-hm69-rqjw
- **修复版本:** v1.0.0-rc10（2020-01）
- **机制:** 建立 rootfs 时存在竞争：攻击者构造共享卷中 `/proc` 为符号链接，诱使 runc 把 `/proc`（以及 `/sys`）挂载到攻击者可控的位置，绕过安全敏感的 `/proc` 掩码与 SELinux 标签，破坏容器隔离。
- **防御/修复:** 拒绝把 `/proc` 挂载到非目录（符号链接）上，作为临时止血；长期方案是改用 openat2/libpathrs 做安全路径解析。
- **修复 commit:** `3291d66b`（rootfs: do not permit /proc mounts to non-directories，PR #2207）
- **后续:** 该修复在 CVE-2021-30465 的 SecureJoin 改动中被回归，即 CVE-2023-27561。

```diff
commit 3291d66b98445bd7f7d02eac7f2bca2ac2c56942
Author: Aleksa Sarai <asarai@suse.de>
Date:   Sat Dec 21 23:40:17 2019 +1100

    rootfs: do not permit /proc mounts to non-directories
    
    mount(2) will blindly follow symlinks, which is a problem because it
    allows a malicious container to trick runc into mounting /proc to an
    entirely different location (and thus within the attacker's control for
    a rename-exchange attack).
    
    This is just a hotfix (to "stop the bleeding"), and the more complete
    fix would be finish libpathrs and port runc to it (to avoid these types
    of attacks entirely, and defend against a variety of other /proc-related
    attacks). It can be bypased by someone having "/" be a volume controlled
    by another container.
    
    Fixes: CVE-2019-19921
    Signed-off-by: Aleksa Sarai <asarai@suse.de>

diff --git a/libcontainer/rootfs_linux.go b/libcontainer/rootfs_linux.go
index 29102144..106c4c2b 100644
--- a/libcontainer/rootfs_linux.go
+++ b/libcontainer/rootfs_linux.go
@@ -299,6 +299,18 @@ func mountToRootfs(m *configs.Mount, rootfs, mountLabel string, enableCgroupns b
 
 	switch m.Device {
 	case "proc", "sysfs":
+		// If the destination already exists and is not a directory, we bail
+		// out This is to avoid mounting through a symlink or similar -- which
+		// has been a "fun" attack scenario in the past.
+		// TODO: This won't be necessary once we switch to libpathrs and we can
+		//       stop all of these symlink-exchange attacks.
+		if fi, err := os.Lstat(dest); err != nil {
+			if !os.IsNotExist(err) {
+				return err
+			}
+		} else if fi.Mode()&os.ModeDir == 0 {
+			return fmt.Errorf("filesystem %q must be mounted on ordinary directory", m.Device)
+		}
 		if err := os.MkdirAll(dest, 0755); err != nil {
 			return err
 		}
```
---

## CVE-2021-30465 — runc 挂载符号链接交换逃逸（TOCTOU）

- **GHSA:** GHSA-c3xm-pvg7-gh7r
- **修复版本:** v1.0.0-rc95（2021-05-19）
- **机制:** runc 解析挂载目标路径与实际执行 `mount(2)` 之间存在 TOCTOU 竞争。攻击者利用共享卷（如 K8s emptyDir）配合符号链接交换，在路径解析后把目标换成指向宿主根 `/` 的符号链接，诱使 runc 把宿主根文件系统 bind-mount 进容器，实现容器逃逸。
- **防御/修复:** 在执行 mount 之前，在容器 rootfs 内解析并校验挂载目标必须位于 rootfs 边界内（SecureJoin + 校验解析结果），防止逃逸出 rootfs。发现者 Etienne Champetier，补丁由 Noah Meyerhans/Aleksa Sarai 完成，embargo 期直接提交。
- **修复 commit:** `0ca91f44`（rootfs: add mount destination validation）；release 合并 `d3e53034`。
- **副作用:** 该修复把 `filepath.Join` 换成 `SecureJoin`，引入了 CVE-2023-27561 回归（/proc、/sys 符号链接检查失效）。

```diff
commit 0ca91f44f1664da834bc61115a849b56d22f595f
Author: Aleksa Sarai <cyphar@cyphar.com>
Date:   Thu Apr 1 12:00:31 2021 -0700

    rootfs: add mount destination validation
    
    Because the target of a mount is inside a container (which may be a
    volume that is shared with another container), there exists a race
    condition where the target of the mount may change to a path containing
    a symlink after we have sanitised the path -- resulting in us
    inadvertently mounting the path outside of the container.
    
    This is not immediately useful because we are in a mount namespace with
    MS_SLAVE mount propagation applied to "/", so we cannot mount on top of
    host paths in the host namespace. However, if any subsequent mountpoints
    in the configuration use a subdirectory of that host path as a source,
    those subsequent mounts will use an attacker-controlled source path
    (resolved within the host rootfs) -- allowing the bind-mounting of "/"
    into the container.
    
    While arguably configuration issues like this are not entirely within
    runc's threat model, within the context of Kubernetes (and possibly
    other container managers that provide semi-arbitrary container creation
    privileges to untrusted users) this is a legitimate issue. Since we
    cannot block mounting from the host into the container, we need to block
    the first stage of this attack (mounting onto a path outside the
    container).
    
    The long-term plan to solve this would be to migrate to libpathrs, but
    as a stop-gap we implement libpathrs-like path verification through
    readlink(/proc/self/fd/$n) and then do mount operations through the
    procfd once it's been verified to be inside the container. The target
    could move after we've checked it, but if it is inside the container
    then we can assume that it is safe for the same reason that libpathrs
    operations would be safe.
    
    A slight wrinkle is the "copyup" functionality we provide for tmpfs,
    which is the only case where we want to do a mount on the host
    filesystem. To facilitate this, I split out the copy-up functionality
    entirely so that the logic isn't interspersed with the regular tmpfs
    logic. In addition, all dependencies on m.Destination being overwritten
    have been removed since that pattern was just begging to be a source of
    more mount-target bugs (we do still have to modify m.Destination for
    tmpfs-copyup but we only do it temporarily).
    
    Fixes: CVE-2021-30465
    Reported-by: Etienne Champetier <champetier.etienne@gmail.com>
    Co-authored-by: Noah Meyerhans <nmeyerha@amazon.com>
    Reviewed-by: Samuel Karp <skarp@amazon.com>
    Reviewed-by: Kir Kolyshkin <kolyshkin@gmail.com> (@kolyshkin)
    Reviewed-by: Akihiro Suda <akihiro.suda.cz@hco.ntt.co.jp>
    Signed-off-by: Aleksa Sarai <cyphar@cyphar.com>

diff --git a/libcontainer/container_linux.go b/libcontainer/container_linux.go
index 945a0fa0..849bf4a6 100644
--- a/libcontainer/container_linux.go
+++ b/libcontainer/container_linux.go
@@ -1217,7 +1217,6 @@ func (c *linuxContainer) makeCriuRestoreMountpoints(m *configs.Mount) error {
 		if err := checkProcMount(c.config.Rootfs, dest, ""); err != nil {
 			return err
 		}
-		m.Destination = dest
 		if err := os.MkdirAll(dest, 0755); err != nil {
 			return err
 		}
@@ -1257,13 +1256,16 @@ func (c *linuxContainer) prepareCriuRestoreMounts(mounts []*configs.Mount) error
 	umounts := []string{}
 	defer func() {
 		for _, u := range umounts {
-			if e := unix.Unmount(u, unix.MNT_DETACH); e != nil {
-				if e != unix.EINVAL {
-					// Ignore EINVAL as it means 'target is not a mount point.'
-					// It probably has already been unmounted.
-					logrus.Warnf("Error during cleanup unmounting of %q (%v)", u, e)
+			_ = utils.WithProcfd(c.config.Rootfs, u, func(procfd string) error {
+				if e := unix.Unmount(procfd, unix.MNT_DETACH); e != nil {
+					if e != unix.EINVAL {
+						// Ignore EINVAL as it means 'target is not a mount point.'
+						// It probably has already been unmounted.
+						logrus.Warnf("Error during cleanup unmounting of %s (%s): %v", procfd, u, e)
+					}
 				}
-			}
+				return nil
+			})
 		}
 	}()
 	for _, m := range mounts {
@@ -1281,8 +1283,13 @@ func (c *linuxContainer) prepareCriuRestoreMounts(mounts []*configs.Mount) error
 			// because during initial container creation mounts are
 			// set up in the order they are configured.
 			if m.Device == "bind" {
-				if err := unix.Mount(m.Source, m.Destination, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
-					return errorsf.Wrapf(err, "unable to bind mount %q to %q", m.Source, m.Destination)
+				if err := utils.WithProcfd(c.config.Rootfs, m.Destination, func(procfd string) error {
+					if err := unix.Mount(m.Source, procfd, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
+						return errorsf.Wrapf(err, "unable to bind mount %q to %q (through %q)", m.Source, m.Destination, procfd)
+					}
+					return nil
+				}); err != nil {
+					return err
 				}
 				umounts = append(umounts, m.Destination)
 			}
diff --git a/libcontainer/rootfs_linux.go b/libcontainer/rootfs_linux.go
index 1d8a5a03..d9c5146d 100644
--- a/libcontainer/rootfs_linux.go
+++ b/libcontainer/rootfs_linux.go
@@ -25,6 +25,7 @@ import (
 	libcontainerUtils "github.com/opencontainers/runc/libcontainer/utils"
 	"github.com/opencontainers/runtime-spec/specs-go"
 	"github.com/opencontainers/selinux/go-selinux/label"
+	"github.com/sirupsen/logrus"
 	"golang.org/x/sys/unix"
 )
 
@@ -228,8 +229,6 @@ func prepareBindMount(m *configs.Mount, rootfs string) error {
 	if err := checkProcMount(rootfs, dest, m.Source); err != nil {
 		return err
 	}
-	// update the mount with the correct dest after symlinks are resolved.
-	m.Destination = dest
 	if err := createIfNotExists(dest, stat.IsDir()); err != nil {
 		return err
 	}
@@ -266,18 +265,21 @@ func mountCgroupV1(m *configs.Mount, c *mountConfig) error {
 			if err := os.MkdirAll(subsystemPath, 0755); err != nil {
 				return err
 			}
-			flags := defaultMountFlags
-			if m.Flags&unix.MS_RDONLY != 0 {
-				flags = flags | unix.MS_RDONLY
-			}
-			cgroupmount := &configs.Mount{
-				Source:      "cgroup",
-				Device:      "cgroup", // this is actually fstype
-				Destination: subsystemPath,
-				Flags:       flags,
-				Data:        filepath.Base(subsystemPath),
-			}
-			if err := mountNewCgroup(cgroupmount); err != nil {
+			if err := utils.WithProcfd(c.root, b.Destination, func(procfd string) error {
+				flags := defaultMountFlags
+				if m.Flags&unix.MS_RDONLY != 0 {
+					flags = flags | unix.MS_RDONLY
+				}
+				var (
+					source = "cgroup"
+					data   = filepath.Base(subsystemPath)
+				)
+				if data == "systemd" {
+					data = cgroups.CgroupNamePrefix + data
+					source = "systemd"
+				}
+				return unix.Mount(source, procfd, "cgroup", uintptr(flags), data)
+			}); err != nil {
 				return err
 			}
 		} else {
@@ -307,33 +309,79 @@ func mountCgroupV2(m *configs.Mount, c *mountConfig) error {
 	if err := os.MkdirAll(dest, 0755); err != nil {
 		return err
 	}
-	if err := unix.Mount(m.Source, dest, "cgroup2", uintptr(m.Flags), m.Data); err != nil {
-		// when we are in UserNS but CgroupNS is not unshared, we cannot mount cgroup2 (#2158)
-		if err == unix.EPERM || err == unix.EBUSY {
-			src := fs2.UnifiedMountpoint
-			if c.cgroupns && c.cgroup2Path != "" {
-				// Emulate cgroupns by bind-mounting
-				// the container cgroup path rather than
-				// the whole /sys/fs/cgroup.
-				src = c.cgroup2Path
-			}
-			err = unix.Mount(src, dest, "", uintptr(m.Flags)|unix.MS_BIND, "")
-			if err == unix.ENOENT && c.rootlessCgroups {
-				err = nil
+	return utils.WithProcfd(c.root, m.Destination, func(procfd string) error {
+		if err := unix.Mount(m.Source, procfd, "cgroup2", uintptr(m.Flags), m.Data); err != nil {
+			// when we are in UserNS but CgroupNS is not unshared, we cannot mount cgroup2 (#2158)
+			if err == unix.EPERM || err == unix.EBUSY {
+				src := fs2.UnifiedMountpoint
+				if c.cgroupns && c.cgroup2Path != "" {
+					// Emulate cgroupns by bind-mounting
+					// the container cgroup path rather than
+					// the whole /sys/fs/cgroup.
+					src = c.cgroup2Path
+				}
+				err = unix.Mount(src, procfd, "", uintptr(m.Flags)|unix.MS_BIND, "")
+				if err == unix.ENOENT && c.rootlessCgroups {
+					err = nil
+				}
 			}
 			return err
 		}
+		return nil
+	})
+}
+
+func doTmpfsCopyUp(m *configs.Mount, rootfs, mountLabel string) (Err error) {
+	// Set up a scratch dir for the tmpfs on the host.
+	tmpdir, err := prepareTmp("/tmp")
+	if err != nil {
+		return newSystemErrorWithCause(err, "tmpcopyup: failed to setup tmpdir")
+	}
+	defer cleanupTmp(tmpdir)
+	tmpDir, err := ioutil.TempDir(tmpdir, "runctmpdir")
+	if err != nil {
+		return newSystemErrorWithCause(err, "tmpcopyup: failed to create tmpdir")
+	}
+	defer os.RemoveAll(tmpDir)
+
+	// Configure the *host* tmpdir as if it's the container mount. We change
+	// m.Destination since we are going to mount *on the host*.
+	oldDest := m.Destination
+	m.Destination = tmpDir
+	err = mountPropagate(m, "/", mountLabel)
+	m.Destination = oldDest
+	if err != nil {
 		return err
 	}
-	return nil
+	defer func() {
+		if Err != nil {
+			if err := unix.Unmount(tmpDir, unix.MNT_DETACH); err != nil {
+				logrus.Warnf("tmpcopyup: failed to unmount tmpdir on error: %v", err)
+			}
+		}
+	}()
+
+	return utils.WithProcfd(rootfs, m.Destination, func(procfd string) (Err error) {
+		// Copy the container data to the host tmpdir. We append "/" to force
+		// CopyDirectory to resolve the symlink rather than trying to copy the
+		// symlink itself.
+		if err := fileutils.CopyDirectory(procfd+"/", tmpDir); err != nil {
+			return fmt.Errorf("tmpcopyup: failed to copy %s to %s (%s): %w", m.Destination, procfd, tmpDir, err)
+		}
+		// Now move the mount into the container.
+		if err := unix.Mount(tmpDir, procfd, "", unix.MS_MOVE, ""); err != nil {
+			return fmt.Errorf("tmpcopyup: failed to move mount %s to %s (%s): %w", tmpDir, procfd, m.Destination, err)
+		}
+		return nil
+	})
 }
 
 func mountToRootfs(m *configs.Mount, c *mountConfig) error {
 	rootfs := c.root
 	mountLabel := c.label
-	dest := m.Destination
-	if !strings.HasPrefix(dest, rootfs) {
-		dest = filepath.Join(rootfs, dest)
+	dest, err := securejoin.SecureJoin(rootfs, m.Destination)
+	if err != nil {
+		return err
 	}
 
 	switch m.Device {
@@ -364,53 +412,21 @@ func mountToRootfs(m *configs.Mount, c *mountConfig) error {
 		}
 		return label.SetFileLabel(dest, mountLabel)
 	case "tmpfs":
-		copyUp := m.Extensions&configs.EXT_COPYUP == configs.EXT_COPYUP
-		tmpDir := ""
-		// dest might be an absolute symlink, so it needs
-		// to be resolved under rootfs.
-		dest, err := securejoin.SecureJoin(rootfs, m.Destination)
-		if err != nil {
-			return err
-		}
-		m.Destination = dest
 		stat, err := os.Stat(dest)
 		if err != nil {
 			if err := os.MkdirAll(dest, 0755); err != nil {
 				return err
 			}
 		}
-		if copyUp {
-			tmpdir, err := prepareTmp("/tmp")
-			if err != nil {
-				return newSystemErrorWithCause(err, "tmpcopyup: failed to setup tmpdir")
-			}
-			defer cleanupTmp(tmpdir)
-			tmpDir, err = ioutil.TempDir(tmpdir, "runctmpdir")
-			if err != nil {
-				return newSystemErrorWithCause(err, "tmpcopyup: failed to create tmpdir")
-			}
-			defer os.RemoveAll(tmpDir)
-			m.Destination = tmpDir
+
+		if m.Extensions&configs.EXT_COPYUP == configs.EXT_COPYUP {
+			err = doTmpfsCopyUp(m, rootfs, mountLabel)
+		} else {
+			err = mountPropagate(m, rootfs, mountLabel)
 		}
-		if err := mountPropagate(m, rootfs, mountLabel); err != nil {
+		if err != nil {
 			return err
 		}
-		if copyUp {
-			if err := fileutils.CopyDirectory(dest, tmpDir); err != nil {
-				errMsg := fmt.Errorf("tmpcopyup: failed to copy %s to %s: %v", dest, tmpDir, err)
-				if err1 := unix.Unmount(tmpDir, unix.MNT_DETACH); err1 != nil {
-					return newSystemErrorWithCausef(err1, "tmpcopyup: %v: failed to unmount", errMsg)
-				}
-				return errMsg
-			}
-			if err := unix.Mount(tmpDir, dest, "", unix.MS_MOVE, ""); err != nil {
-				errMsg := fmt.Errorf("tmpcopyup: failed to move mount %s to %s: %v", tmpDir, dest, err)
-				if err1 := unix.Unmount(tmpDir, unix.MNT_DETACH); err1 != nil {
-					return newSystemErrorWithCausef(err1, "tmpcopyup: %v: failed to unmount", errMsg)
-				}
-				return errMsg
-			}
-		}
 		if stat != nil {
 			if err = os.Chmod(dest, stat.Mode()); err != nil {
 				return err
@@ -454,19 +470,9 @@ func mountToRootfs(m *configs.Mount, c *mountConfig) error {
 		}
 		return mountCgroupV1(m, c)
 	default:
-		// ensure that the destination of the mount is resolved of symlinks at mount time because
-		// any previous mounts can invalidate the next mount's destination.
-		// this can happen when a user specifies mounts within other mounts to cause breakouts or other
-		// evil stuff to try to escape the container's rootfs.
-		var err error
-		if dest, err = securejoin.SecureJoin(rootfs, m.Destination); err != nil {
-			return err
-		}
 		if err := checkProcMount(rootfs, dest, m.Source); err != nil {
 			return err
 		}
-		// update the mount with the correct dest after symlinks are resolved.
-		m.Destination = dest
 		if err := os.MkdirAll(dest, 0755); err != nil {
 			return err
 		}
@@ -649,7 +655,7 @@ func createDevices(config *configs.Config) error {
 	return nil
 }
 
-func bindMountDeviceNode(dest string, node *devices.Device) error {
+func bindMountDeviceNode(rootfs, dest string, node *devices.Device) error {
 	f, err := os.Create(dest)
 	if err != nil && !os.IsExist(err) {
 		return err
@@ -657,7 +663,9 @@ func bindMountDeviceNode(dest string, node *devices.Device) error {
 	if f != nil {
 		f.Close()
 	}
-	return unix.Mount(node.Path, dest, "bind", unix.MS_BIND, "")
+	return utils.WithProcfd(rootfs, dest, func(procfd string) error {
+		return unix.Mount(node.Path, procfd, "bind", unix.MS_BIND, "")
+	})
 }
 
 // Creates the device node in the rootfs of the container.
@@ -666,18 +674,21 @@ func createDeviceNode(rootfs string, node *devices.Device, bind bool) error {
 		// The node only exists for cgroup reasons, ignore it here.
 		return nil
 	}
-	dest := filepath.Join(rootfs, node.Path)
+	dest, err := securejoin.SecureJoin(rootfs, node.Path)
+	if err != nil {
+		return err
+	}
 	if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
 		return err
 	}
 	if bind {
-		return bindMountDeviceNode(dest, node)
+		return bindMountDeviceNode(rootfs, dest, node)
 	}
 	if err := mknodDevice(dest, node); err != nil {
 		if os.IsExist(err) {
 			return nil
 		} else if os.IsPermission(err) {
-			return bindMountDeviceNode(dest, node)
+			return bindMountDeviceNode(rootfs, dest, node)
 		}
 		return err
 	}
@@ -1024,61 +1035,47 @@ func writeSystemProperty(key, value string) error {
 }
 
 func remount(m *configs.Mount, rootfs string) error {
-	var (
-		dest = m.Destination
-	)
-	if !strings.HasPrefix(dest, rootfs) {
-		dest = filepath.Join(rootfs, dest)
-	}
-	return unix.Mount(m.Source, dest, m.Device, uintptr(m.Flags|unix.MS_REMOUNT), "")
+	return utils.WithProcfd(rootfs, m.Destination, func(procfd string) error {
+		return unix.Mount(m.Source, procfd, m.Device, uintptr(m.Flags|unix.MS_REMOUNT), "")
+	})
 }
 
 // Do the mount operation followed by additional mounts required to take care
-// of propagation flags.
+// of propagation flags. This will always be scoped inside the container rootfs.
 func mountPropagate(m *configs.Mount, rootfs string, mountLabel string) error {
 	var (
-		dest  = m.Destination
 		data  = label.FormatMountLabel(m.Data, mountLabel)
 		flags = m.Flags
 	)
-	if libcontainerUtils.CleanPath(dest) == "/dev" {
-		flags &= ^unix.MS_RDONLY
-	}
-
-	// Mount it rw to allow chmod operation. A remount will be performed
-	// later to make it ro if set.
-	if m.Device == "tmpfs" {
+	// Delay mounting the filesystem read-only if we need to do further
+	// operations on it. We need to set up files in "/dev" and tmpfs mounts may
+	// need to be chmod-ed after mounting. The mount will be remounted ro later
+	// in finalizeRootfs() if necessary.
+	if libcontainerUtils.CleanPath(m.Destination) == "/dev" || m.Device == "tmpfs" {
 		flags &= ^unix.MS_RDONLY
 	}
 
-	copyUp := m.Extensions&configs.EXT_COPYUP == configs.EXT_COPYUP
-	if !(copyUp || strings.HasPrefix(dest, rootfs)) {
-		dest = filepath.Join(rootfs, dest)
-	}
-
-	if err := unix.Mount(m.Source, dest, m.Device, uintptr(flags), data); err != nil {
-		return err
-	}
-
-	for _, pflag := range m.PropagationFlags {
-		if err := unix.Mount("", dest, "", uintptr(pflag), ""); err != nil {
-			return err
+	// Because the destination is inside a container path which might be
+	// mutating underneath us, we verify that we are actually going to mount
+	// inside the container with WithProcfd() -- mounting through a procfd
+	// mounts on the target.
+	if err := utils.WithProcfd(rootfs, m.Destination, func(procfd string) error {
+		return unix.Mount(m.Source, procfd, m.Device, uintptr(flags), data)
+	}); err != nil {
+		return fmt.Errorf("mount through procfd: %w", err)
+	}
+	// We have to apply mount propagation flags in a separate WithProcfd() call
+	// because the previous call invalidates the passed procfd -- the mount
+	// target needs to be re-opened.
+	if err := utils.WithProcfd(rootfs, m.Destination, func(procfd string) error {
+		for _, pflag := range m.PropagationFlags {
+			if err := unix.Mount("", procfd, "", uintptr(pflag), ""); err != nil {
+				return err
+			}
 		}
-	}
-	return nil
-}
-
-func mountNewCgroup(m *configs.Mount) error {
-	var (
-		data   = m.Data
-		source = m.Source
-	)
-	if data == "systemd" {
-		data = cgroups.CgroupNamePrefix + data
-		source = "systemd"
-	}
-	if err := unix.Mount(source, m.Destination, m.Device, uintptr(m.Flags), data); err != nil {
-		return err
+		return nil
+	}); err != nil {
+		return fmt.Errorf("change mount propagation through procfd: %w", err)
 	}
 	return nil
 }
diff --git a/libcontainer/utils/utils.go b/libcontainer/utils/utils.go
index 1b72b7a1..cd78f23e 100644
--- a/libcontainer/utils/utils.go
+++ b/libcontainer/utils/utils.go
@@ -3,12 +3,15 @@ package utils
 import (
 	"encoding/binary"
 	"encoding/json"
+	"fmt"
 	"io"
 	"os"
 	"path/filepath"
+	"strconv"
 	"strings"
 	"unsafe"
 
+	"github.com/cyphar/filepath-securejoin"
 	"golang.org/x/sys/unix"
 )
 
@@ -88,6 +91,57 @@ func CleanPath(path string) string {
 	return filepath.Clean(path)
 }
 
+// stripRoot returns the passed path, stripping the root path if it was
+// (lexicially) inside it. Note that both passed paths will always be treated
+// as absolute, and the returned path will also always be absolute. In
+// addition, the paths are cleaned before stripping the root.
+func stripRoot(root, path string) string {
+	// Make the paths clean and absolute.
+	root, path = CleanPath("/"+root), CleanPath("/"+path)
+	switch {
+	case path == root:
+		path = "/"
+	case root == "/":
+		// do nothing
+	case strings.HasPrefix(path, root+"/"):
+		path = strings.TrimPrefix(path, root+"/")
+	}
+	return CleanPath("/" + path)
+}
+
+// WithProcfd runs the passed closure with a procfd path (/proc/self/fd/...)
+// corresponding to the unsafePath resolved within the root. Before passing the
+// fd, this path is verified to have been inside the root -- so operating on it
+// through the passed fdpath should be safe. Do not access this path through
+// the original path strings, and do not attempt to use the pathname outside of
+// the passed closure (the file handle will be freed once the closure returns).
+func WithProcfd(root, unsafePath string, fn func(procfd string) error) error {
+	// Remove the root then forcefully resolve inside the root.
+	unsafePath = stripRoot(root, unsafePath)
+	path, err := securejoin.SecureJoin(root, unsafePath)
+	if err != nil {
+		return fmt.Errorf("resolving path inside rootfs failed: %v", err)
+	}
+
+	// Open the target path.
+	fh, err := os.OpenFile(path, unix.O_PATH|unix.O_CLOEXEC, 0)
+	if err != nil {
+		return fmt.Errorf("open o_path procfd: %w", err)
+	}
+	defer fh.Close()
+
+	// Double-check the path is the one we expected.
+	procfd := "/proc/self/fd/" + strconv.Itoa(int(fh.Fd()))
+	if realpath, err := os.Readlink(procfd); err != nil {
+		return fmt.Errorf("procfd verification failed: %w", err)
+	} else if realpath != path {
+		return fmt.Errorf("possibly malicious path detected -- refusing to operate on %s", realpath)
+	}
+
+	// Run the closure.
+	return fn(procfd)
+}
+
 // SearchLabels searches a list of key-value pairs for the provided key and
 // returns the corresponding value. The pairs must be separated with '='.
 func SearchLabels(labels []string, query string) string {
diff --git a/libcontainer/utils/utils_test.go b/libcontainer/utils/utils_test.go
index 7f38ed16..d3366223 100644
--- a/libcontainer/utils/utils_test.go
+++ b/libcontainer/utils/utils_test.go
@@ -143,3 +143,38 @@ func TestCleanPath(t *testing.T) {
 		t.Errorf("expected to receive '/foo' and received %s", path)
 	}
 }
+
+func TestStripRoot(t *testing.T) {
+	for _, test := range []struct {
+		root, path, out string
+	}{
+		// Works with multiple components.
+		{"/a/b", "/a/b/c", "/c"},
+		{"/hello/world", "/hello/world/the/quick-brown/fox", "/the/quick-brown/fox"},
+		// '/' must be a no-op.
+		{"/", "/a/b/c", "/a/b/c"},
+		// Must be the correct order.
+		{"/a/b", "/a/c/b", "/a/c/b"},
+		// Must be at start.
+		{"/abc/def", "/foo/abc/def/bar", "/foo/abc/def/bar"},
+		// Must be a lexical parent.
+		{"/foo/bar", "/foo/barSAMECOMPONENT", "/foo/barSAMECOMPONENT"},
+		// Must only strip the root once.
+		{"/foo/bar", "/foo/bar/foo/bar/baz", "/foo/bar/baz"},
+		// Deal with .. in a fairly sane way.
+		{"/foo/bar", "/foo/bar/../baz", "/foo/baz"},
+		{"/foo/bar", "../../../../../../foo/bar/baz", "/baz"},
+		{"/foo/bar", "/../../../../../../foo/bar/baz", "/baz"},
+		{"/foo/bar/../baz", "/foo/baz/bar", "/bar"},
+		{"/foo/bar/../baz", "/foo/baz/../bar/../baz/./foo", "/foo"},
+		// All paths are made absolute before stripping.
+		{"foo/bar", "/foo/bar/baz/bee", "/baz/bee"},
+		{"/foo/bar", "foo/bar/baz/beef", "/baz/beef"},
+		{"foo/bar", "foo/bar/baz/beets", "/baz/beets"},
+	} {
+		got := stripRoot(test.root, test.path)
+		if got != test.out {
+			t.Errorf("stripRoot(%q, %q) -- got %q, expected %q", test.root, test.path, got, test.out)
+		}
+	}
+}
```
---

## CVE-2021-43784 — runc init netlink 长度整数溢出

- **GHSA:** GHSA-v95c-p5hm-xq8f
- **修复版本:** v1.0.3（2021-12-06），亦在 v1.1.0-rc1
- **机制:** runc init 通过 netlink socket 把容器配置从父进程传给子进程。byte-array 属性的 16-bit 长度字段未检查整数溢出：构造超大的配置 blob 可使长度字段溢出，导致属性负载被当作 netlink 消息解析，从而覆盖其他容器配置（如命名空间限制、挂载路径）。Google Project Zero 的 Felix Wilhelm 报告；实际利用难度低（官方评估所有已发布版本基本不可利用）。
- **防御/修复:** 对 netlink 消息长度做溢出检查。
- **修复 commit:** `d72d057b`（runc init: avoid netlink message length overflows）

```diff
commit d72d057ba794164c3cce9451a00b72a78b25e1ae
Author: Aleksa Sarai <cyphar@cyphar.com>
Date:   Thu Nov 18 16:12:59 2021 +1100

    runc init: avoid netlink message length overflows
    
    When writing netlink messages, it is possible to have a byte array
    larger than UINT16_MAX which would result in the length field
    overflowing and allowing user-controlled data to be parsed as control
    characters (such as creating custom mount points, changing which set of
    namespaces to allow, and so on).
    
    Co-authored-by: Kir Kolyshkin <kolyshkin@gmail.com>
    Signed-off-by: Kir Kolyshkin <kolyshkin@gmail.com>
    Signed-off-by: Aleksa Sarai <cyphar@cyphar.com>

diff --git a/libcontainer/container_linux.go b/libcontainer/container_linux.go
index 4c56582f..f6877b74 100644
--- a/libcontainer/container_linux.go
+++ b/libcontainer/container_linux.go
@@ -2102,16 +2102,34 @@ func encodeIDMapping(idMap []configs.IDMap) ([]byte, error) {
 	return data.Bytes(), nil
 }
 
+// netlinkError is an error wrapper type for use by custom netlink message
+// types. Panics with errors are wrapped in netlinkError so that the recover
+// in bootstrapData can distinguish intentional panics.
+type netlinkError struct{ error }
+
 // bootstrapData encodes the necessary data in netlink binary format
 // as a io.Reader.
 // Consumer can write the data to a bootstrap program
 // such as one that uses nsenter package to bootstrap the container's
 // init process correctly, i.e. with correct namespaces, uid/gid
 // mapping etc.
-func (c *linuxContainer) bootstrapData(cloneFlags uintptr, nsMaps map[configs.NamespaceType]string, it initType) (io.Reader, error) {
+func (c *linuxContainer) bootstrapData(cloneFlags uintptr, nsMaps map[configs.NamespaceType]string, it initType) (_ io.Reader, Err error) {
 	// create the netlink message
 	r := nl.NewNetlinkRequest(int(InitMsg), 0)
 
+	// Our custom messages cannot bubble up an error using returns, instead
+	// they will panic with the specific error type, netlinkError. In that
+	// case, recover from the panic and return that as an error.
+	defer func() {
+		if r := recover(); r != nil {
+			if e, ok := r.(netlinkError); ok {
+				Err = e.error
+			} else {
+				panic(r)
+			}
+		}
+	}()
+
 	// write cloneFlags
 	r.AddData(&Int32msg{
 		Type:  CloneFlagsAttr,
diff --git a/libcontainer/message_linux.go b/libcontainer/message_linux.go
index 7d0b6295..6d1107e8 100644
--- a/libcontainer/message_linux.go
+++ b/libcontainer/message_linux.go
@@ -1,6 +1,9 @@
 package libcontainer
 
 import (
+	"fmt"
+	"math"
+
 	"github.com/vishvananda/netlink/nl"
 	"golang.org/x/sys/unix"
 )
@@ -53,6 +56,12 @@ type Bytemsg struct {
 
 func (msg *Bytemsg) Serialize() []byte {
 	l := msg.Len()
+	if l > math.MaxUint16 {
+		// We cannot return nil nor an error here, so we panic with
+		// a specific type instead, which is handled via recover in
+		// bootstrapData.
+		panic(netlinkError{fmt.Errorf("netlink: cannot serialize bytemsg of length %d (larger than UINT16_MAX)", l)})
+	}
 	buf := make([]byte, (l+unix.NLA_ALIGNTO-1) & ^(unix.NLA_ALIGNTO-1))
 	native := nl.NativeEndian()
 	native.PutUint16(buf[0:2], uint16(l))
```
---

## CVE-2023-25809 — rootless 模式下 /sys/fs/cgroup 可写

- **GHSA:** GHSA-m8cg-xc2p-r3fc
- **修复版本:** 1.1.5（2023-03-29）
- **机制:** 在两种情况下 rootless runc 使 `/sys/fs/cgroup` 以可写方式暴露给容器：(1) runc 在用户命名空间内执行且未取消共享 cgroup 命名空间（如 Rootless Docker/Podman 配 `--cgroupns=host`）；(2) runc 在用户命名空间外执行且 `/sys` 以 `rbind,ro` 挂载。容器由此可写宿主用户拥有的 cgroup 层次（`/sys/fs/cgroup/user.slice/...`），破坏隔离。
- **防御/修复:** 重写 `mountCgroupV2`，把 cgroup bind 挂载委托给 `mountToRootfs()` 并保持只读标志。
- **修复 commit:** `df4eae45`（rootless: fix /sys/fs/cgroup mounts）；1.1 backport `0e6b818a`；私有安全 merge `0d62b950`。

```diff
commit df4eae457b8ccffa619c659c2def5c777d8ff507
Author: Akihiro Suda <akihiro.suda.cz@hco.ntt.co.jp>
Date:   Mon Dec 26 12:04:26 2022 +0900

    rootless: fix /sys/fs/cgroup mounts
    
    It was found that rootless runc makes `/sys/fs/cgroup` writable in following conditons:
    
    1. when runc is executed inside the user namespace, and the config.json does not specify the cgroup namespace to be unshared
       (e.g.., `(docker|podman|nerdctl) run --cgroupns=host`, with Rootless Docker/Podman/nerdctl)
    2. or, when runc is executed outside the user namespace, and `/sys` is mounted with `rbind, ro`
       (e.g., `runc spec --rootless`; this condition is very rare)
    
    A container may gain the write access to user-owned cgroup hierarchy `/sys/fs/cgroup/user.slice/...` on the host.
    Other users's cgroup hierarchies are not affected.
    
    To fix the issue, this commit does:
    1. Remount `/sys/fs/cgroup` to apply `MS_RDONLY` when it is being bind-mounted
    2. Mask `/sys/fs/cgroup` when the bind source is unavailable
    
    Fix CVE-2023-25809 (GHSA-m8cg-xc2p-r3fc)
    
    Co-authored-by: Kir Kolyshkin <kolyshkin@gmail.com>
    Signed-off-by: Akihiro Suda <akihiro.suda.cz@hco.ntt.co.jp>

diff --git a/libcontainer/rootfs_linux.go b/libcontainer/rootfs_linux.go
index 2a98372b..2e0e3770 100644
--- a/libcontainer/rootfs_linux.go
+++ b/libcontainer/rootfs_linux.go
@@ -306,26 +306,41 @@ func mountCgroupV2(m *configs.Mount, c *mountConfig) error {
 	if err := os.MkdirAll(dest, 0o755); err != nil {
 		return err
 	}
-	return utils.WithProcfd(c.root, m.Destination, func(procfd string) error {
-		if err := mount(m.Source, m.Destination, procfd, "cgroup2", uintptr(m.Flags), m.Data); err != nil {
-			// when we are in UserNS but CgroupNS is not unshared, we cannot mount cgroup2 (#2158)
-			if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EBUSY) {
-				src := fs2.UnifiedMountpoint
-				if c.cgroupns && c.cgroup2Path != "" {
-					// Emulate cgroupns by bind-mounting
-					// the container cgroup path rather than
-					// the whole /sys/fs/cgroup.
-					src = c.cgroup2Path
-				}
-				err = mount(src, m.Destination, procfd, "", uintptr(m.Flags)|unix.MS_BIND, "")
-				if c.rootlessCgroups && errors.Is(err, unix.ENOENT) {
-					err = nil
-				}
-			}
-			return err
-		}
-		return nil
+	err = utils.WithProcfd(c.root, m.Destination, func(procfd string) error {
+		return mount(m.Source, m.Destination, procfd, "cgroup2", uintptr(m.Flags), m.Data)
 	})
+	if err == nil || !(errors.Is(err, unix.EPERM) || errors.Is(err, unix.EBUSY)) {
+		return err
+	}
+
+	// When we are in UserNS but CgroupNS is not unshared, we cannot mount
+	// cgroup2 (#2158), so fall back to bind mount.
+	bindM := &configs.Mount{
+		Device:           "bind",
+		Source:           fs2.UnifiedMountpoint,
+		Destination:      m.Destination,
+		Flags:            unix.MS_BIND | m.Flags,
+		PropagationFlags: m.PropagationFlags,
+	}
+	if c.cgroupns && c.cgroup2Path != "" {
+		// Emulate cgroupns by bind-mounting the container cgroup path
+		// rather than the whole /sys/fs/cgroup.
+		bindM.Source = c.cgroup2Path
+	}
+	// mountToRootfs() handles remounting for MS_RDONLY.
+	// No need to set c.fd here, because mountToRootfs() calls utils.WithProcfd() by itself in mountPropagate().
+	err = mountToRootfs(bindM, c)
+	if c.rootlessCgroups && errors.Is(err, unix.ENOENT) {
+		// ENOENT (for `src = c.cgroup2Path`) happens when rootless runc is being executed
+		// outside the userns+mountns.
+		//
+		// Mask `/sys/fs/cgroup` to ensure it is read-only, even when `/sys` is mounted
+		// with `rbind,ro` (`runc spec --rootless` produces `rbind,ro` for `/sys`).
+		err = utils.WithProcfd(c.root, m.Destination, func(procfd string) error {
+			return maskPath(procfd, c.label)
+		})
+	}
+	return err
 }
 
 func doTmpfsCopyUp(m *configs.Mount, rootfs, mountLabel string) (Err error) {
diff --git a/tests/integration/mounts.bats b/tests/integration/mounts.bats
index 1ec675ac..1e72c5b1 100644
--- a/tests/integration/mounts.bats
+++ b/tests/integration/mounts.bats
@@ -63,3 +63,20 @@ function teardown() {
 	runc run test_busybox
 	[ "$status" -eq 0 ]
 }
+
+# https://github.com/opencontainers/runc/security/advisories/GHSA-m8cg-xc2p-r3fc
+@test "runc run [ro /sys/fs/cgroup mount]" {
+	# With cgroup namespace
+	update_config '.process.args |= ["sh", "-euc", "for f in `grep /sys/fs/cgroup /proc/mounts | awk \"{print \\\\$2}\"| uniq`; do grep -w $f /proc/mounts | tail -n1; done"]'
+	runc run test_busybox
+	[ "$status" -eq 0 ]
+	[ "${#lines[@]}" -ne 0 ]
+	for line in "${lines[@]}"; do [[ "${line}" == *'ro,'* ]]; done
+
+	# Without cgroup namespace
+	update_config '.linux.namespaces -= [{"type": "cgroup"}]'
+	runc run test_busybox
+	[ "$status" -eq 0 ]
+	[ "${#lines[@]}" -ne 0 ]
+	for line in "${lines[@]}"; do [[ "${line}" == *'ro,'* ]]; done
+}
```
---

## CVE-2023-27561 — CVE-2019-19921 回归：/proc、/sys 符号链接检查失效

- **GHSA:** GHSA-vpvm-3wq2-2wvm
- **修复版本:** 1.1.5（2023-03-29）
- **机制:** CVE-2021-30465 的修复（`0ca91f44`）把 `filepath.Join` 换成 `SecureJoin`，而 SecureJoin 会解析符号链接，导致原先"拒绝把 /proc、/sys 挂载到符号链接上"的检查（CVE-2019-19921 的修复）失效。攻击者起两个容器 + 共享卷竞争符号链接，可在宿主 `/proc/sys/kernel/core_pattern` 等路径写入，破坏容器隔离甚至提权到宿主。
- **防御/修复:** 恢复并加强检查：`/proc` 与 `/sys` 不得是符号链接（"Prohibit /proc and /sys to be symlinks"）。回归测试见 `457e1ffa`。
- **修复 commit:** `0abab45c`（PR #3785 核心提交，merge `059d7730`）
- **相关:** 同一回归的另一攻击向量 CVE-2023-28642（GHSA-g2j6-57v7-gm8c）同批修复。

```diff
commit 0abab45c9b97c113ff2cdc16f3a7388444c3fbec
Author: Kir Kolyshkin <kolyshkin@gmail.com>
Date:   Thu Mar 16 14:35:50 2023 -0700

    Prohibit /proc and /sys to be symlinks
    
    Commit 3291d66b9844 introduced a check for /proc and /sys, making sure
    the destination (dest) is a directory (and not e.g. a symlink).
    
    Later, a hunk from commit 0ca91f44f switched from using filepath.Join
    to SecureJoin for dest. As SecureJoin follows and resolves symlinks,
    the check whether dest is a symlink no longer works.
    
    To fix, do the check without/before using SecureJoin.
    
    Add integration tests to make sure we won't regress.
    
    Signed-off-by: Kir Kolyshkin <kolyshkin@gmail.com>
    (cherry picked from commit 0d72adf96dda1b687815bf89bb245b937a2f603c)
    Signed-off-by: Sebastiaan van Stijn <github@gone.nl>

diff --git a/libcontainer/rootfs_linux.go b/libcontainer/rootfs_linux.go
index ec7638e4..17eefb38 100644
--- a/libcontainer/rootfs_linux.go
+++ b/libcontainer/rootfs_linux.go
@@ -398,32 +398,43 @@ func doTmpfsCopyUp(m *configs.Mount, rootfs, mountLabel string) (Err error) {
 
 func mountToRootfs(m *configs.Mount, c *mountConfig) error {
 	rootfs := c.root
-	mountLabel := c.label
-	mountFd := c.fd
-	dest, err := securejoin.SecureJoin(rootfs, m.Destination)
-	if err != nil {
-		return err
-	}
 
+	// procfs and sysfs are special because we need to ensure they are actually
+	// mounted on a specific path in a container without any funny business.
 	switch m.Device {
 	case "proc", "sysfs":
 		// If the destination already exists and is not a directory, we bail
-		// out This is to avoid mounting through a symlink or similar -- which
+		// out. This is to avoid mounting through a symlink or similar -- which
 		// has been a "fun" attack scenario in the past.
 		// TODO: This won't be necessary once we switch to libpathrs and we can
 		//       stop all of these symlink-exchange attacks.
+		dest := filepath.Clean(m.Destination)
+		if !strings.HasPrefix(dest, rootfs) {
+			// Do not use securejoin as it resolves symlinks.
+			dest = filepath.Join(rootfs, dest)
+		}
 		if fi, err := os.Lstat(dest); err != nil {
 			if !os.IsNotExist(err) {
 				return err
 			}
-		} else if fi.Mode()&os.ModeDir == 0 {
+		} else if !fi.IsDir() {
 			return fmt.Errorf("filesystem %q must be mounted on ordinary directory", m.Device)
 		}
 		if err := os.MkdirAll(dest, 0o755); err != nil {
 			return err
 		}
-		// Selinux kernels do not support labeling of /proc or /sys
+		// Selinux kernels do not support labeling of /proc or /sys.
 		return mountPropagate(m, rootfs, "", nil)
+	}
+
+	mountLabel := c.label
+	mountFd := c.fd
+	dest, err := securejoin.SecureJoin(rootfs, m.Destination)
+	if err != nil {
+		return err
+	}
+
+	switch m.Device {
 	case "mqueue":
 		if err := os.MkdirAll(dest, 0o755); err != nil {
 			return err
diff --git a/tests/integration/mask.bats b/tests/integration/mask.bats
index b5f29675..272c879c 100644
--- a/tests/integration/mask.bats
+++ b/tests/integration/mask.bats
@@ -56,3 +56,22 @@ function teardown() {
 	[ "$status" -eq 1 ]
 	[[ "${output}" == *"Operation not permitted"* ]]
 }
+
+@test "mask paths [prohibit symlink /proc]" {
+	ln -s /symlink rootfs/proc
+	runc run -d --console-socket "$CONSOLE_SOCKET" test_busybox
+	[ "$status" -eq 1 ]
+	[[ "${output}" == *"must be mounted on ordinary directory"* ]]
+}
+
+@test "mask paths [prohibit symlink /sys]" {
+	# In rootless containers, /sys is a bind mount not a real sysfs.
+	requires root
+
+	ln -s /symlink rootfs/sys
+	runc run -d --console-socket "$CONSOLE_SOCKET" test_busybox
+	[ "$status" -eq 1 ]
+	# On cgroup v1, this may fail before checking if /sys is a symlink,
+	# so we merely check that it fails, and do not check the exact error
+	# message like for /proc above.
+}
```
---

## CVE-2024-21626 — Leaky Vessels：泄漏 fd 导致 cwd 逃逸

- **GHSA:** GHSA-xr7r-f8xq-vfvv（CVSS 8.6）
- **修复版本:** 1.1.12（2024-01-31）
- **机制:** runc 在容器初始化期间内部打开的 fd（如 `/sys/fs/cgroup`）被容器 init 进程继承且未设 `O_CLOEXEC`。攻击变体：
  1. 恶意镜像把 `process.cwd` 指到泄漏的 fd，泄露宿主命名空间的 cwd（`/proc/self/fd/[n]`）；
  2. `runc exec --cwd` 符号链接到泄漏 fd → 容器逃逸；
  3a/3b. 通过 `/proc/self/fd/7/../../../bin/bash` 这类路径覆盖宿主二进制（类似 CVE-2019-5736 手法）。
- **防御/修复（7 个 commit）:**
  - `284ba305` — init: close internal fds before execve（execve 前关闭内部 fd）
  - `0994249a` — init: verify after chdir that cwd is inside the container（校验 cwd 在容器内）
  - `683ad2ff` — libcontainer: mark all non-stdio fds O_CLOEXEC before spawning init（所有非 stdio fd 设 CLOEXEC）
  - `b6633f48` — cgroup: plug leaks of /sys/fs/cgroup handle（堵塞 cgroup fd 泄漏）
  - `fbe3eed1` — setns init: do explicit lookup of execve argument early
  - `e9665f4d` — init: don't special-case logrus fds
  - `506552a8` — Fix File to Close
  - 私有安全 merge: `a9833ff`

<details>
<summary>284ba305 — init: close internal fds before execve（点击展开）</summary>

```diff
commit 284ba3057e428f8d6c7afcc3b0ac752e525957df
Author: Aleksa Sarai <cyphar@cyphar.com>
Date:   Tue Jan 2 14:58:28 2024 +1100

    init: close internal fds before execve
    
    If we leak a file descriptor referencing the host filesystem, an
    attacker could use a /proc/self/fd magic-link as the source for execve
    to execute a host binary in the container. This would allow the binary
    itself (or a process inside the container in the 'runc exec' case) to
    write to a host binary, leading to a container escape.
    
    The simple solution is to make sure we close all file descriptors
    immediately before the execve(2) step. Doing this earlier can lead to very
    serious issues in Go (as file descriptors can be reused, any (*os.File)
    reference could start silently operating on a different file) so we have
    to do it as late as possible.
    
    Unfortunately, there are some Go runtime file descriptors that we must
    not close (otherwise the Go scheduler panics randomly). The only way of
    being sure which file descriptors cannot be closed is to sneakily
    go:linkname the runtime internal "internal/poll.IsPollDescriptor"
    function. This is almost certainly not recommended but there isn't any
    other way to be absolutely sure, while also closing any other possible
    files.
    
    In addition, we can keep the logrus forwarding logfd open because you
    cannot execve a pipe and the contents of the pipe are so restricted
    (JSON-encoded in a format we pick) that it seems unlikely you could even
    construct shellcode. Closing the logfd causes issues if there is an
    error returned from execve.
    
    In mainline runc, runc-dmz protects us against this attack because the
    intermediate execve(2) closes all of the O_CLOEXEC internal runc file
    descriptors and thus runc-dmz cannot access them to attack the host.
    
    Fixes: GHSA-xr7r-f8xq-vfvv CVE-2024-21626
    Signed-off-by: Aleksa Sarai <cyphar@cyphar.com>

diff --git a/libcontainer/logs/logs.go b/libcontainer/logs/logs.go
index 95deb0d6..349a18ed 100644
--- a/libcontainer/logs/logs.go
+++ b/libcontainer/logs/logs.go
@@ -4,10 +4,19 @@ import (
 	"bufio"
 	"encoding/json"
 	"io"
+	"os"
 
 	"github.com/sirupsen/logrus"
 )
 
+// IsLogrusFd returns whether the provided fd matches the one that logrus is
+// currently outputting to. This should only ever be called by UnsafeCloseFrom
+// from `runc init`.
+func IsLogrusFd(fd uintptr) bool {
+	file, ok := logrus.StandardLogger().Out.(*os.File)
+	return ok && file.Fd() == fd
+}
+
 func ForwardLogs(logPipe io.ReadCloser) chan error {
 	done := make(chan error, 1)
 	s := bufio.NewScanner(logPipe)
diff --git a/libcontainer/setns_init_linux.go b/libcontainer/setns_init_linux.go
index e891773e..d1bb1227 100644
--- a/libcontainer/setns_init_linux.go
+++ b/libcontainer/setns_init_linux.go
@@ -15,6 +15,7 @@ import (
 	"github.com/opencontainers/runc/libcontainer/keys"
 	"github.com/opencontainers/runc/libcontainer/seccomp"
 	"github.com/opencontainers/runc/libcontainer/system"
+	"github.com/opencontainers/runc/libcontainer/utils"
 )
 
 // linuxSetnsInit performs the container's initialization for running a new process
@@ -117,5 +118,23 @@ func (l *linuxSetnsInit) Init() error {
 		return &os.PathError{Op: "close log pipe", Path: "fd " + strconv.Itoa(l.logFd), Err: err}
 	}
 
+	// Close all file descriptors we are not passing to the container. This is
+	// necessary because the execve target could use internal runc fds as the
+	// execve path, potentially giving access to binary files from the host
+	// (which can then be opened by container processes, leading to container
+	// escapes). Note that because this operation will close any open file
+	// descriptors that are referenced by (*os.File) handles from underneath
+	// the Go runtime, we must not do any file operations after this point
+	// (otherwise the (*os.File) finaliser could close the wrong file). See
+	// CVE-2024-21626 for more information as to why this protection is
+	// necessary.
+	//
+	// This is not needed for runc-dmz, because the extra execve(2) step means
+	// that all O_CLOEXEC file descriptors have already been closed and thus
+	// the second execve(2) from runc-dmz cannot access internal file
+	// descriptors from runc.
+	if err := utils.UnsafeCloseFrom(l.config.PassedFilesCount + 3); err != nil {
+		return err
+	}
 	return system.Exec(name, l.config.Args[0:], os.Environ())
 }
diff --git a/libcontainer/standard_init_linux.go b/libcontainer/standard_init_linux.go
index c09a7bed..d1d94352 100644
--- a/libcontainer/standard_init_linux.go
+++ b/libcontainer/standard_init_linux.go
@@ -17,6 +17,7 @@ import (
 	"github.com/opencontainers/runc/libcontainer/keys"
 	"github.com/opencontainers/runc/libcontainer/seccomp"
 	"github.com/opencontainers/runc/libcontainer/system"
+	"github.com/opencontainers/runc/libcontainer/utils"
 )
 
 type linuxStandardInit struct {
@@ -258,5 +259,23 @@ func (l *linuxStandardInit) Init() error {
 		return err
 	}
 
+	// Close all file descriptors we are not passing to the container. This is
+	// necessary because the execve target could use internal runc fds as the
+	// execve path, potentially giving access to binary files from the host
+	// (which can then be opened by container processes, leading to container
+	// escapes). Note that because this operation will close any open file
+	// descriptors that are referenced by (*os.File) handles from underneath
+	// the Go runtime, we must not do any file operations after this point
+	// (otherwise the (*os.File) finaliser could close the wrong file). See
+	// CVE-2024-21626 for more information as to why this protection is
+	// necessary.
+	//
+	// This is not needed for runc-dmz, because the extra execve(2) step means
+	// that all O_CLOEXEC file descriptors have already been closed and thus
+	// the second execve(2) from runc-dmz cannot access internal file
+	// descriptors from runc.
+	if err := utils.UnsafeCloseFrom(l.config.PassedFilesCount + 3); err != nil {
+		return err
+	}
 	return system.Exec(name, l.config.Args[0:], os.Environ())
 }
diff --git a/libcontainer/utils/utils_unix.go b/libcontainer/utils/utils_unix.go
index 220d0b43..842f9b0a 100644
--- a/libcontainer/utils/utils_unix.go
+++ b/libcontainer/utils/utils_unix.go
@@ -7,8 +7,11 @@ import (
 	"fmt"
 	"os"
 	"strconv"
+	_ "unsafe" // for go:linkname
 
 	"golang.org/x/sys/unix"
+
+	"github.com/opencontainers/runc/libcontainer/logs"
 )
 
 // EnsureProcHandle returns whether or not the given file handle is on procfs.
@@ -23,9 +26,11 @@ func EnsureProcHandle(fh *os.File) error {
 	return nil
 }
 
-// CloseExecFrom applies O_CLOEXEC to all file descriptors currently open for
-// the process (except for those below the given fd value).
-func CloseExecFrom(minFd int) error {
+type fdFunc func(fd int)
+
+// fdRangeFrom calls the passed fdFunc for each file descriptor that is open in
+// the current process.
+func fdRangeFrom(minFd int, fn fdFunc) error {
 	fdDir, err := os.Open("/proc/self/fd")
 	if err != nil {
 		return err
@@ -50,15 +55,66 @@ func CloseExecFrom(minFd int) error {
 		if fd < minFd {
 			continue
 		}
-		// Intentionally ignore errors from unix.CloseOnExec -- the cases where
-		// this might fail are basically file descriptors that have already
-		// been closed (including and especially the one that was created when
-		// os.ReadDir did the "opendir" syscall).
-		unix.CloseOnExec(fd)
+		// Ignore the file descriptor we used for readdir, as it will be closed
+		// when we return.
+		if uintptr(fd) == fdDir.Fd() {
+			continue
+		}
+		// Run the closure.
+		fn(fd)
 	}
 	return nil
 }
 
+// CloseExecFrom sets the O_CLOEXEC flag on all file descriptors greater or
+// equal to minFd in the current process.
+func CloseExecFrom(minFd int) error {
+	return fdRangeFrom(minFd, unix.CloseOnExec)
+}
+
+//go:linkname runtime_IsPollDescriptor internal/poll.IsPollDescriptor
+
+// In order to make sure we do not close the internal epoll descriptors the Go
+// runtime uses, we need to ensure that we skip descriptors that match
+// "internal/poll".IsPollDescriptor. Yes, this is a Go runtime internal thing,
+// unfortunately there's no other way to be sure we're only keeping the file
+// descriptors the Go runtime needs. Hopefully nothing blows up doing this...
+func runtime_IsPollDescriptor(fd uintptr) bool //nolint:revive
+
+// UnsafeCloseFrom closes all file descriptors greater or equal to minFd in the
+// current process, except for those critical to Go's runtime (such as the
+// netpoll management descriptors).
+//
+// NOTE: That this function is incredibly dangerous to use in most Go code, as
+// closing file descriptors from underneath *os.File handles can lead to very
+// bad behaviour (the closed file descriptor can be re-used and then any
+// *os.File operations would apply to the wrong file). This function is only
+// intended to be called from the last stage of runc init.
+func UnsafeCloseFrom(minFd int) error {
+	// We must not close some file descriptors.
+	return fdRangeFrom(minFd, func(fd int) {
+		if runtime_IsPollDescriptor(uintptr(fd)) {
+			// These are the Go runtimes internal netpoll file descriptors.
+			// These file descriptors are operated on deep in the Go scheduler,
+			// and closing those files from underneath Go can result in panics.
+			// There is no issue with keeping them because they are not
+			// executable and are not useful to an attacker anyway. Also we
+			// don't have any choice.
+			return
+		}
+		if logs.IsLogrusFd(uintptr(fd)) {
+			// Do not close the logrus output fd. We cannot exec a pipe, and
+			// the contents are quite limited (very little attacker control,
+			// JSON-encoded) making shellcode attacks unlikely.
+			return
+		}
+		// There's nothing we can do about errors from close(2), and the
+		// only likely error to be seen is EBADF which indicates the fd was
+		// already closed (in which case, we got what we wanted).
+		_ = unix.Close(fd)
+	})
+}
+
 // NewSockPair returns a new unix socket pair
 func NewSockPair(name string) (parent *os.File, child *os.File, err error) {
 	fds, err := unix.Socketpair(unix.AF_LOCAL, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
```
</details>
<details>
<summary>0994249a — init: verify after chdir that cwd is inside the container（点击展开）</summary>

```diff
commit 0994249a5ec4e363bfcf9af58a87a722e9a3a31b
Author: Aleksa Sarai <cyphar@cyphar.com>
Date:   Tue Dec 26 23:53:07 2023 +1100

    init: verify after chdir that cwd is inside the container
    
    If a file descriptor of a directory in the host's mount namespace is
    leaked to runc init, a malicious config.json could use /proc/self/fd/...
    as a working directory to allow for host filesystem access after the
    container runs. This can also be exploited by a container process if it
    knows that an administrator will use "runc exec --cwd" and the target
    --cwd (the attacker can change that cwd to be a symlink pointing to
    /proc/self/fd/... and wait for the process to exec and then snoop on
    /proc/$pid/cwd to get access to the host). The former issue can lead to
    a critical vulnerability in Docker and Kubernetes, while the latter is a
    container breakout.
    
    We can (ab)use the fact that getcwd(2) on Linux detects this exact case,
    and getcwd(3) and Go's Getwd() return an error as a result. Thus, if we
    just do os.Getwd() after chdir we can easily detect this case and error
    out.
    
    In runc 1.1, a /sys/fs/cgroup handle happens to be leaked to "runc
    init", making this exploitable. On runc main it just so happens that the
    leaked /sys/fs/cgroup gets clobbered and thus this is only consistently
    exploitable for runc 1.1.
    
    Fixes: GHSA-xr7r-f8xq-vfvv CVE-2024-21626
    Co-developed-by: lifubang <lifubang@acmcoder.com>
    Signed-off-by: lifubang <lifubang@acmcoder.com>
    [refactored the implementation and added more comments]
    Signed-off-by: Aleksa Sarai <cyphar@cyphar.com>

diff --git a/libcontainer/init_linux.go b/libcontainer/init_linux.go
index 5b88c71f..d9f18139 100644
--- a/libcontainer/init_linux.go
+++ b/libcontainer/init_linux.go
@@ -8,6 +8,7 @@ import (
 	"io"
 	"net"
 	"os"
+	"path/filepath"
 	"strings"
 	"unsafe"
 
@@ -135,6 +136,32 @@ func populateProcessEnvironment(env []string) error {
 	return nil
 }
 
+// verifyCwd ensures that the current directory is actually inside the mount
+// namespace root of the current process.
+func verifyCwd() error {
+	// getcwd(2) on Linux detects if cwd is outside of the rootfs of the
+	// current mount namespace root, and in that case prefixes "(unreachable)"
+	// to the returned string. glibc's getcwd(3) and Go's Getwd() both detect
+	// when this happens and return ENOENT rather than returning a non-absolute
+	// path. In both cases we can therefore easily detect if we have an invalid
+	// cwd by checking the return value of getcwd(3). See getcwd(3) for more
+	// details, and CVE-2024-21626 for the security issue that motivated this
+	// check.
+	//
+	// We have to use unix.Getwd() here because os.Getwd() has a workaround for
+	// $PWD which involves doing stat(.), which can fail if the current
+	// directory is inaccessible to the container process.
+	if wd, err := unix.Getwd(); errors.Is(err, unix.ENOENT) {
+		return errors.New("current working directory is outside of container mount namespace root -- possible container breakout detected")
+	} else if err != nil {
+		return fmt.Errorf("failed to verify if current working directory is safe: %w", err)
+	} else if !filepath.IsAbs(wd) {
+		// We shouldn't ever hit this, but check just in case.
+		return fmt.Errorf("current working directory is not absolute -- possible container breakout detected: cwd is %q", wd)
+	}
+	return nil
+}
+
 // finalizeNamespace drops the caps, sets the correct user
 // and working dir, and closes any leaked file descriptors
 // before executing the command inside the namespace
@@ -193,6 +220,10 @@ func finalizeNamespace(config *initConfig) error {
 			return fmt.Errorf("chdir to cwd (%q) set in config.json failed: %w", config.Cwd, err)
 		}
 	}
+	// Make sure our final working directory is inside the container.
+	if err := verifyCwd(); err != nil {
+		return err
+	}
 	if err := system.ClearKeepCaps(); err != nil {
 		return fmt.Errorf("unable to clear keep caps: %w", err)
 	}
diff --git a/libcontainer/integration/seccomp_test.go b/libcontainer/integration/seccomp_test.go
index 31092a0a..ecdfa795 100644
--- a/libcontainer/integration/seccomp_test.go
+++ b/libcontainer/integration/seccomp_test.go
@@ -13,7 +13,7 @@ import (
 	libseccomp "github.com/seccomp/libseccomp-golang"
 )
 
-func TestSeccompDenyGetcwdWithErrno(t *testing.T) {
+func TestSeccompDenySyslogWithErrno(t *testing.T) {
 	if testing.Short() {
 		return
 	}
@@ -25,7 +25,7 @@ func TestSeccompDenyGetcwdWithErrno(t *testing.T) {
 		DefaultAction: configs.Allow,
 		Syscalls: []*configs.Syscall{
 			{
-				Name:     "getcwd",
+				Name:     "syslog",
 				Action:   configs.Errno,
 				ErrnoRet: &errnoRet,
 			},
@@ -39,7 +39,7 @@ func TestSeccompDenyGetcwdWithErrno(t *testing.T) {
 	buffers := newStdBuffers()
 	pwd := &libcontainer.Process{
 		Cwd:    "/",
-		Args:   []string{"pwd"},
+		Args:   []string{"dmesg"},
 		Env:    standardEnvironment,
 		Stdin:  buffers.Stdin,
 		Stdout: buffers.Stdout,
@@ -65,17 +65,17 @@ func TestSeccompDenyGetcwdWithErrno(t *testing.T) {
 	}
 
 	if exitCode == 0 {
-		t.Fatalf("Getcwd should fail with negative exit code, instead got %d!", exitCode)
+		t.Fatalf("dmesg should fail with negative exit code, instead got %d!", exitCode)
 	}
 
-	expected := "pwd: getcwd: No such process"
+	expected := "dmesg: klogctl: No such process"
 	actual := strings.Trim(buffers.Stderr.String(), "\n")
 	if actual != expected {
 		t.Fatalf("Expected output %s but got %s\n", expected, actual)
 	}
 }
 
-func TestSeccompDenyGetcwd(t *testing.T) {
+func TestSeccompDenySyslog(t *testing.T) {
 	if testing.Short() {
 		return
 	}
@@ -85,7 +85,7 @@ func TestSeccompDenyGetcwd(t *testing.T) {
 		DefaultAction: configs.Allow,
 		Syscalls: []*configs.Syscall{
 			{
-				Name:   "getcwd",
+				Name:   "syslog",
 				Action: configs.Errno,
 			},
 		},
@@ -98,7 +98,7 @@ func TestSeccompDenyGetcwd(t *testing.T) {
 	buffers := newStdBuffers()
 	pwd := &libcontainer.Process{
 		Cwd:    "/",
-		Args:   []string{"pwd"},
+		Args:   []string{"dmesg"},
 		Env:    standardEnvironment,
 		Stdin:  buffers.Stdin,
 		Stdout: buffers.Stdout,
@@ -124,10 +124,10 @@ func TestSeccompDenyGetcwd(t *testing.T) {
 	}
 
 	if exitCode == 0 {
-		t.Fatalf("Getcwd should fail with negative exit code, instead got %d!", exitCode)
+		t.Fatalf("dmesg should fail with negative exit code, instead got %d!", exitCode)
 	}
 
-	expected := "pwd: getcwd: Operation not permitted"
+	expected := "dmesg: klogctl: Operation not permitted"
 	actual := strings.Trim(buffers.Stderr.String(), "\n")
 	if actual != expected {
 		t.Fatalf("Expected output %s but got %s\n", expected, actual)
```
</details>
<details>
<summary>683ad2ff — libcontainer: mark all non-stdio fds O_CLOEXEC before spawning init（点击展开）</summary>

```diff
commit 683ad2ff3b01fb142ece7a8b3829de17150cf688
Author: Aleksa Sarai <cyphar@cyphar.com>
Date:   Thu Dec 28 00:42:23 2023 +1100

    libcontainer: mark all non-stdio fds O_CLOEXEC before spawning init
    
    Given the core issue in GHSA-xr7r-f8xq-vfvv was that we were unknowingly
    leaking file descriptors to "runc init", it seems prudent to make sure
    we proactively prevent this in the future. The solution is to simply
    mark all non-stdio file descriptors as O_CLOEXEC before we spawn "runc
    init".
    
    For libcontainer library users, this could result in unrelated files
    being marked as O_CLOEXEC -- however (for the same reason we are doing
    this for runc), for security reasons those files should've been marked
    as O_CLOEXEC anyway.
    
    Fixes: GHSA-xr7r-f8xq-vfvv CVE-2024-21626
    Signed-off-by: Aleksa Sarai <cyphar@cyphar.com>

diff --git a/libcontainer/container_linux.go b/libcontainer/container_linux.go
index 59aa0338..40b332f9 100644
--- a/libcontainer/container_linux.go
+++ b/libcontainer/container_linux.go
@@ -353,6 +353,15 @@ func (c *linuxContainer) start(process *Process) (retErr error) {
 		}()
 	}
 
+	// Before starting "runc init", mark all non-stdio open files as O_CLOEXEC
+	// to make sure we don't leak any files into "runc init". Any files to be
+	// passed to "runc init" through ExtraFiles will get dup2'd by the Go
+	// runtime and thus their O_CLOEXEC flag will be cleared. This is some
+	// additional protection against attacks like CVE-2024-21626, by making
+	// sure we never leak files to "runc init" we didn't intend to.
+	if err := utils.CloseExecFrom(3); err != nil {
+		return fmt.Errorf("unable to mark non-stdio fds as cloexec: %w", err)
+	}
 	if err := parent.start(); err != nil {
 		return fmt.Errorf("unable to start container process: %w", err)
 	}
```
</details>
<details>
<summary>b6633f48 — cgroup: plug leaks of /sys/fs/cgroup handle（点击展开）</summary>

```diff
commit b6633f48a8c970433737b9be5bfe4f25d58a5aa7
Author: Aleksa Sarai <cyphar@cyphar.com>
Date:   Tue Dec 26 23:36:51 2023 +1100

    cgroup: plug leaks of /sys/fs/cgroup handle
    
    We auto-close this file descriptor in the final exec step, but it's
    probably a good idea to not possibly leak the file descriptor to "runc
    init" (we've had issues like this in the past) especially since it is a
    directory handle from the host mount namespace.
    
    In practice, on runc 1.1 this does leak to "runc init" but on main the
    handle has a low enough file descriptor that it gets clobbered by the
    ForkExec of "runc init".
    
    OPEN_TREE_CLONE would let us protect this handle even further, but the
    performance impact of creating an anonymous mount namespace is probably
    not worth it.
    
    Also, switch to using an *os.File for the handle so if it goes out of
    scope during setup (i.e. an error occurs during setup) it will get
    cleaned up by the GC.
    
    Fixes: GHSA-xr7r-f8xq-vfvv CVE-2024-21626
    Signed-off-by: Aleksa Sarai <cyphar@cyphar.com>

diff --git a/libcontainer/cgroups/file.go b/libcontainer/cgroups/file.go
index 48b263a1..f6e1b73b 100644
--- a/libcontainer/cgroups/file.go
+++ b/libcontainer/cgroups/file.go
@@ -77,16 +77,16 @@ var (
 	// TestMode is set to true by unit tests that need "fake" cgroupfs.
 	TestMode bool
 
-	cgroupFd     int = -1
-	prepOnce     sync.Once
-	prepErr      error
-	resolveFlags uint64
+	cgroupRootHandle *os.File
+	prepOnce         sync.Once
+	prepErr          error
+	resolveFlags     uint64
 )
 
 func prepareOpenat2() error {
 	prepOnce.Do(func() {
 		fd, err := unix.Openat2(-1, cgroupfsDir, &unix.OpenHow{
-			Flags: unix.O_DIRECTORY | unix.O_PATH,
+			Flags: unix.O_DIRECTORY | unix.O_PATH | unix.O_CLOEXEC,
 		})
 		if err != nil {
 			prepErr = &os.PathError{Op: "openat2", Path: cgroupfsDir, Err: err}
@@ -97,15 +97,16 @@ func prepareOpenat2() error {
 			}
 			return
 		}
+		file := os.NewFile(uintptr(fd), cgroupfsDir)
+
 		var st unix.Statfs_t
-		if err = unix.Fstatfs(fd, &st); err != nil {
+		if err := unix.Fstatfs(int(file.Fd()), &st); err != nil {
 			prepErr = &os.PathError{Op: "statfs", Path: cgroupfsDir, Err: err}
 			logrus.Warnf("falling back to securejoin: %s", prepErr)
 			return
 		}
 
-		cgroupFd = fd
-
+		cgroupRootHandle = file
 		resolveFlags = unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS
 		if st.Type == unix.CGROUP2_SUPER_MAGIC {
 			// cgroupv2 has a single mountpoint and no "cpu,cpuacct" symlinks
@@ -132,7 +133,7 @@ func openFile(dir, file string, flags int) (*os.File, error) {
 		return openFallback(path, flags, mode)
 	}
 
-	fd, err := unix.Openat2(cgroupFd, relPath,
+	fd, err := unix.Openat2(int(cgroupRootHandle.Fd()), relPath,
 		&unix.OpenHow{
 			Resolve: resolveFlags,
 			Flags:   uint64(flags) | unix.O_CLOEXEC,
@@ -140,20 +141,20 @@ func openFile(dir, file string, flags int) (*os.File, error) {
 		})
 	if err != nil {
 		err = &os.PathError{Op: "openat2", Path: path, Err: err}
-		// Check if cgroupFd is still opened to cgroupfsDir
+		// Check if cgroupRootHandle is still opened to cgroupfsDir
 		// (happens when this package is incorrectly used
 		// across the chroot/pivot_root/mntns boundary, or
 		// when /sys/fs/cgroup is remounted).
 		//
 		// TODO: if such usage will ever be common, amend this
-		// to reopen cgroupFd and retry openat2.
-		fdStr := strconv.Itoa(cgroupFd)
+		// to reopen cgroupRootHandle and retry openat2.
+		fdStr := strconv.Itoa(int(cgroupRootHandle.Fd()))
 		fdDest, _ := os.Readlink("/proc/self/fd/" + fdStr)
 		if fdDest != cgroupfsDir {
-			// Wrap the error so it is clear that cgroupFd
+			// Wrap the error so it is clear that cgroupRootHandle
 			// is opened to an unexpected/wrong directory.
-			err = fmt.Errorf("cgroupFd %s unexpectedly opened to %s != %s: %w",
-				fdStr, fdDest, cgroupfsDir, err)
+			err = fmt.Errorf("cgroupRootHandle %d unexpectedly opened to %s != %s: %w",
+				cgroupRootHandle.Fd(), fdDest, cgroupfsDir, err)
 		}
 		return nil, err
 	}
```
</details>
<details>
<summary>fbe3eed1 — setns init: do explicit lookup of execve argument early（点击展开）</summary>

```diff
commit fbe3eed1e568a376f371d2ced1b4ac16b7d7adde
Author: Aleksa Sarai <cyphar@cyphar.com>
Date:   Fri Jan 5 01:42:32 2024 +1100

    setns init: do explicit lookup of execve argument early
    
    (This is a partial backport of a minor change included in commit
    dac41717465462b21fab5b5942fe4cb3f47d7e53.)
    
    This mirrors the logic in standard_init_linux.go, and also ensures that
    we do not call exec.LookPath in the final execve step.
    
    While this is okay for regular binaries, it seems exec.LookPath calls
    os.Getenv which tries to emit a log entry to the test harness when
    running in "go test" mode. In a future patch (in order to fix
    CVE-2024-21626), we will close all of the file descriptors immediately
    before execve, which would mean the file descriptor for test harness
    logging would be closed at execve time. So, moving exec.LookPath earlier
    is necessary.
    
    Ref: dac417174654 ("runc-dmz: reduce memfd binary cloning cost with small C binary")
    Signed-off-by: Aleksa Sarai <cyphar@cyphar.com>

diff --git a/libcontainer/setns_init_linux.go b/libcontainer/setns_init_linux.go
index 09ab552b..e891773e 100644
--- a/libcontainer/setns_init_linux.go
+++ b/libcontainer/setns_init_linux.go
@@ -4,6 +4,7 @@ import (
 	"errors"
 	"fmt"
 	"os"
+	"os/exec"
 	"strconv"
 
 	"github.com/opencontainers/selinux/go-selinux"
@@ -82,6 +83,21 @@ func (l *linuxSetnsInit) Init() error {
 	if err := apparmor.ApplyProfile(l.config.AppArmorProfile); err != nil {
 		return err
 	}
+
+	// Check for the arg before waiting to make sure it exists and it is
+	// returned as a create time error.
+	name, err := exec.LookPath(l.config.Args[0])
+	if err != nil {
+		return err
+	}
+	// exec.LookPath in Go < 1.20 might return no error for an executable
+	// residing on a file system mounted with noexec flag, so perform this
+	// extra check now while we can still return a proper error.
+	// TODO: remove this once go < 1.20 is not supported.
+	if err := eaccess(name); err != nil {
+		return &os.PathError{Op: "eaccess", Path: name, Err: err}
+	}
+
 	// Set seccomp as close to execve as possible, so as few syscalls take
 	// place afterward (reducing the amount of syscalls that users need to
 	// enable in their seccomp profiles).
@@ -101,5 +117,5 @@ func (l *linuxSetnsInit) Init() error {
 		return &os.PathError{Op: "close log pipe", Path: "fd " + strconv.Itoa(l.logFd), Err: err}
 	}
 
-	return system.Execv(l.config.Args[0], l.config.Args[0:], os.Environ())
+	return system.Exec(name, l.config.Args[0:], os.Environ())
 }
```
</details>
<details>
<summary>e9665f4d — init: don't special-case logrus fds（点击展开）</summary>

```diff
commit e9665f4d606b64bf9c4652ab2510da368bfbd951
Author: Aleksa Sarai <cyphar@cyphar.com>
Date:   Sat Jan 20 16:56:38 2024 +1100

    init: don't special-case logrus fds
    
    We close the logfd before execve so there's no need to special case it.
    In addition, it turns out that (*os.File).Fd() doesn't handle the case
    where the file was closed and so it seems suspect to use that kind of
    check.
    
    Signed-off-by: Aleksa Sarai <cyphar@cyphar.com>

diff --git a/libcontainer/logs/logs.go b/libcontainer/logs/logs.go
index 349a18ed..95deb0d6 100644
--- a/libcontainer/logs/logs.go
+++ b/libcontainer/logs/logs.go
@@ -4,19 +4,10 @@ import (
 	"bufio"
 	"encoding/json"
 	"io"
-	"os"
 
 	"github.com/sirupsen/logrus"
 )
 
-// IsLogrusFd returns whether the provided fd matches the one that logrus is
-// currently outputting to. This should only ever be called by UnsafeCloseFrom
-// from `runc init`.
-func IsLogrusFd(fd uintptr) bool {
-	file, ok := logrus.StandardLogger().Out.(*os.File)
-	return ok && file.Fd() == fd
-}
-
 func ForwardLogs(logPipe io.ReadCloser) chan error {
 	done := make(chan error, 1)
 	s := bufio.NewScanner(logPipe)
diff --git a/libcontainer/utils/utils_unix.go b/libcontainer/utils/utils_unix.go
index 842f9b0a..bf3237a2 100644
--- a/libcontainer/utils/utils_unix.go
+++ b/libcontainer/utils/utils_unix.go
@@ -10,8 +10,6 @@ import (
 	_ "unsafe" // for go:linkname
 
 	"golang.org/x/sys/unix"
-
-	"github.com/opencontainers/runc/libcontainer/logs"
 )
 
 // EnsureProcHandle returns whether or not the given file handle is on procfs.
@@ -102,12 +100,6 @@ func UnsafeCloseFrom(minFd int) error {
 			// don't have any choice.
 			return
 		}
-		if logs.IsLogrusFd(uintptr(fd)) {
-			// Do not close the logrus output fd. We cannot exec a pipe, and
-			// the contents are quite limited (very little attacker control,
-			// JSON-encoded) making shellcode attacks unlikely.
-			return
-		}
 		// There's nothing we can do about errors from close(2), and the
 		// only likely error to be seen is EBADF which indicates the fd was
 		// already closed (in which case, we got what we wanted).
```
</details>
<details>
<summary>506552a8 — Fix File to Close（点击展开）</summary>

```diff
commit 506552a88bd3455e80a9b3829568e94ec0160309
Author: hang.jiang <hang.jiang@daocloud.io>
Date:   Fri Sep 1 16:17:13 2023 +0800

    Fix File to Close
    
    (This is a cherry-pick of 937ca107c3d22da77eb8e8030f2342253b980980.)
    
    Signed-off-by: hang.jiang <hang.jiang@daocloud.io>
    Fixes: GHSA-xr7r-f8xq-vfvv CVE-2024-21626
    Signed-off-by: Aleksa Sarai <cyphar@cyphar.com>

diff --git a/libcontainer/cgroups/fs/paths.go b/libcontainer/cgroups/fs/paths.go
index 1092331b..2cb970a3 100644
--- a/libcontainer/cgroups/fs/paths.go
+++ b/libcontainer/cgroups/fs/paths.go
@@ -83,6 +83,7 @@ func tryDefaultCgroupRoot() string {
 	if err != nil {
 		return ""
 	}
+	defer dir.Close()
 	names, err := dir.Readdirnames(1)
 	if err != nil {
 		return ""
diff --git a/update.go b/update.go
index 9ce5a2e8..6d582ddd 100644
--- a/update.go
+++ b/update.go
@@ -174,6 +174,7 @@ other options are ignored.
 				if err != nil {
 					return err
 				}
+				defer f.Close()
 			}
 			err = json.NewDecoder(f).Decode(&r)
 			if err != nil {
```
</details>
---

## CVE-2024-45310 — os.MkdirAll TOCTOU：在宿主任意位置创建空文件/目录

- **GHSA:** GHSA-jfvp-7x6p-h2pv（CVSS 3.6，低危，但无 user-ns 场景危害更大）
- **修复版本:** 1.1.14 与 1.2.0-rc.3（2024-09-03）
- **机制:** 两个容器共享卷时，针对 `os.MkdirAll` 的 TOCTOU 竞争可诱使 runc 在宿主文件系统任意位置创建**空文件或目录**（不截断已有文件）。攻击者需能使用自定义卷配置启动容器；runc、Docker、Kubernetes 均可直接利用。用户命名空间会限制影响范围但不完全阻止。
- **防御/修复:** 把 MkdirAll 限定在 rootfs 内部（安全路径解析后创建），并新增 CI lint 禁止使用 `os.Create`。由 Aleksa Sarai 修复。
- **修复 commit:** `63c29081`（rootfs: try to scope MkdirAll to stay inside the rootfs，PR #4359）；1.1 backport `f0b652ea`、`8781993`；CI lint `29e1e181`。

```diff
commit 63c2908164f3a1daea455bf5bcd8d363d70328c7
Author: Aleksa Sarai <cyphar@cyphar.com>
Date:   Tue Jul 2 20:58:43 2024 +1000

    rootfs: try to scope MkdirAll to stay inside the rootfs
    
    While we use SecureJoin to try to make all of our target paths inside
    the container safe, SecureJoin is not safe against an attacker than can
    change the path after we "resolve" it.
    
    os.MkdirAll can inadvertently follow symlinks and thus an attacker could
    end up tricking runc into creating empty directories on the host (note
    that the container doesn't get access to these directories, and the host
    just sees empty directories). However, this could potentially cause DoS
    issues by (for instance) creating a directory in a conf.d directory for
    a daemon that doesn't handle subdirectories properly.
    
    In addition, the handling for creating file bind-mounts did a plain
    open(O_CREAT) on the SecureJoin'd path, which is even more obviously
    unsafe (luckily we didn't use O_TRUNC, or this bug could've allowed an
    attacker to cause data loss...). Regardless of the symlink issue,
    opening an untrusted file could result in a DoS if the file is a hung
    tty or some other "nasty" file. We can use mknodat to safely create a
    regular file without opening anything anyway (O_CREAT|O_EXCL would also
    work but it makes the logic a bit more complicated, and we don't want to
    open the file for any particular reason anyway).
    
    libpathrs[1] is the long-term solution for these kinds of problems, but
    for now we can patch this particular issue by creating a more restricted
    MkdirAll that refuses to resolve symlinks and does the creation using
    file descriptors. This is loosely based on a more secure version that
    filepath-securejoin now has[2] and will be added to libpathrs soon[3].
    
    [1]: https://github.com/openSUSE/libpathrs
    [2]: https://github.com/cyphar/filepath-securejoin/releases/tag/v0.3.0
    [3]: https://github.com/openSUSE/libpathrs/issues/10
    
    Fixes: CVE-2024-45310
    Signed-off-by: Aleksa Sarai <cyphar@cyphar.com>

diff --git a/libcontainer/rootfs_linux.go b/libcontainer/rootfs_linux.go
index 16878274..f5112398 100644
--- a/libcontainer/rootfs_linux.go
+++ b/libcontainer/rootfs_linux.go
@@ -313,7 +313,7 @@ func mountCgroupV1(m *configs.Mount, c *mountConfig) error {
 			// inside the tmpfs, so we don't want to resolve symlinks).
 			subsystemPath := filepath.Join(c.root, b.Destination)
 			subsystemName := filepath.Base(b.Destination)
-			if err := os.MkdirAll(subsystemPath, 0o755); err != nil {
+			if err := utils.MkdirAllInRoot(c.root, subsystemPath, 0o755); err != nil {
 				return err
 			}
 			if err := utils.WithProcfd(c.root, b.Destination, func(dstFd string) error {
@@ -505,15 +505,26 @@ func createMountpoint(rootfs string, m mountEntry) (string, error) {
 				return "", fmt.Errorf("%w: file bind mount over rootfs", errRootfsToFile)
 			}
 			// Make the parent directory.
-			if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
+			destDir, destBase := filepath.Split(dest)
+			destDirFd, err := utils.MkdirAllInRootOpen(rootfs, destDir, 0o755)
+			if err != nil {
 				return "", fmt.Errorf("make parent dir of file bind-mount: %w", err)
 			}
-			// Make the target file.
-			f, err := os.OpenFile(dest, os.O_CREATE, 0o755)
-			if err != nil {
-				return "", fmt.Errorf("create target of file bind-mount: %w", err)
+			defer destDirFd.Close()
+			// Make the target file. We want to avoid opening any file that is
+			// already there because it could be a "bad" file like an invalid
+			// device or hung tty that might cause a DoS, so we use mknodat.
+			// destBase does not contain any "/" components, and mknodat does
+			// not follow trailing symlinks, so we can safely just call mknodat
+			// here.
+			if err := unix.Mknodat(int(destDirFd.Fd()), destBase, unix.S_IFREG|0o644, 0); err != nil {
+				// If we get EEXIST, there was already an inode there and
+				// we can consider that a success.
+				if !errors.Is(err, unix.EEXIST) {
+					err = &os.PathError{Op: "mknod regular file", Path: dest, Err: err}
+					return "", fmt.Errorf("create target of file bind-mount: %w", err)
+				}
 			}
-			_ = f.Close()
 			// Nothing left to do.
 			return dest, nil
 		}
@@ -532,7 +543,7 @@ func createMountpoint(rootfs string, m mountEntry) (string, error) {
 		}
 	}
 
-	if err := os.MkdirAll(dest, 0o755); err != nil {
+	if err := utils.MkdirAllInRoot(rootfs, dest, 0o755); err != nil {
 		return "", err
 	}
 	return dest, nil
@@ -565,7 +576,7 @@ func mountToRootfs(c *mountConfig, m mountEntry) error {
 		} else if !fi.IsDir() {
 			return fmt.Errorf("filesystem %q must be mounted on ordinary directory", m.Device)
 		}
-		if err := os.MkdirAll(dest, 0o755); err != nil {
+		if err := utils.MkdirAllInRoot(rootfs, dest, 0o755); err != nil {
 			return err
 		}
 		// Selinux kernels do not support labeling of /proc or /sys.
@@ -928,7 +939,7 @@ func createDeviceNode(rootfs string, node *devices.Device, bind bool) error {
 	if dest == rootfs {
 		return fmt.Errorf("%w: mknod over rootfs", errRootfsToFile)
 	}
-	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
+	if err := utils.MkdirAllInRoot(rootfs, filepath.Dir(dest), 0o755); err != nil {
 		return err
 	}
 	if bind {
diff --git a/libcontainer/system/linux.go b/libcontainer/system/linux.go
index 7bbf92a3..27e89d63 100644
--- a/libcontainer/system/linux.go
+++ b/libcontainer/system/linux.go
@@ -6,7 +6,9 @@ import (
 	"fmt"
 	"io"
 	"os"
+	"runtime"
 	"strconv"
+	"strings"
 	"syscall"
 	"unsafe"
 
@@ -214,3 +216,42 @@ func SetLinuxPersonality(personality int) error {
 	}
 	return nil
 }
+
+func prepareAt(dir *os.File, path string) (int, string) {
+	if dir == nil {
+		return unix.AT_FDCWD, path
+	}
+
+	// Rather than just filepath.Join-ing path here, do it manually so the
+	// error and handle correctly indicate cases like path=".." as being
+	// relative to the correct directory. The handle.Name() might end up being
+	// wrong but because this is (currently) only used in MkdirAllInRoot, that
+	// isn't a problem.
+	dirName := dir.Name()
+	if !strings.HasSuffix(dirName, "/") {
+		dirName += "/"
+	}
+	fullPath := dirName + path
+
+	return int(dir.Fd()), fullPath
+}
+
+func Openat(dir *os.File, path string, flags int, mode uint32) (*os.File, error) {
+	dirFd, fullPath := prepareAt(dir, path)
+	fd, err := unix.Openat(dirFd, path, flags, mode)
+	if err != nil {
+		return nil, &os.PathError{Op: "openat", Path: fullPath, Err: err}
+	}
+	runtime.KeepAlive(dir)
+	return os.NewFile(uintptr(fd), fullPath), nil
+}
+
+func Mkdirat(dir *os.File, path string, mode uint32) error {
+	dirFd, fullPath := prepareAt(dir, path)
+	err := unix.Mkdirat(dirFd, path, mode)
+	if err != nil {
+		err = &os.PathError{Op: "mkdirat", Path: fullPath, Err: err}
+	}
+	runtime.KeepAlive(dir)
+	return err
+}
diff --git a/libcontainer/utils/utils_unix.go b/libcontainer/utils/utils_unix.go
index 6bf9102f..1f3439b7 100644
--- a/libcontainer/utils/utils_unix.go
+++ b/libcontainer/utils/utils_unix.go
@@ -3,6 +3,7 @@
 package utils
 
 import (
+	"errors"
 	"fmt"
 	"math"
 	"os"
@@ -13,6 +14,8 @@ import (
 	"sync"
 	_ "unsafe" // for go:linkname
 
+	"github.com/opencontainers/runc/libcontainer/system"
+
 	securejoin "github.com/cyphar/filepath-securejoin"
 	"github.com/sirupsen/logrus"
 	"golang.org/x/sys/unix"
@@ -275,3 +278,112 @@ func IsLexicallyInRoot(root, path string) bool {
 	}
 	return strings.HasPrefix(path, root)
 }
+
+// MkdirAllInRootOpen attempts to make
+//
+//	path, _ := securejoin.SecureJoin(root, unsafePath)
+//	os.MkdirAll(path, mode)
+//	os.Open(path)
+//
+// safer against attacks where components in the path are changed between
+// SecureJoin returning and MkdirAll (or Open) being called. In particular, we
+// try to detect any symlink components in the path while we are doing the
+// MkdirAll.
+//
+// NOTE: Unlike os.MkdirAll, mode is not Go's os.FileMode, it is the unix mode
+// (the suid/sgid/sticky bits are not the same as for os.FileMode).
+//
+// NOTE: If unsafePath is a subpath of root, we assume that you have already
+// called SecureJoin and so we use the provided path verbatim without resolving
+// any symlinks (this is done in a way that avoids symlink-exchange races).
+// This means that the path also must not contain ".." elements, otherwise an
+// error will occur.
+//
+// This is a somewhat less safe alternative to
+// <https://github.com/cyphar/filepath-securejoin/pull/13>, but it should
+// detect attempts to trick us into creating directories outside of the root.
+// We should migrate to securejoin.MkdirAll once it is merged.
+func MkdirAllInRootOpen(root, unsafePath string, mode uint32) (_ *os.File, Err error) {
+	// If the path is already "within" the root, use it verbatim.
+	fullPath := unsafePath
+	if !IsLexicallyInRoot(root, unsafePath) {
+		var err error
+		fullPath, err = securejoin.SecureJoin(root, unsafePath)
+		if err != nil {
+			return nil, err
+		}
+	}
+	subPath, err := filepath.Rel(root, fullPath)
+	if err != nil {
+		return nil, err
+	}
+
+	// Check for any silly mode bits.
+	if mode&^0o7777 != 0 {
+		return nil, fmt.Errorf("tried to include non-mode bits in MkdirAll mode: 0o%.3o", mode)
+	}
+
+	currentDir, err := os.OpenFile(root, unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
+	if err != nil {
+		return nil, fmt.Errorf("open root handle: %w", err)
+	}
+	defer func() {
+		if Err != nil {
+			currentDir.Close()
+		}
+	}()
+
+	for _, part := range strings.Split(subPath, string(filepath.Separator)) {
+		switch part {
+		case "", ".":
+			// Skip over no-op components.
+			continue
+		case "..":
+			return nil, fmt.Errorf("possible breakout detected: found %q component in SecureJoin subpath %s", part, subPath)
+		}
+
+		nextDir, err := system.Openat(currentDir, part, unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
+		switch {
+		case err == nil:
+			// Update the currentDir.
+			_ = currentDir.Close()
+			currentDir = nextDir
+
+		case errors.Is(err, unix.ENOTDIR):
+			// This might be a symlink or some other random file. Either way,
+			// error out.
+			return nil, fmt.Errorf("cannot mkdir in %s/%s: %w", currentDir.Name(), part, unix.ENOTDIR)
+
+		case errors.Is(err, os.ErrNotExist):
+			// Luckily, mkdirat will not follow trailing symlinks, so this is
+			// safe to do as-is.
+			if err := system.Mkdirat(currentDir, part, mode); err != nil {
+				return nil, err
+			}
+			// Open the new directory. There is a race here where an attacker
+			// could swap the directory with a different directory, but
+			// MkdirAll's fuzzy semantics mean we don't care about that.
+			nextDir, err := system.Openat(currentDir, part, unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
+			if err != nil {
+				return nil, fmt.Errorf("open newly created directory: %w", err)
+			}
+			// Update the currentDir.
+			_ = currentDir.Close()
+			currentDir = nextDir
+
+		default:
+			return nil, err
+		}
+	}
+	return currentDir, nil
+}
+
+// MkdirAllInRoot is a wrapper around MkdirAllInRootOpen which closes the
+// returned handle, for callers that don't need to use it.
+func MkdirAllInRoot(root, unsafePath string, mode uint32) error {
+	f, err := MkdirAllInRootOpen(root, unsafePath, mode)
+	if err == nil {
+		_ = f.Close()
+	}
+	return err
+}
```
---

# 二、非 runc 仓库的 CVE（修复在其他项目，仅列版本/机制/修复 commit 链接）

> 以下 CVE 的修复不在 opencontainers/runc 仓库中。**containerd 的两个（15257 / 43816）已在
> 本地 containerd 克隆补全完整 git diff，并已在 `ctf-learn` 分支回退（见第三部分）**。
> 其余项目的修复仅列版本/机制/修复 commit 链接（可直接访问 GitHub 查看 diff），暂未回退。

## CVE-2018-15664 — Docker `docker cp` 符号链接交换 TOCTOU

- **项目:** Docker / Moby
- **修复版本:** Docker 18.09.2（2019-02-11）
- **机制:** `docker cp` 背后的 archive 接口存在 TOCTOU 符号链接竞争，攻击者可对宿主任意文件做读写（目录穿越 + 符号链接交换）。
- **防御/修复:** 在 chroot 内执行 Tar/Untar，杜绝符号链接逃逸。
- **修复 commit:** https://github.com/moby/moby/commit/364f9bce16e8c95c79fc68d23867e871f20cb452 （PR #39292）

## CVE-2020-15257 — containerd-shim 抽象 socket 暴露

- **项目:** containerd
- **修复版本:** containerd 1.3.9 / 1.4.3（2020-11-30）
- **机制:** containerd-shim 的 API 使用 **abstract Unix socket**（`\x00/containerd-shim/<hash>.sock`）。abstract socket 没有文件系统路径与权限保护，绑定在创建进程所在**网络命名空间**上。shim 跑在宿主网络命名空间，因此容器以 `--net=host` 运行且为 root（仅校验 euid==0）时，可连接宿主 shim 的 ttrpc API，使新进程以宿主上的高权限执行。
- **防御/修复:** shim 改用**基于文件系统路径的 unix socket**（`unix:///run/containerd/s/<hash>`，目录 0700、socket 0600 权限），不再使用 abstract socket，容器无法再通过共享的网络命名空间触达。
- **修复 commit:** https://github.com/containerd/containerd/commit/4a4bb851f5da563ff6e68a83dc837c7699c469ad （merge，GHSA-36xw-fx78-c5r4，共改 11 个文件）

```diff
diff --git a/runtime/v2/shim/util_unix.go b/runtime/v2/shim/util_unix.go
--- a/runtime/v2/shim/util_unix.go
+++ b/runtime/v2/shim/util_unix.go
@@ -63,20 +66,21 @@ func AdjustOOMScore(pid int) error {
 	return nil
 }
 
-// SocketAddress returns an abstract socket address
-func SocketAddress(ctx context.Context, id string) (string, error) {
+const socketRoot = "/run/containerd"
+
+// SocketAddress returns a socket address
+func SocketAddress(ctx context.Context, socketPath, id string) (string, error) {
 	ns, err := namespaces.NamespaceRequired(ctx)
 	if err != nil {
 		return "", err
 	}
-	d := sha256.Sum256([]byte(filepath.Join(ns, id)))
-	return filepath.Join(string(filepath.Separator), "containerd-shim", fmt.Sprintf("%x.sock", d)), nil
+	d := sha256.Sum256([]byte(filepath.Join(socketPath, ns, id)))
+	return fmt.Sprintf("unix://%s/%x", filepath.Join(socketRoot, "s"), d), nil
 }
 
-// AnonDialer returns a dialer for an abstract socket
+// AnonDialer returns a dialer for a socket
 func AnonDialer(address string, timeout time.Duration) (net.Conn, error) {
-	address = strings.TrimPrefix(address, "unix://")
-	return dialer.Dialer("\x00"+address, timeout)
+	return dialer.Dialer(socket(address).path(), timeout)
 }
 
 // NewSocket returns a new socket
 func NewSocket(address string) (*net.UnixListener, error) {
-	if len(address) > 106 {
-		return nil, errors.Errorf("%q: unix socket path too long (> 106)", address)
+	var (
+		sock = socket(address)
+		path = sock.path()
+	)
+	if !sock.isAbstract() {
+		if err := os.MkdirAll(filepath.Dir(path), 0600); err != nil {
+			return nil, errors.Wrapf(err, "%s", path)
+		}
 	}
-	l, err := net.Listen("unix", "\x00"+address)
+	l, err := net.Listen("unix", path)
 	if err != nil {
-		return nil, errors.Wrapf(err, "failed to listen to abstract unix socket %q", address)
+		return nil, err
+	}
+	if err := os.Chmod(path, 0600); err != nil {
+		os.Remove(sock.path())
+		l.Close()
+		return nil, err
 	}
 	return l.(*net.UnixListener), nil
 }
```

> 核心变化：`SocketAddress` 从返回 abstract 地址改为返回 `unix:///run/containerd/s/<hash>`；
> `NewSocket` 由直接 `net.Listen("unix", "\x00"+addr)` 改为先建目录、`net.Listen` 路径 socket
> 再 `chmod 0600`（新增 `socket` 类型同时保留 abstract 兼容）。其余 9 个文件的改动是把
> `runtime/v2/runc/v1·v2/service.go`、`cmd/containerd-shim/main_unix.go` 等调用方从
> "abstract socket" 语义改为"路径 socket"语义。

## CVE-2021-20199 — rootless Podman 网络伪造

- **项目:** Podman / rootlesskit
- **修复版本:** Podman 3.0.0；rootlesskit PR #206
- **机制:** rootless Podman 中所有到达容器的流量看起来都来自 127.0.0.1（即使来自远端主机），容器内信任 localhost 的应用（如跳过认证）可被远程攻击者访问。
- **防御/修复:** 区分转发流量与本地流量，不再把远端流量伪装成本地回环。
- **修复 commit:** https://github.com/containers/podman/pull/9052 、https://github.com/rootless-containers/rootlesskit/pull/206

## CVE-2021-43816 — containerd CRI hostPath SELinux 重标记

- **项目:** containerd（CRI 实现）
- **修复版本:** containerd 1.5.9 / 1.6.0（2022-01-06）
- **机制:** 启用 SELinux 时，CRI 会把挂载源按容器 `mountLabel` 重标记。修复前 CRI 对所有 bind mount（**含用户指定的 hostPath 卷**）都重标记，hostPath 获得容器 SELinux 标签 → 容器获得对宿主任意文件的全读写，绕过 SELinux 隔离。
- **防御/修复:** 只对 CRI 自己管理的 `/etc` 挂载（`/etc/hosts`、`/etc/hostname`、`/etc/resolv.conf`）保留重标记，**用户 hostPath 卷不再重标记**（通过给 CRI 管理的挂载加 `SelinuxRelabel: true` 标志，`WithMounts` 只对带此标志的挂载调 `label.Relabel`）。
- **修复 commit:** https://github.com/containerd/containerd/commit/9b0303913fcfa297f984d954c718541cf474107b （"only relabel cri managed host mounts"；GHSA-mvff-h3cj-wj9c，merge `1407cab50`）
  > 注意：diff.md 早期引用的 `a7310392`（2021-01 "[cri] label etc files for selinux containers"）是**前置相关改动**（给 /etc 挂载加 `WithRelabeledContainerMounts`），并非本 CVE 的修复 commit。

```diff
diff --git a/pkg/cri/opts/spec_linux.go b/pkg/cri/opts/spec_linux.go
--- a/pkg/cri/opts/spec_linux.go
+++ b/pkg/cri/opts/spec_linux.go
@@ -224,30 +224,6 @@ func WithMounts(osi osinterface.OS, config *runtime.ContainerConfig, extra []*ru
 	}
 }
 
-const (
-	etcHosts       = "/etc/hosts"
-	etcHostname    = "/etc/hostname"
-	resolvConfPath = "/etc/resolv.conf"
-)
-
-// WithRelabeledContainerMounts relabels the default container mounts for files in /etc
-func WithRelabeledContainerMounts(mountLabel string) oci.SpecOpts {
-	return func(ctx context.Context, client oci.Client, _ *containers.Container, s *runtimespec.Spec) (err error) {
-		if mountLabel == "" {
-			return nil
-		}
-		for _, m := range s.Mounts {
-			switch m.Destination {
-			case etcHosts, etcHostname, resolvConfPath:
-				if err := label.Relabel(m.Source, mountLabel, false); err != nil {
-					return err
-				}
-			}
-		}
-		return nil
-	}
-}
-
 // Ensure mount point on which path is mounted, is shared.
 func ensureShared(path string, lookupMount func(string) (mount.Info, error)) error {
 	mountInfo, err := lookupMount(path)
diff --git a/pkg/cri/server/container_create_linux.go b/pkg/cri/server/container_create_linux.go
--- a/pkg/cri/server/container_create_linux.go
+++ b/pkg/cri/server/container_create_linux.go
@@ -68,18 +68,20 @@ func (c *criService) containerMounts(sandboxID string, config *runtime.Container
 		hostpath := c.getSandboxHostname(sandboxID)
 		if _, err := c.os.Stat(hostpath); err == nil {
 			mounts = append(mounts, &runtime.Mount{
-				ContainerPath: etcHostname,
-				HostPath:      hostpath,
-				Readonly:      securityContext.GetReadonlyRootfs(),
+				ContainerPath:  etcHostname,
+				HostPath:       hostpath,
+				Readonly:       securityContext.GetReadonlyRootfs(),
+				SelinuxRelabel: true,
 			})
 		}
 	}
 
 	if !isInCRIMounts(etcHosts, config.GetMounts()) {
 		mounts = append(mounts, &runtime.Mount{
-			ContainerPath: etcHosts,
-			HostPath:      c.getSandboxHosts(sandboxID),
-			Readonly:      securityContext.GetReadonlyRootfs(),
+			ContainerPath:  etcHosts,
+			HostPath:       c.getSandboxHosts(sandboxID),
+			Readonly:       securityContext.GetReadonlyRootfs(),
+			SelinuxRelabel: true,
 		})
 	}
 
@@ -87,9 +89,10 @@ func (c *criService) containerMounts(sandboxID string, config *runtime.Container
 	if !isInCRIMounts(resolvConfPath, config.GetMounts()) {
 		mounts = append(mounts, &runtime.Mount{
-			ContainerPath: resolvConfPath,
-			HostPath:      c.getResolvPath(sandboxID),
-			Readonly:      securityContext.GetReadonlyRootfs(),
+			ContainerPath:  resolvConfPath,
+			HostPath:       c.getResolvPath(sandboxID),
+			Readonly:       securityContext.GetReadonlyRootfs(),
+			SelinuxRelabel: true,
 		})
 	}
 
@@ -192,7 +195,7 @@ func (c *criService) containerSpec(
 	}()
 
-	specOpts = append(specOpts, customopts.WithMounts(c.os, config, extraMounts, mountLabel), customopts.WithRelabeledContainerMounts(mountLabel))
+	specOpts = append(specOpts, customopts.WithMounts(c.os, config, extraMounts, mountLabel))
```

> 核心变化：删除 `WithRelabeledContainerMounts`（对 /etc 三个文件单独重标记的 SpecOpts），
> 改为在 CRI 管理的 /etc 挂载上直接置 `SelinuxRelabel: true` 标志；`WithMounts` 内部只对
> 带 `SelinuxRelabel` 标志的挂载调 `label.Relabel`，用户 hostPath（默认不带标志）不再被
> 重标记。测试文件（`container_create_linux_test.go`）同步更新各用例期望值，已略。

## CVE-2022-0811 — CRI-O sysctl 注入 / cgroups v1 release_agent 逃逸（cr8escape）

- **项目:** CRI-O（非 runc、非 crun）
- **修复版本:** CRI-O 1.19.6 / 1.20.7 / 1.21.6 / 1.22.3 / 1.23.2（2022-03-17）
- **机制:** CRI-O 对 pod 的 sysctl 设置校验不严，攻击者可设置任意内核参数（特别是 `kernel.core_pattern` 管道到 payload），配合 cgroups v1 `release_agent` 机制，在节点上以 root 执行任意代码。
- **防御/修复:** 限制允许设置的 sysctl 白名单。
- **公告:** https://github.com/advisories/GHSA-6x2m-w449-qwx7 ；CrowdStrike 分析: https://safeguard.sh/resources/blog/cri-o-cr8escape-sysctl-injection-container-escape-cve-2022-0811

## CVE-2022-42150 — TinyLab cloud-lab 默认 seccomp 权限过宽

- **项目:** TinyLab cloud-lab / linux-lab（内核实验教学平台，非生产运行时）
- **修复版本:** 无正式发布版本（仅仓库补丁）
- **机制:** 默认 seccomp profile 权限配置不当（CWE-276），可导致容器逃逸（CVSS 10.0）。
- **防御/修复:** 收紧 `seccomp-profiles-default.json` 的默认权限。
- **说明:** NVD CPE 只列 tinylab:cloud_lab / tinylab:linux_lab，Debian runc 安全追踪器未收录此 CVE —— 与 runc 无关。

## CVE-2024-1753 — Buildah/Podman build 构建期符号链接挂载逃逸

- **项目:** Buildah / Podman build
- **修复版本:** Buildah 1.35.1 / 1.34.3 / 1.33.7 等（2024-03-18）
- **机制:** 恶意 Containerfile 在构建上下文中创建指向宿主根 `/` 的符号链接，配合 `--mount=type=bind,source=<symlink>,...` 使宿主根文件系统在 `RUN` 步骤内被挂载，即使启用 SELinux 也能获得读写（SELinux 下受限为只读枚举）。
- **防御/修复:** `GetBindMount` 用 `copier.Eval` 解析符号链接后再挂载，禁止越界。
- **修复 commit:** https://github.com/containers/buildah/commit/9de9c20ff368beb84b84fe660773d352519dc1c5 （GHSA-pmf3-c36m-g5cf）

## CVE-2024-5154 — CRI-O 挂载显示目录遍历

- **项目:** CRI-O（非 crun、非 runc）
- **修复版本:** CRI-O 1.30.1 / 1.29.5 / 1.28.7（2024-06-03）
- **机制:** 恶意容器可通过目录穿越（CWE-22）在容器内创建指向任意宿主文件的符号链接（如 `etc -> ../../../../../../root`），利用 CRI-O 展示容器挂载的功能读写宿主文件。
- **防御/修复:** 对符号链接路径做规范化校验。
- **公告:** https://github.com/cri-o/cri-o/security/advisories/GHSA-j9hf-98c3-wrm8

## CVE-2025-24965 — crun krun 处理器路径遍历

- **项目:** crun（`--runtime=krun`）
- **修复版本:** crun 1.20（2025-02-05）
- **机制:** krun handler 存在路径遍历（CWE-22）：恶意镜像通过符号链接链把 `.krun_config.json` 指向容器 rootfs 之外，诱使 krun 在宿主上创建/修改文件（复现用 `ln -s` 链到 `/tmp/BREAKOUT`，再 `podman --runtime=krun` 运行）。
- **防御/修复:** 校验 krun 配置路径不越界。
- **修复 commit:** https://github.com/containers/crun/commit/0aec82c2b686f0b1793deed43b46524fe2e8b5a7 （GHSA-f42g-r5jj-qh4j）

---

# 三、回退方法与步骤（ctf-learn 分支实操）

> 本节记录如何在各自仓库上把 **10 个已回退的 CVE**（runc 8 个 + containerd 2 个）逐个
> 回退（重新引入漏洞），用于 CTF 复现：
> - runc 8 个 —— 底座 v1.1.14（`container_all_in_one/runc` 的 `ctf-learn` 分支）
> - containerd 2 个（15257 / 43816）—— 底座当前 main（`container_all_in_one/containerd`
>   的 `ctf-learn` 分支，第 9、10 节）
>
> 其余 7 个 CVE 的修复在 podman/cri-o/buildah/crun/moby/cloud-lab，未回退。
>
> **通用流程：**
> 1. 建分支：`git checkout -b ctf-learn <底座版本>`
> 2. 每回退一个 CVE → 单独 `git commit` 一次
> 3. 在每个修改位置以 Go/C 注释标注字面量 `--CTF-learn--`
> 4. 每步验证 `go build ./...` 通过
>
> **两种回退方式：**
> - **`git revert <fix-commit>`**：修复 commit 距今较近、代码结构未大变时优先
>   （如 runc 的 43784 / 25809 / 27561 / 45310）。merge commit 需 `-m 1`；冲突时手工解决。
> - **手工编辑**：修复基于久远旧代码（如 runc 的 30465 基于 2021-04 代码、containerd 的
>   15257 基于 2020 代码，`git revert` 会大面积冲突），改为只移除"校验动作本身"，
>   保留现状代码结构。

## 1. CVE-2019-5736 — 覆盖宿主 runc 二进制

- **修复 commit：** `6635b4f0`（merge，克隆自身二进制）+ `bb7d8b1f`（后续优化）
- **方式：** 手工编辑（`git revert` 会因 nsexec.c 大量演进而冲突）
- **步骤：**
  1. `libcontainer/nsenter/nsexec.c`：删除 `extern int ensure_cloned_binary(void);`
     声明（原在 `nsexec()` 之前）。
  2. `libcontainer/nsenter/nsexec.c`：删除 `nsexec()` 内进入容器前的
     `if (ensure_cloned_binary() < 0) bail(...)` 调用块。
  3. `libcontainer/nsenter/cloned_binary.c`：**保留但不再被调用**（死代码）。
     > 注：`git rm` 该文件会被权限系统以「不可逆删除源文件」拦截；由于漏洞本质是
     > "runc 不再自克隆"，移除调用即已恢复漏洞，死代码文件不影响复现。
- **标注位置：** `nsexec.c:637`（声明处）、`nsexec.c:881`（调用处）
- **恢复后的行为：** runc init 不再把自身复制到 memfd，容器内 `/proc/self/exe`
  重新指向宿主 runc 二进制，可被容器内进程打开并覆写 → 宿主代码执行。
- **ctf-learn 分支 commit：** `d3f07061`

## 2. CVE-2019-19921 — /proc 挂载到非目录

- **修复 commit：** `3291d66b`
- **方式：** 手工编辑（修复只加了一个 `os.Lstat` 检查块，直接移除）
- **步骤：**
  1. `libcontainer/rootfs_linux.go` `mountToRootfs` 的 `case "proc", "sysfs":`
     分支中，删除挂载前的 `os.Lstat(dest)` 非目录检查块（保留随后的
     `os.MkdirAll`）。
- **标注位置：** `rootfs_linux.go:462`
- **恢复后的行为：** `mount(2)` 盲目跟随符号链接，rootfs 内 /proc 或 /sys 若为
  指向宿主目录的符号链接，挂载被重定向到任意位置。
- **ctf-learn 分支 commit：** `b0c6b155`
- **依赖说明：** 27561 是 19921 修复被 SecureJoin 破坏后的回归，两者回退顺序：
  先 27561 再 19921（后者只需删 Lstat 检查块）。

## 3. CVE-2021-30465 — 挂载符号链接交换 TOCTOU

- **修复 commit：** `0ca91f44`（2021-04，基于旧代码结构）
- **方式：** 手工编辑（`git revert` 会大面积冲突）
- **步骤：** 移除 `libcontainer/rootfs_linux.go` 中 7 处 `utils.WithProcfd(...)`
  挂载校验，改为直接对路径执行 `mount()`：
  1. `mountPropagate` — 先 `strings.HasPrefix` 拼接 `dest`，再 `mount(source, dest, ...)`
  2. `remount` — 计算 `dest` 后 `mount(source, dest, ...)`
  3. `doTmpfsCopyUp` — `SecureJoin` 得 `dest` 后 `CopyDirectory(dest+"/", ...)` + `MS_MOVE`
  4. `bindMountDeviceNode` — `mount(node.Path, dest, "", "bind", unix.MS_BIND, "")`
  5. `createDeviceNode` — `filepath.Join(rootfs, node.Path)`（去掉 `SecureJoin`）
  6. `mountCgroupV1` — `mount(source, subsystemPath, "", "cgroup", ...)`
  7. `mountCgroupV2` — `mount(m.Source, dest, "", "cgroup2", ...)` + bind 兜底
     （`c.rootlessCgroups && ENOENT` 静默放行保留，与 25809 回退叠加）
- **标注位置：** `rootfs_linux.go:271 / 308 / 366 / 725 / 1130`（5 处，另 2 处在
  `createDeviceNode` 与 `bindMountDeviceNode` 的注释附近）
- **恢复后的行为：** 无 `WithProcfd` 时 mount(2) 在调用瞬间解析路径，路径检查与
  mount 之间可被符号链接替换 → 挂载落到宿主文件系统。
- **ctf-learn 分支 commit：** `53d77881`

## 4. CVE-2021-43784 — netlink 长度整数溢出

- **修复 commit：** `d72d057b`
- **方式：** `git revert --no-commit d72d057b`（干净，无冲突）
- **步骤：**
  1. `libcontainer/container_linux.go`：`git revert` 移除 `netlinkError` 类型、
     `bootstrapData` 内 recover 兜底，签名恢复为 `(io.Reader, error)`。
  2. `libcontainer/message_linux.go`：移除 `Bytemsg.Serialize` 中
     `if l > math.MaxUint16 { panic(...) }`，并清理 `fmt`/`math` 导入。
  3. 在 `bootstrapData` 与 `Serialize` 各加 `--CTF-learn--` 注释。
- **标注位置：** `container_linux.go:2107`、`message_linux.go:55`
- **恢复后的行为：** `Value` 超过 UINT16_MAX 时 `uint16(l)` 截断，溢出的低 16 位
  被解析为控制字段（自定义挂载点、命名空间集合等）。
- **ctf-learn 分支 commit：** `5afe351f`

## 5. CVE-2023-25809 — rootless 下 /sys/fs/cgroup 可写

- **修复 commit：** `0e6b818a`
- **方式：** `git revert --no-commit 0e6b818a`（`mountCgroupV2` 与
  `tests/integration/mounts.bats` 冲突，冲突取父侧，并删除 25809 新增的 bats 用例）
- **步骤：**
  1. `libcontainer/rootfs_linux.go` `mountCgroupV2`：改回"裸 bind mount 兜底"，
     bind 源不可用时 rootless 下 `ENOENT` 静默放行（不保证 `MS_RDONLY`）。
  2. `tests/integration/mounts.bats`：移除 25809 修复新增的测试块。
- **标注位置：** `rootfs_linux.go:296`
- **恢复后的行为：** rootless 下 cgroup2 mount 失败时回退为不设 `MS_RDONLY` 的
  bind，容器可获得宿主机 user 属主 cgroup 层级的写权限。
- **ctf-learn 分支 commit：** `0c02344c`

## 6. CVE-2023-27561 — /proc、/sys 符号链接检查失效（19921 回归）

- **修复 commit：** `0abab45c`
- **方式：** `git revert --no-commit 0abab45c`（`mountToRootfs` 与
  `tests/integration/mask.bats` 冲突，取父侧）
- **步骤：**
  1. `libcontainer/rootfs_linux.go` `mountToRootfs`：`dest` 恢复为
     `createMountpoint`（`SecureJoin`）解析路径后再 `os.Lstat` 检查——由于
     SecureJoin 已跟随并消解符号链接，检查永远针对"已解析目录"而通过，形同虚设。
  2. `tests/integration/mask.bats`：移除 27561 新增的测试。
- **标注位置：** `rootfs_linux.go:457`
- **恢复后的行为：** 攻击者可在 rootfs 内把 /proc 或 /sys 替换为指向宿主目录的
  符号链接，绕过 Lstat 检查实现宿主任意 mount（19921 的防御被 SecureJoin 破坏）。
- **ctf-learn 分支 commit：** `8a3b30c6`

## 7. CVE-2024-21626 — Leaky Vessels：泄漏 fd 导致 cwd 逃逸

- **修复 commit：** `2a4ed3e7`（v1.1.12 的 merge，含 7 个 commit）
- **方式：** `git revert -m 1 2a4ed3e7`（merge 取 first-parent 侧），冲突手工解决
- **步骤（核心 4 点）：**
  1. `libcontainer/utils/utils_unix.go`：移除 execve 前的 `UnsafeCloseFrom` /
     fd 关闭逻辑（恢复 fd 泄漏）。
  2. `libcontainer/cgroups/file.go:88`：cgroup fd 恢复为**无 `O_CLOEXEC`**，
     泄漏给容器进程。
  3. `libcontainer/init_linux.go` / `setns_init_linux.go:113` /
     `standard_init_linux.go:262`：execve 前不再关闭内部 fd。
  4. `libcontainer/container_linux.go`：移除 `chdir` 后校验 cwd 是否在容器内的
     逻辑。
- **标注位置：** `cgroups/file.go:88`、`standard_init_linux.go:262`、
  `setns_init_linux.go:113`
- **恢复后的行为：** 容器内进程可通过继承的 fd（`/proc/self/fd/N`）在 execve 时
  把 `process.cwd` 指向宿主路径 → 宿主文件访问/执行宿主二进制。
- **ctf-learn 分支 commit：** `049bda6f`

## 8. CVE-2024-45310 — os.MkdirAll TOCTOU

- **修复 commit：** `f0b652ea`
- **方式：** `git revert --no-commit f0b652ea` + 手工解决冲突
- **步骤：**
  1. `libcontainer/utils/utils_unix.go`、`libcontainer/system/linux.go`：移除
     securejoin 的 `MkdirAllInRoot` / `MkdirAllInRootOpen` 封装。
  2. `libcontainer/rootfs_linux.go` `createMountpoint`：改回在 rootfs 上裸调
     `os.MkdirAll(dest, 0o755)`。
- **标注位置：** `rootfs_linux.go:437`
- **恢复后的行为：** 共享卷场景下，`MkdirAll` 的检查与创建之间存在符号链接竞争
  （TOCTOU），可在宿主文件系统任意位置创建目录/文件。
- **ctf-learn 分支 commit：** `64774e9e`

## 9. CVE-2020-15257 — shim 抽象 socket 暴露（containerd）

- **修复 commit：** merge `4a4bb851`（GHSA-36xw-fx78-c5r4，改 11 个文件）
- **方式：** 手工编辑（fix 基于 2020 代码，现代 main 已移除 `runtime/v1` 并新增
  vsock/hvsock，`git revert` 会冲突爆炸）
- **步骤（仓库：`container_all_in_one/containerd`，底座当前 main）：**
  1. `pkg/shim/util_unix.go` `CreateSocketAddress`：返回值从
     `fmt.Sprintf("unix://%s/%x", socketRoot, d)` 改回 abstract 地址
     `filepath.Join("/", "containerd-shim", fmt.Sprintf("%x.sock", d))`
     （无 `unix://` 前缀）。`pkg/shim` 的 `socket` 类型自带 abstract 支持
     （`isAbstract()` / `\x00` 前缀），`NewSocket` / `AnonDialer` / `RemoveSocket`
     自动适配，无需改调用方。默认流程中 manager 用该地址建 abstract socket 后
     通过 fd(3) 传给 shim，shim `serveListener` 继承 fd。
  2. `pkg/shim/shim_unix.go` `serveListener`：`else` 分支恢复
     `strings.TrimPrefix(path, "unix://")` + 无前缀时补 `\x00` 的 abstract 兜底
     （供独立 `-socket` / `-debug-socket` 启动模式用），长度检查移到处理后的 `p`。
  3. `cleanupSockets` 里 `RemoveSocket("unix://"+socketFlag)` 对 abstract 地址是
     无害的失败 no-op（abstract socket 随进程退出由内核回收），可不动。
- **标注位置：** `pkg/shim/util_unix.go:93`、`pkg/shim/shim_unix.go:62`
- **恢复后的行为：** shim 监听 abstract socket（绑定宿主网络命名空间），
  `--net=host` 且为 root 的容器可连接 shim 的 ttrpc API，以宿主 root 权限启动进程。
- **containerd ctf-learn 分支 commit：** `c597ac738`

## 10. CVE-2021-43816 — CRI hostPath SELinux 重标记（containerd）

- **修复 commit：** `9b0303913`（GHSA-mvff-h3cj-wj9c，merge `1407cab50`）
- **方式：** 手工编辑（单点条件反转）
- **步骤（仓库：`container_all_in_one/containerd`，底座当前 main）：**
  1. `internal/cri/opts/spec_linux_opts.go` `withMounts`：relabel 条件从
     `if mount.GetSelinuxRelabel() { ... label.Relabel(src, mountLabel, false) ... }`
     改为 `if mountLabel != "" { ... }` —— 所有 host bind mount（含用户 hostPath 卷）
     无条件按容器 `mountLabel` 重标记。（`WithMounts` 即 `withMounts` 的薄封装；
     现代代码中该文件已从 `pkg/cri/opts/` 移至 `internal/cri/opts/`。）
- **标注位置：** `internal/cri/opts/spec_linux_opts.go:204`
- **恢复后的行为：** SELinux 启用时（`mountLabel` 非空），用户 hostPath 卷被重标记为
  容器标签，容器获得对宿主任意文件的读写权限，绕过 SELinux。
- **containerd ctf-learn 分支 commit：** `0d45bff38`

---

# 附：防御思路小结（CTF 视角）

- **符号链接/挂载逃逸类（19921 / 30465 / 27561 / 45310 / 1753 / 5154）:** 核心是"解析后再校验边界"或"全程用 fd / openat2 / securejoin 在 rootfs 内解析"，堵住 TOCTOU。CTF 里重点看挂载源/目标路径是否经过 `SecureJoin`、是否校验解析结果仍在 rootfs 内。
- **宿主二进制覆盖类（5736 / 21626）:** 核心是 `/proc/self/exe` 与泄漏 fd。修复 = memfd 复制二进制 + `O_CLOEXEC` + execve 前关闭内部 fd + 校验 cwd。CTF 里常考 `runc exec` 配合 `process.cwd` 或 `/proc/self/fd/N`。
- **配置/权限校验类（25809 / 43784 / 42150 / 20199 / 0811 / 15257）:** 核心是"未校验输入即应用"（可写 cgroup、netlink 溢出、过宽 seccomp、错误信任 localhost、白名单外 sysctl、socket 未绑定网络命名空间）。
- **通用防御:** 用户命名空间（rootless）、非特权容器、`--no-new-privileges`、capability 裁剪、seccomp/apparmor 收紧、内核补丁。多数逃逸链靠"最小权限 + 命名空间隔离"就能拦下一大截。

*本文件由 runc 与 containerd 仓库 git 历史 + GitHub Security Advisory 交叉核对生成。
回退实操基于本地 clone：`container_all_in_one/runc`（底座 v1.1.14）与
`container_all_in_one/containerd`（底座 main），均在 `ctf-learn` 分支，共回退 10 个 CVE
（runc 8 + containerd 2），代码中以 `--CTF-learn--` 标注。*
