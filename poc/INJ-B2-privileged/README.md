# INJ-B2 — privileged 判定失效（containerd CRI）⚠️ 需 containerd CRI 环境

**植入位置**：`containerd/internal/cri/server/container_create.go` 的 `buildLinuxSpec`。

**漏洞效果**：`if securityContext.GetPrivileged()` 判定被短路，**任何普通容器都无条件追加**
`oci.WithPrivileged`（+ `WithHostDevices`/`WithAllDevicesAllowed`）——误给全能力 + 全设备 + 无 seccomp。

> 与其他 4 个不同：B2 在 containerd 的 CRI 层，不走 standalone `runc-vuln`。
> 需要 containerd（本仓库树）+ CRI 插件 + crictl 才能复现。

## 前置

1. 用当前 `containerd/` 树构建并启动 containerd，启用 CRI 插件
   （`config.toml` 启用 CRI，参考 `containerd/script/setup/` 与官方文档）。
2. 安装 `crictl`（`curl -L https://github.com/kubernetes-sigs/cri-tools/releases/... | tar xz`）。

## 复现步骤

```bash
# 1. 拉镜像
crictl pull busybox

# 2. 建普通（非 privileged）pod —— security_context 里 privileged: false
cat > /tmp/b2-pod.yaml <<'EOF'
metadata:
  attempt: 1
  name: b2-pod
linux:
  security_context:
    privileged: false
EOF
crictl runp /tmp/b2-pod.yaml          # 记录 PODID

# 3. 建普通容器 —— 同样 privileged: false，只 sleep
cat > /tmp/b2-container.yaml <<'EOF'
metadata:
  name: b2-ctr
image:
  image: busybox
command:
  - sleep
  - "300"
linux:
  security_context:
    privileged: false
EOF
CTRID=$(crictl create "$PODID" /tmp/b2-container.yaml /tmp/b2-pod.yaml)
crictl start "$CTRID"

# 4. 验证：普通容器被误当 privileged
#    a) 能力：CapEff 应为全 1（漏洞态），正常应只有 3 项小 mask
crictl exec "$CTRID" grep CapEff /proc/self/status

#    b) 设备：/dev 应出现宿主设备节点（正常容器 /dev 只有 null/zero/...）
crictl exec "$CTRID" ls /dev | grep -E 'sda|nvme' || echo "no host devices visible"

#    c) spec 角度：inspect 应显示 privileged 相关字段/全设备
crictl inspect "$CTRID" | grep -iE 'privileged|sda' | head
```

## 期望结果（差分）

| 观察点 | 正常（修复版） | 漏洞态（B2） |
|---|---|---|
| 容器 CapEff | 仅请求的小集合 | 全 caps（`0x1ffffffffff` 等） |
| `/dev` 设备 | 仅 null/zero/tty 等 | 含 `sda`/`nvme*` 等宿主设备 |
| seccomp | 正常配置生效 | 无 seccomp |

**验证**：任一观察点显示普通容器获得特权能力/设备，即 B2 生效。

## 备注

- B2 是 k8s 历史上多次出现的"privileged 判定缺陷"最接近的真实误判植入
  （kubelet 曾因检查条件写错导致普通容器获得特权）。
- 若仅想快速看效果而不搭 CRI，可改为单测/直接调用 `buildLinuxSpec`，但
  CRI 全链路最贴近真实攻击面。
