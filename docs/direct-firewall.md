# macOS Claude 直连防火墙

菜单入口：**设置 → Claude 直连防火墙**。支持查看安装状态、预览范围、安装、卸载和管理员检查实际 PF 状态。安装与卸载弹出 macOS 管理员授权框，密码仅输入系统窗口。

```bash
claudeguard firewall preview
claudeguard firewall install
claudeguard firewall status
claudeguard firewall verify
claudeguard firewall uninstall
```

## 行为

- 只在实体出口接口（`en*`、`bridge*`、`bond*`）阻断目标 IPv4/IPv6 包；不封锁 `lo0`、`utun*`。浏览器经本机 HTTP/SOCKS 代理，再由远端节点连接 Claude 的路径保留。
- 浏览器直接发往目标 IP 的连接被 PF 丢弃；不会依赖浏览器是否读取 hosts。固定网段覆盖整个网段，不区分 TCP、UDP 或其他 IP 协议。
- 规则不随出口检测成功、风险分通过、关闭防护或退出 ClaudeGuard 而解除。卸载此功能才清理其专属规则。
- 安装不替浏览器启用代理，不更改 Bettbox、系统代理、TUN、hosts 或 ClaudeGuard 的其他开关。若本机代理不可用，安装后直连访问目标将失败。
- 新增封锁地址时，仅清理指向这些目标的既有 PF 连接状态；涉及的连接会重连。不清空系统全部连接。

## 固定网段

```text
160.79.104.0/21
153.61.224.0/22
2607:6bc0::/32
```

## 域名范围

维护用户指定的 14 个完整域名的 A/AAAA 解析地址：

```text
servd-anthropic-website.b-cdn.net
anthropic.com.cdn.cloudflare.net
anthropic.auth0.com
anthropic-com.ghost.io
claude.ai
anthropic.com
claude.com
claudeusercontent.com
claudemcpcontent.com
clau.de
claudemcpclient.com
claude.dev
claude.app
datadoghq.com
```

另外维护已明确指定的四个子域名：`api.anthropic.com`、`http-intake.logs.us5.datadoghq.com`、`bridge.claudeusercontent.com`、`downloads.claude.ai`。

**PF 不支持域名通配符。** 上面的主域名不会自动枚举所有子域名。未知子域名、浏览器与本机解析结果不同、尚未观察到的 CDN 地址，均不在完整覆盖保证内；三个固定网段始终覆盖。不将本功能描述为对任意 Claude 域名的绝对断路器。

共享 CDN IP 会影响同一 IP 上其他网站的直连，且 PF 无法区分同 IP 的域名。代理节点本身若落入封锁目标也会被阻断，应先核查代理链路。经其他远端隧道出站的流量不属于物理网卡上的目标直连。

## 维护与卸载

独立 root LaunchDaemon 每 5 分钟维护地址和接口；不是常驻 Python 进程。用 `dig` 向 `1.1.1.1` 查询，失败再尝试 `8.8.8.8`，只接收公网 A/AAAA 地址。网络失败时保留旧地址；完整解析成功后，超过 24 小时未再次观察到的旧地址才过期。新网卡在下一轮维护后覆盖，期间存在窗口。

安装路径为 `/Library/Application Support/ClaudeGuard/DirectFirewall`，启动项为 `/Library/LaunchDaemons/com.claudeguard.direct-firewall.plist`。使用 `com.apple/claudeguard/direct` 子锚点、`claudeguard_direct` 表和当前启动会话自身的 PF enable token。父锚点由 ClaudeGuard 系统助手维护，在放行和阻断两种状态下都保留 `anchor "direct"`。不重载 `/etc/pf.conf`，不关闭全局 PF，不改网络共享等其他主规则。

安装前要求运行中的主规则提供 `anchor "com.apple/*"` 或 `anchor "com.apple/claudeguard"`，并要求父锚点已有 `direct` 子入口。升级系统助手后重新检测即可建立子入口；缺失时返回错误，保留其他规则，不自动替换主规则。

`status` 展示 root 写入的最近成功应用记录，不冒充实时内核检查。`verify` 经管理员授权回读 PF 启用状态、专属规则、目标表、实体接口及其 PF skip 标记。升级此功能前会在同一系统目录留下 `DirectFirewall-backup-*` 备份，卸载保留这些备份。开机时必须等系统任务首次成功加载规则；加载前、睡眠恢复、接口切换时存在窗口，真实运行效果必须通过现场检查确认。

## 验收

使用单独测试连接，核对目标 IP：代理正常时可以访问；同一目标强制直连失败；代理退出后直连仍失败；IPv4 和 IPv6 均检查。必须确认规则计数/日志与失败连接对应，网络原本不可达或 HTTP 拒绝不能充当防火墙阻断证据。测试不应发送模型请求，也不应关闭现有 Claude 会话。

只运行单元测试、PF 语法检查或看到“已安装”不能代表上述现场验收完成。
