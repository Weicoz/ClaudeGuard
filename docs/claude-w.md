# Claude-W 完整集成

Claude-W 的窗口调度、额度查询、请求历史和命令行管理已集成到 ClaudeGuard。代码来自用户维护的 [Weicoz/claude-w](https://github.com/Weicoz/claude-w)，基线提交 `0f001d1`；原项目未改动。

```bash
claudeguard window --help
claudeguard window status --cached
claudeguard window usage --cached
claudeguard window usage
claudeguard window history
claudeguard window logs
claudeguard window dry-run
claudeguard window 10:00 --dry-run
claudeguard window 10:00 -n 3
claudeguard window 10:00 -d
claudeguard window schedule tomorrow 10:00
claudeguard window cancel
claudeguard window auto
claudeguard window start
claudeguard window stop
claudeguard window poke --dry-run
claudeguard window poke
claudeguard window kill --dry-run
claudeguard window kill
claudeguard window config --expected-ip 203.0.113.10
```

最后一行是示例 IP，必须替换为用户确认的固定出口。`claude-w`、`claude-window` 和 `ckill` 保留兼容入口。原有配置、额度缓存、计划和真实请求历史继续使用 `~/.local/state/claude-window/`；安装前备份，卸载时恢复此前的兼容命令，并保留本地数据。

新安装的定时请求任务默认禁用。手动执行 `auto`、`start`、创建计划或 `poke` 可以启用任务/发起请求，并消耗订阅额度。当前用户此次迁移已选择默认关闭，因此旧定时任务也会停用；已有计划和历史保留。安装器对其他已有安装保留任务原启用状态，不会自动启动原本停止的任务。

`HH:MM` 是目标重置时间，工具反推五小时安排请求。每十分钟检查一次；错过超过二十分钟或已有活跃窗口时不补发。保留失败一小时退避、每天最多四次成功请求、周额度已用 95% 时跳过等保护。

所有官方出口/额度查询先通过 ClaudeGuard 防护，再验证原有 Bettbox TUN、固定出口和订阅 OAuth。`--cached` 和 `--dry-run` 保持离线；不会为界面刷新自动发送模型请求。额度查询使用既有本地凭据，Keychain 要求授权时由用户完成；令牌不进入命令参数、日志或缓存。

关闭进程统一由 ClaudeGuard 的原生进程控制执行。Claude-W 不再保留独立进程扫描/终止代码；旧 `kill`/`ckill` 转发到原生入口。Desktop 复用既有关闭实现，Code 按实际可执行文件与官方 Node 入口识别，排除其他用户与管理工具。实际终止会丢失未保存内容；先使用 `--dry-run` 查看范围。

设置菜单新增“额度与窗口（Claude-W）”，可查看缓存、刷新额度、查看历史、离线预演和管理计划。请求和终止动作先显示确认；完整命令行功能通过 `claudeguard window` 提供。
