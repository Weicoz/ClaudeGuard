# macOS DMG 发行

构建 Apple Silicon / Intel 通用包，最低 macOS 13：

```bash
python3 scripts/build-dmg.py --version 0.1.0-beta.1
```

输出位于 `dist/`：DMG 和 `SHA256SUMS`。镜像包含预编译原生程序、完整运行源码、图标、许可证、卸载脚本、安装入口和逐文件校验清单，不包含本机配置、白名单、历史、凭据或日志。

用户打开镜像后，双击 `Install ClaudeGuard.command`。它先检查负载完整性，再运行项目安装器；网络助手需要管理员权限，由用户输入密码。后台自动启动，设置按需打开；新装窗口定时任务默认禁用。该版本仍需要可用的 `/usr/bin/python3`，通常由 Xcode 命令行工具提供。

这是安装器型 DMG，不是拖拽即用的独立 App。当前构建仅使用 ad-hoc 签名，没有 Developer ID 签名或 Apple 公证；下载后的 macOS 安全检查可以阻止运行。不得把本地签名验证通过称为 Gatekeeper 或公证通过。

发行前检查：两个原生程序均包含 arm64/x86_64，代码签名结构有效；`hdiutil verify` 通过；只读挂载后逐文件核对清单和架构；单元测试、Shell/C 语法及源码差异检查通过。Intel 真机和干净系统完整安装仍未验证，因此发布为预览版。

已知系统网络助手沿用原项目的全局 pf 操作，设置交互也尚未完成手工端到端验收。具体风险见 [性能审查](performance-audit.md)。
