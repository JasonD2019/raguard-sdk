# Changelog

## [1.0.0] - 2026-05-06

### Added
- 四大核心模块：doc_scanner, prompt_checker, recall_filter, full_check
- License 系统：在线验证 + 7 天离线宽容期
- 内置规则库：900+ 注入模式，500+ 越狱模式，518 敏感词
- 统一 RulesLoader 规则加载器
- 性能指标达标：prompt_checker ~30ms, full_check ~200ms

### Modules
- doc_scanner: PDF/DOCX/TXT/MD 文档扫描
- prompt_checker: 注入/越狱攻击检测
- recall_filter: RBAC 权限过滤
- full_check: 全链路聚合检测

## [0.1.0] - 2026-04-05

### Added
- 项目骨架搭建
- 核心模块设计
- 规则库初始化