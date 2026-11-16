<div align="center">

# 🧊 TokenDiet

**Extreme AI Codebase Context Compressor · 极简大模型上下文压缩器**

*Zero Dependencies · Single File · Pure Python Standard Library · Safer, smaller AI context*

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python&logoColor=white)](https://python.org)
[![Dependencies](https://img.shields.io/badge/Dependencies-0%20(Standard%20Library)-brightgreen)](#)
[![Format](https://img.shields.io/badge/Prompt%20Format-Anthropic%20XML%20%7C%20Markdown-orange)](#)
[![Tests](https://img.shields.io/badge/Tests-Passing%20(27%2F27)-brightgreen)](#)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

[English](#features) · [中文文档](#-为什么需要-tokendiet) · [快速开始](#quick-start) · [Web 看板](#-zero-dependency-web-visualizer) · [架构符号树](#-architectural-symbol-map)

</div>

---

## 💡 为什么需要 TokenDiet？

当你使用 **Claude Code、Cursor、Windsurf、Aider** 等工具处理完整代码库时，常会遇到三类上下文问题：

1. **上下文冗余**：仓库里常有重复实现、生成物和与当前任务无关的细节，整库打包会挤占模型上下文。TokenDiet 提供压缩前后启发式估算；实际 Token 数与费用因模型、分词器和定价而异。
2. **实现细节过载**：大量与当前任务无关的代码可能遮住模块边界与依赖关系。压缩骨架提供另一种阅读视角，但不能保证模型推理质量。
3. **敏感凭据泄漏风险**：源码可能残留 API Key、数据库密码、内网连接串，不慎打包会增加外发风险。TokenDiet 尝试脱敏常见模式，但并非完整的 secret scanner。

**TokenDiet 的做法：**
> 生成仓库树、符号索引与压缩后的文件上下文；对指定焦点文件保留完整实现，让使用者自行选择全局结构与局部细节的取舍。

---

## ⚡ 核心特性 (Features)

- 🪶 **零第三方依赖 (Zero Dependencies)**：100% 纯 Python 标准库编写（`ast`, `re`, `http.server`, `urllib`）。无需 `pip install`，无需 `node_modules`，无需虚拟环境。
- 📦 **单文件架构 (Single File)**：核心工具仅由一个 `tokendiet.py` 驱动，随拷随用；开发测试和发布配置另有独立文件。
- 🧭 **仓库感知过滤**：按目录作用域处理常用 `.gitignore` 规则与反选，保留 `.github` 等有用的隐藏项目文件；支持额外 `--ignore` 规则。
- 🧠 **多语言结构感知骨架化**：
  - **Python**：原生 `ast` 解析，保留装饰器、函数/类签名、完整类型注解与第一行 Docstring，剥离函数体并替换为 `...  # [implementation omitted]`。
  - **TypeScript / JavaScript / Go / Java / Rust / C++ / C# / Kotlin**：括号语法感知状态机，尽量保留常见接口（`interface`）、类型（`type`）、结构体（`struct`）、类头并折叠可识别的函数体；不是完整语言解析器，复杂语法可能无法正确分类。
- 🗺️ **全局架构符号树 (Symbol Map)**：
  - 从支持语言中提取可识别的类名、函数和接口线索（`--repomap`），帮助模型快速定位关键抽象；覆盖范围取决于语法规则。
- 🎯 **聚焦模式 (Focus Mode)**：
  - `--focus src/api.py`：让匹配的文件以 `full` 模式保留，其余纳入扫描的文件按所选模式处理；搭配 `--stats` 在自己的仓库验证实际开销。
- 🧭 **Git 会话上下文 (`--changed`)**：
  - 以 `HEAD` 或指定分支/提交为基准，将已修改、暂存和未跟踪文件保留为完整内容，其他文件继续压缩；特别适合准备一次代码审查或 AI 编码会话。
- 🎚️ **动态 Token 预算控制 (`--budget N`)**：
  - 输入预算后，优先保留焦点文件，再将非焦点文件从骨架降级为符号存根。预算基于启发式估算；若焦点文件或存根本身超过预算，仍可能超出目标。
- 🛡️ **凭据风险降低与独立审计**：
  - 启发式规则可脱敏常见 GitHub、AWS、OpenAI/Anthropic、Stripe、HuggingFace、JWT、私钥、数据库 URI 与密码；默认不把 `.env` 文件放入上下文。
  - `--audit-secrets` 也会检查 `.env` 文件。检测并非完备保证，发送前仍须审查输出；启发式规则可能漏报或误报。
- 📊 **零依赖 Token 与费用估算**：
  - 纯标准库启发式估算，方便横向比较压缩效果；不是模型 tokenizer，也不承诺固定误差。可用 `--price-per-million` 设置输入 Token 参考单价（默认 `$3.00 / 1M`，仅作示例，不代表当前供应商定价）。
- 🖥️ **本地 Web 看板 (`--serve`)**：
  - 内置零依赖交互界面；默认仅绑定 `127.0.0.1`。路径和符号按文本安全渲染，API 返回的原文已应用默认脱敏。只有信任网络时才使用 `--host 0.0.0.0`。
- 📋 **跨平台剪贴板一键导出 (`-c`)**：
  - 自动适配 macOS (`pbcopy`)、Linux Wayland (`wl-copy`)、Linux X11 (`xclip`) 及 Windows/WSL (`clip.exe`)。

---

## 📊 结果如何解读

TokenDiet 不承诺适用于所有仓库的固定压缩率或 Token 精度。结果取决于项目语言、文件组成、压缩模式、焦点文件，以及目标模型的 tokenizer。先在自己的仓库运行 `--stats`，并把 `--format json` 输出用于脚本化比较；费用数字只是代码中参考单价的估算值，不是报价。

---

## 🚀 Quick Start (快速开始)

### 1. 运行方式（免安装）

直接下载单个文件即可运行：

```bash
# 方式 A：直接运行（输出 Anthropic XML 到标准输出）
python3 tokendiet.py .

# 方式 B：压缩当前目录并直接写入剪贴板（推荐日常使用）
python3 tokendiet.py . -c

# 方式 C：聚焦指定文件（核心文件全量，其他文件骨架化）
python3 tokendiet.py . --focus src/user_service.py -c

# 方式 D：Git 会话模式（变更与未跟踪文件全量，其余压缩）
python3 tokendiet.py . --changed -c

# 方式 E：相对主分支构建上下文
python3 tokendiet.py . --changed origin/main -o review.xml

# 方式 F：尝试压缩到目标 Token 预算（估算值，可能超过目标）
python3 tokendiet.py . --budget 8000 -c

# 方式 G：输出 Markdown 格式到文件
python3 tokendiet.py . --format markdown -o context.md

# 方式 H：项目凭据启发式审计（也检查 .env）
python3 tokendiet.py . --audit-secrets
```

### 2. 一键安装全局命令

```bash
# 下载至本地可执行路径
curl -fsSL https://raw.githubusercontent.com/ice-wocker/tokendiet/main/tokendiet.py -o ~/.local/bin/tokendiet
chmod +x ~/.local/bin/tokendiet

# 在任意工程根目录下直接使用
tokendiet . -c
```

---

## 🗺️ Architectural Symbol Map

想要直接了解整个代码库的核心抽象？运行 `--repomap`：

```bash
tokendiet . --repomap
```

产出清晰直观的符号架构索引：
```text
• api_service.py:
    - class User
    - class UserManager [__init__, _init_connection, get_user_by_id, update_user_status]
    - def hash_password()
• auth_manager.ts:
    - type TokenPayload
    - type AuthConfig
    - fn extractBearerToken()
    - class AuthManager
• db_pool.go:
    - type Config
    - type Database
    - type ConnectionPool
    - func NewConnectionPool()
    - func Ping()
```

---

## 🖥️ Zero-Dependency Web Visualizer

想可视化挑选要喂给 AI 的文件？无需安装 Node 或 Web 依赖，一条命令启动内置看板：

```bash
python3 tokendiet.py . --serve 8080
```

打开浏览器访问 `http://127.0.0.1:8080`。服务默认只监听本机回环地址；只有明确需要且了解代码暴露风险时才传入 `--host 0.0.0.0`。

看板提供：
- **实时文件树**：勾选/排除特定模块。
- **三档即时切换**：对任意文件随时切换 `Skeleton`（骨架）、`Compact`（紧凑）、`Full`（全量）。
- **实时收益仪表盘**：动态查看 Token 变化与节省的费用。
- **符号速览**：即时查看选中文件的导出符号列表。
- **一键导出**：一键生成 Anthropic 推荐的 XML 格式或 Markdown 格式。

---

## 📖 命令行参数详解

```text
用法: tokendiet.py [path] [选项]

位置参数:
  path                  需要扫描分析的代码库根目录 (默认: 当前目录 ".")

选项:
  -m, --mode            压缩模式: skeleton (AST 骨架, 默认) | compact (去空行/紧凑) | full (全量)
  --focus               逗号分隔的文件通配符列表，保持全量模式 (例: "src/api.py,src/auth/*")
  --changed [BASE]       Git 会话模式：变更与未跟踪文件全量，默认比较 HEAD (例: origin/main)
  -b, --budget          目标 Token 预算参考：逐级压缩非焦点文件（估算值，可能超出）
  --price-per-million   输入 Token 参考单价（USD / 1M；默认 3.00，可自定义）
  -f, --format          输出结构格式: xml (默认) | markdown | json
  -o, --output          将提示词保存到指定文件路径 (例: -o prompt.xml)
  -c, --clip            直接将生成的提示词写入系统剪贴板 (免去复制粘贴)
  --serve [port]        启动本地 Web 看板 (默认端口: 8080，仅绑定 127.0.0.1)
  --host                Web 看板绑定地址 (默认 127.0.0.1；非本机地址会暴露仓库内容)
  --stats               仅打印 Token 压缩前后数据对比与费用明细表，不输出全文
  --tree-only           仅输出当前代码库的 ASCII 架构目录树
  --repomap             仅输出全局架构符号索引树 (Symbol Map)
  --audit-secrets       扫描代码库中的敏感 Key 与凭据并报错退出
  --no-scrub            关闭敏感凭据脱敏 (危险；默认开启启发式脱敏)
  --max-size            跳过单文件体积大于 N KB 的大文件 (默认: 512KB)
  --ignore              额外排除的文件通配符规则 (可多次指定，例: --ignore "*.test.ts")
  -v, --version         打印当前版本号
```

---

## 🤖 与 AI 工具的最佳结合实践

### 1. 与 Claude Code / Cursor / Windsurf 搭配
在日常编码时，直接在终端执行：
```bash
tokendiet . --focus src/models/billing.py -c
```
在对话框中直接 `Ctrl+V` (或 `Cmd+V`) 粘贴，然后提问：
> *"我正在修改 billing.py，上面给出了整个仓库的架构和接口签名，请帮我把新的订阅计费状态同步到各个周边调用模块中。"*

此时模型可以参考目录结构、可提取的符号和压缩后的内容；符号提取与结构解析属于启发式，可能遗漏或误判，生成结果仍应结合真实代码验证。压缩比例、Token 消耗与推理效果取决于仓库、模型和任务。

---

## 🧪 单元测试

本项目自带完整的单测覆盖：

```bash
python3 -m unittest discover -s tests -v
```

当前回归套件覆盖 Gitignore 规则、Python 3.8 AST 回退、敏感凭据和 `.env` 审计、XML/Markdown/JSON 输出与 Web UI 的安全渲染。CI 在 Python 3.8–3.14 矩阵执行。

---

## 🔐 安全与边界

- 常见凭据的脱敏和审计均为启发式检测，不等同于完整 DLP、密钥管理器或安全审计；检测规则可能漏掉未知格式。
- 默认上下文扫描忽略 `.env`，但 `--audit-secrets` 会检查 `.env` / `.env.*`（文件上限 1 MiB）。
- Web 看板默认监听回环地址；共享服务器上的非本机绑定会让访问者看到扫描到的仓库上下文。
- Token 和费用都是粗略估算；严格配额请在目标模型 tokenizer 上复核。

---

## 📄 License

MIT License © 2026 [ice-wocker](https://github.com/ice-wocker)
保留极客纯粹，拒绝代码臃肿。
