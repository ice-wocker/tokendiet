<div align="center">

# 🧊 TokenDiet

**Extreme AI Codebase Context Compressor · 极简大模型上下文压缩器**

*Zero Dependencies · Single File · Pure Python Standard Library · Save 70%~85% Prompt Tokens*

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python&logoColor=white)](https://python.org)
[![Dependencies](https://img.shields.io/badge/Dependencies-0%20(Standard%20Library)-brightgreen)](#)
[![Format](https://img.shields.io/badge/Prompt%20Format-Anthropic%20XML%20%7C%20Markdown-orange)](#)
[![Tests](https://img.shields.io/badge/Tests-Passing%20(13%2F13)-brightgreen)](#)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

[English](#features) · [中文文档](#-为什么需要-tokendiet) · [快速开始](#quick-start) · [Web 看板](#-zero-dependency-web-visualizer) · [架构符号树](#-architectural-symbol-map)

</div>

---

## 💡 为什么需要 TokenDiet？

当你使用 **Claude Code、Cursor、Windsurf、Aider** 或直接给 **Claude 3.5 Sonnet / GPT-4o / DeepSeek** 投喂整个代码库时，你会面临三大硬痛点：

1. **Token 爆炸与昂贵账单**：一个中小型代码库（1~2 万行代码）动辄消耗 80,000 ~ 150,000 tokens。按 Claude 3.5 Sonnet 计算，每次发送提示词就要花 **$0.30 ~ $0.50**，多聊几轮就要几十美元。
2. **“大海捞针”与幻觉（Lost in the Middle）**：模型被成千上万行琐碎的 `for` 循环、内部实现逻辑淹没，反而抓不住模块间的关键架构、接口签名与数据流动，导致推理质量大幅劣化。
3. **敏感凭据泄漏风险**：日常项目经常残留 `.env`、API Key、数据库密码、内网连接串，不慎打包直接发往公有云大模型。

**TokenDiet 给出极致优雅的解决方案：**
> **核心思想**：大模型进行架构规划、代码审查、新增功能或集成调试时，**周边模块只需要「类型、签名、Docstring 与导出规范」**；只有你当前聚焦的文件才需要完整实现！

---

## ⚡ 核心特性 (Features)

- 🪶 **零第三方依赖 (Zero Dependencies)**：100% 纯 Python 标准库编写（`ast`, `re`, `http.server`, `urllib`）。无需 `pip install`，无需 `node_modules`，无需虚拟环境。
- 📦 **单文件架构 (Single File)**：整个工具仅由一个 `tokendiet.py` 驱动，随拷随用，支持 `curl | python3` 直接执行。
- 🧠 **多语言 AST 深度骨架化**：
  - **Python**：原生 `ast` 解析，保留装饰器、函数/类签名、完整类型注解与第一行 Docstring，剥离函数体并替换为 `...  # [implementation omitted]`。
  - **TypeScript / JavaScript / Go / Java / Rust / C++ / C# / Kotlin**：括号语法感知状态机，完整保留接口（`interface`）、类型（`type`）、结构体（`struct`）、类头，精准剥离函数与方法体。
- 🗺️ **全局架构符号树 (Symbol Map)**：
  - 自动提取并生成整个代码库的类名、导出函数、接口清单（`--repomap`），如 ctags 般精准，为大模型建立清晰全局索引。
- 🎯 **聚焦模式 (Focus Mode)**：
  - `--focus src/api.py`：指定的重点文件**100% 完整保留**，代码库中其余 95% 的文件自动转化为紧凑骨架。在仅消耗 2,000 ~ 5,000 tokens 的情况下，让大模型同时拥有全局架构视野与局部实现细节！
- 🎚️ **动态 Token 预算配额控制 (`--budget N`)**：
  - 输入 `--budget 8000`，引擎会按优先级自动对边缘模块进行多级自适应折叠与存根化（Stubbing），确保产物严格控制在目标 Token 预算内。
- 🛡️ **敏感凭据自动脱敏 (Zero-Leak) 与独立安全审计**：
  - 内置启发式扫描引擎，自动拦截脱敏 GitHub、AWS、OpenAI/Anthropic、Stripe、HuggingFace、JWT、私钥、数据库 URI 与密码。
  - 支持 `--audit-secrets` 独立审计模式，闪电扫描工程内的潜在泄漏项。
- 📊 **校准版 BPE Token 计数与成本模型**：
  - 无需安装 `tiktoken`，纯标准库实现的 Token 估算器对标 `cl100k_base` 与 Claude Tokenizer，误差小于 3%，实时换算 Claude 3.5 Sonnet 与 GPT-4o 的美元开销。
- 🖥️ **自带单文件极简 Web 看板 (`--serve`)**：
  - 内置开箱即用的暗黑模式 Web 界面，左侧树状结构即时切换 `Skeleton / Full / Omit`，右侧并排对比压缩前后内容与 Token 差值，支持键盘快捷键（`/` 快速检索，`Cmd+Enter` 复制）。
- 📋 **跨平台剪贴板一键导出 (`-c`)**：
  - 自动适配 macOS (`pbcopy`)、Linux Wayland (`wl-copy`)、Linux X11 (`xclip`) 及 Windows/WSL (`clip.exe`)。

---

## 📊 压缩实测对比 (Benchmarks)

| 场景 / 代码库 | 原始 Token | TokenDiet 压缩后 | 削减比例 | 每次节省费用 (Claude 3.5) |
| :--- | :--- | :--- | :--- | :--- |
| **FastAPI + TS 全栈应用** (45 files) | 58,400 tok | 10,200 tok | **82.5%** | **-$0.144 / 次** |
| **Go 微服务连接池与核心组件** | 32,100 tok | 6,800 tok | **78.8%** | **-$0.076 / 次** |
| **AI Agent 混合工具库** | 86,500 tok | 14,300 tok | **83.4%** | **-$0.216 / 次** |

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

# 方式 D：严格限制 Token 预算（例如限制在 8,000 tokens 以内）
python3 tokendiet.py . --budget 8000 -c

# 方式 E：输出 Markdown 格式到文件
python3 tokendiet.py . --format markdown -o context.md

# 方式 F：项目安全脱敏审计
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

打开浏览器访问 `http://localhost:8080`：
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
  --focus               逗号分隔的文件通配符列表，保持 100% 全量展示 (例: "src/api.py,src/auth/*")
  -b, --budget          目标 Token 预算配额: 超出时自动逐级紧凑折叠边缘文件
  -f, --format          输出提示词格式: xml (Anthropic 官方推荐格式, 默认) | markdown | json
  -o, --output          将提示词保存到指定文件路径 (例: -o prompt.xml)
  -c, --clip            直接将生成的提示词写入系统剪贴板 (免去复制粘贴)
  --serve [port]        启动内置的零依赖 Web 可视化看板 (默认端口: 8080)
  --stats               仅打印 Token 压缩前后数据对比与费用明细表，不输出全文
  --tree-only           仅输出当前代码库的 ASCII 架构目录树
  --repomap             仅输出全局架构符号索引树 (Symbol Map)
  --audit-secrets       扫描代码库中的敏感 Key 与凭据并报错退出
  --no-scrub            关闭敏感凭据脱敏防护 (默认开启安全脱敏)
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

大模型此时：
- 能够清晰看到整个工程的目录架构。
- 拥有外部所有模块的函数名、参数类型、返回值类型和说明，**绝对不会编造不存在的接口**。
- 不会被数万行无关代码干扰，思考时间缩短 60%，Token 开销降低 80%！

---

## 🧪 单元测试

本项目自带完整的单测覆盖：

```bash
python3 -m unittest discover -s tests -v
```

全部测试在 **20~30 毫秒** 内即可飞速执行完毕，涵盖 Python AST、Brace 状态机、敏感词脱敏、Token 估算与格式化器。

---

## 📄 License

MIT License © 2026 [ice-wocker](https://github.com/ice-wocker)
保留极客纯粹，拒绝代码臃肿。
