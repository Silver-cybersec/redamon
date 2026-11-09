# 静态安全审计（Silver-cybersec/redamon）

- 审计日期：2026-11-09
- 对象：本工作区 `master` 检出，版本 `7.7.0`（`VERSION`）
- 提交：`046921e65f7168bbc15946a257df4d14663e9b56`（`feat(settings): Save stays on screen in every Global Settings form`，作者 Samuele Giampieri）
- 许可证：MIT（`LICENSE`，版权 2026 Samuele Giampieri）
- 方法：只读静态阅读。未运行仓库脚本、未构建镜像、未安装依赖、未对任何扫描目标发包。公开漏洞查询仅访问 OSV API（`https://api.osv.dev`）与 GitHub 提交 API。
- 身份核对：GitHub API 上 `samugit83/redamon` 的 `master` 与 `Silver-cybersec/redamon` 的 `master` 均为上述 SHA。本 fork 的 `master` 与上游该提交一致，未见额外提交。工作区 `git status` 在审计开始时干净。

结论先说在这里，依据在后文。

**未发现隐藏后门或混淆载荷。** 这是上游公开的进攻性安全平台（侦察、漏洞扫描、Kali 沙箱、Metasploit、由 LLM 驱动的工具执行），危险能力是产品功能，不是偷偷塞进来的恶意代码。

**实验室自行部署的总体风险：高。** 风险来自默认就会拉起的进攻能力、若干失败打开的认证、宿主机 Docker 套接字，以及大量未锁定的镜像和 `@latest` / `master` 下载。可以在隔离实验室使用，但不能按「裸 `docker compose up`、主机可上网、端口对局域网开放」来用。使用前的加固项见第 4 节。

文中「未确认」表示静态材料不足以判定，不是暗示它有问题。

---

## 1. 恶意代码 / 后门

### 1.1 未发现的项

在生产代码（排除测试里故意写的漏洞样例和攻击提示词）中检索了 `eval` / `exec`、`pickle.loads`、`marshal.loads`、`shell=True`、`/dev/tcp`、`bash -i`、提交的二进制（`*.exe` / `*.so` / `*.whl` / `*.jar`）、以及指向 `webhook.site`、`burpcollaborator`、`pastebin`、Discord webhook 一类外联地址的字符串。

- 仓库内没有提交的二进制或 wheel。
- 生产 Python 里没有 `shell=True`。唯一命中在测试注释：`agentic/tests/test_cve_intel_integration.py:475`。
- 没有发现把 base64/hex 解码后再 `exec` 的隐藏载荷。
- `webapp/package.json:15` 的 `postinstall` 只有 `prisma generate`。锁文件里带 `hasInstallScript` 的是上游官方包（见 3.2），仓库自己没有自定义安装钩子去外发数据。
- `.github/` 只有 Issue 模板，没有 Actions 工作流，因此没有仓库内的 CI 步骤去拉第三方 action。
- 子模块只有文档站：`.gitmodules` 指向 `https://github.com/samugit83/redamon.wiki.git`，记录的提交是 `61c4b4b46e9bc11c907fe1ee1e3cb1c61bf2102c`。检出时子模块未初始化（`git submodule status` 行首为 `-`）。子模块内容未读，标「未确认」。

### 1.2 动态执行：是产品功能，路径清楚

| 位置 | 行为 | 判定 |
| --- | --- | --- |
| `mcp/servers/network_recon_server.py:484-523` | `kali_shell` 把参数交给 `bash -c` | 文档化的沙箱命令执行，不是隐藏后门 |
| `mcp/servers/network_recon_server.py:536-631` | `execute_code` 把模型给出的源码写到 `/tmp` 再用 python/bash/ruby/perl/gcc 执行 | 同上。文件名有字符白名单（约 597 行），代码内容没有白名单 |
| `tooling/scripts/parse_settings_mappings.py:151` | `exec` 求值本仓库自己的字面量 | 维护脚本，输入不是外部请求 |
| `recon/tests/test_dead_bundled_data.py:73-74` | `eval`/`compile` 本仓库源码 | 测试 |
| `mcp/servers/redamon.py:578` | 方法名 `eval` | 浏览器侧 JS 求值接口（代理大脑），不是 Python `eval` 后门。调用链细节标「未确认」是否还有第二处包装 |

攻击提示词里的反弹 shell 示例在 `agentic/prompts/`（例如 `cve_exploit_prompts.py`）。那是给操作员模型看的进攻剧本，随产品一起发布，不是安装时自动执行的载荷。

### 1.3 网络外联：都是声明过的行为，其中几条会把秘密送到第三方

这些不是偷偷写死的 C2，但实验室若允许出网，它们会在安装后或扫描时主动连出去。

1. **用扫到的令牌去官方 API 做有效性验证**（令牌会离开实验室）。`recon/helpers/js_recon/validators.py`：
   - GitHub `116`、GitLab `135`、Slack `157`、Stripe `181`、Google Maps `201`、SendGrid `237`、Mailgun `256`、Mailchimp `277`、HubSpot `294`、Heroku `312`、DigitalOcean `352`、Telegram `371`、Discord `390`、Postmark `408`、Cloudflare `443`、OpenAI `463`。
   - npm 包元数据：`recon/helpers/js_recon/dependency.py:62` 请求 `registry.npmjs.org`。
2. **Nuclei OAST 默认开启。** `recon/project_settings.py:212` 默认 `NUCLEI_INTERACTSH: True`。`recon/helpers/nuclei_helpers.py:257-267` 写明回调打到公共收集器（interact.sh / oast.fun）。带认证头时会强制 `-no-interactsh`。无认证的扫描仍会把探测流量的回连交给 ProjectDiscovery 的公共基础设施。
3. **Kali 容器启动即自更新。** `mcp/kali-sandbox/entrypoint.sh:32-52`：`MSF_AUTO_UPDATE` 默认 `true`（`msfupdate`，失败则 `apt-get install metasploit-framework`）；`NUCLEI_AUTO_UPDATE` 默认 `true`（`nuclei -update-templates`）。这是每次启动都从上游拉可变内容。
4. **侦察容器启动拉可变 DNS 列表和 `:latest` 镜像。** `recon/entrypoint.sh:114` 从 `raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt` 下载（`main` 可被改写，无校验和）。同文件 `133-146` 在本地没有镜像时 `docker pull` 一组 `:latest`（见 3.4）。
5. **插件目录运行时拉取。** `webapp/src/lib/plugins/catalog.ts:29` 默认 `https://raw.githubusercontent.com/samugit83/redamon-plugins/master/catalog.json`。同文件后文会验 Ed25519 签名和序号。签名验证在代码里，本次未取线上 catalog 核对密钥是否仍是 `keyring.ts` 里的那把。插件包本体在另一个仓库，不在本树，内容标「未确认」。
6. **`./redamon.sh update` 会 `git pull`。** 这是文档中的升级路径（`redamon.sh` 约 39、1558 行），跟踪的是 clone 时的 `origin`。若 origin 被改到别的远程，更新会跟着走。脚本本身没有写死第二个隐蔽远程。
7. **可选隧道。** `mcp/servers/tunnel_manager.py:55-71` 在配置了 ngrok token 后把本机 `4444` 暴露到公网。默认不启动，但二进制在镜像构建时就会下载（见 3.5）。

未发现读取 `~/.ssh`、浏览器 Cookie 目录或整份环境变量后发到作者服务器的逻辑。图数据库和提示词里出现 `id_rsa`，是侦察/后渗透要找的文件类型（例如 `scanners/github_secret_hunt/github_secret_hunt.py:473`、`webapp/src/app/graph/components/AIAssistantDrawer/suggestionData.ts:415`），不是安装程序去偷操作员的钥匙。

### 1.4 持久化

- Kali 源码以只读挂载，注释写明是为了避免被改写后重启仍在：`docker-compose.yml:782-788`。
- 容器 `restart: unless-stopped` / `on-failure` 是编排策略，不是隐藏的主机持久化（cron、systemd unit、`authorized_keys`）。仓库内未发现安装到宿主机用户目录的自启动单元。
- `tooling/deploy/single-host/` 会在操作员显式部署时改 SSH、防火墙、unattended-upgrades。那是可选的单机部署脚本，不是 clone 之后自动执行。

---

## 2. 危险能力与默认配置

产品定位就是授权测试用的红队平台（`SECURITY.md:64-65`、`DISCLAIMER.md`）。下面列的是**默认就会具备或很容易误开**的能力，供实验室决定要不要接受。

### 2.1 工具执行边界

LLM 的工具调用不是直接在宿主机 shell 里跑，而是进 Kali 容器里的 MCP 工具。边界如下。

- 危险工具名单：`agentic/project_settings.py:42-55`。其中包括 `kali_shell`、`execute_code`、`execute_curl`、`metasploit_console`、`execute_hydra`、`proxy_brain`、`execute_guarddog`。
- 默认要人确认：`REQUIRE_TOOL_CONFIRMATION`、`REQUIRE_APPROVAL_FOR_EXPLOITATION`、`REQUIRE_APPROVAL_FOR_POST_EXPLOITATION` 都是 `True`（同文件 `195-197`；Prisma 默认值 `webapp/prisma/schema.prisma:1165-1167`）。
- 阶段门并不挡住 shell。测试明确把 `kali_shell` 放进 informational / exploitation / post_exploitation 三个阶段（`agentic/tests/test_phase_gating.py:112-146`）。拦住随意执行的是确认开关，不是阶段。
- 确认开关可以被项目设置关掉。关掉之后，模型输出（以及提示注入）可以变成容器内的任意 bash/Python。Kali 镜像里有 nmap、Metasploit、sqlmap、hydra、hashcat、ysoserial、linpeas、winPEAS 等（`mcp/kali-sandbox/Dockerfile:43-67` 以及后续 `curl` 段）。
- 容器不是强沙箱：`docker-compose.yml:743-752` 给了 `NET_ADMIN`、`NET_RAW` 和 `seccomp:unconfined`。注释说明不给 `SYS_PTRACE`。`cap_drop: ALL` 没有加在这个服务上。
- 同服务把反弹 shell 端口映射到宿主机所有接口：`docker-compose.yml:778` 的 `"4444:4444"`。注释 `768-777` 说明这是故意的。单机部署 overlay 才改回 loopback：`tooling/deploy/single-host/compose/docker-compose.prod.yml:57-69`。

`execute_code` 的解释器是固定列表，但代码正文没有策略限制。这是命令执行面，不是注入漏洞意义上的「忘记转义」：调用方本来就被设计成能跑任意代码。

### 2.2 谁拿着 Docker 套接字

| 服务 | 挂载 | 位置 |
| --- | --- | --- |
| `docker-broker` | 宿主机 `/var/run/docker.sock` | `docker-compose.yml:409` |
| `recon-orchestrator` | 同上，原始套接字 | `docker-compose.yml:461` |
| 侦察容器 | 设计上走 broker 的过滤套接字 | `docker-compose.yml:392-399` |

编排器和 broker 被攻破等价于宿主机 root（能起特权容器）。broker 的绑定路径白名单默认写了一台开发机路径：`docker-compose.yml:418` 的 `DOCKER_BROKER_ALLOWED_BIND_PREFIXES` 含 `/tmp/redamon` 和 `${PWD:-/home/samuele/Progetti didattici/redamon}`。`PWD` 在 compose 插值时通常是启动目录；若 `PWD` 为空，会退回作者本机路径。那不是后门，但是默认值不该留在发布文件里。过滤规则是否真能挡住 `-v /:/host`，本次未运行 broker，标「未确认」。

GVM 扫描容器同样放宽了沙箱：`docker-compose.yml:255-259`，`cap_add: NET_ADMIN/NET_RAW`，`seccomp=unconfined`，`apparmor=unconfined`。

### 2.3 默认端口

`redamon.sh` 正常安装只拉起 `CORE_SERVICES`（`redamon.sh:18`）：postgres、neo4j、docker-broker、recon-orchestrator、kali-sandbox、agent、webapp。

| 发布 | 绑定 | 位置 | 说明 |
| --- | --- | --- | --- |
| Web `:3000` | `0.0.0.0` | `docker-compose.yml:1101` | 登录面。生产 overlay 改为 `127.0.0.1`（`docker-compose.prod.yml:25-26`） |
| Agent `:8090` | `0.0.0.0` | `docker-compose.yml:873` | 见 2.4 的失败打开 |
| 反弹 shell `:4444` | `0.0.0.0` | `docker-compose.yml:778` | 见 2.1 |
| Postgres `5432`、Neo4j `7474/7687`、编排器 `8010`、MCP `8000-8005`、`8013-8016`、ngrok API `4040`、捕获代理 `8888` | `127.0.0.1` | `docker-compose.yml:39,72-73,459,761-780,1345` | 仅本机。同一台机器上的其他用户仍可访问 |
| GVM | 未见宿主机端口 | `gvmd` / `gvm-ospd` 服务块 | 只在 Docker 网络内。未确认镜像内部是否另有监听 |

入站 MCP 默认开：`docker-compose.yml:1153` `MCP_SERVER_ENABLED` 默认 `true`。`redamon.sh:2047-2066` 在内部密钥缺失或为 `changeme` 时拒绝把它打开。密钥齐了之后，持有令牌的客户端可以驱动平台。令牌权限细节标「未确认」是否包含写操作（需读 MCP 工具表，本次未逐项打分）。

### 2.4 口令、密钥、失败打开

`./redamon.sh install|up` 会在 `.env` 里生成随机密钥（`redamon.sh:1915-2044`：`AUTH_SECRET`、`INTERNAL_API_KEY`、`SCANNER_API_KEY`、`ORCHESTRATOR_API_KEY`、`MCP_AUTH_TOKEN`、`AGENT_WS_TICKET_SECRET`、`TUNNEL_AUTH_TOKEN`、`REDAMON_SECRET_HMAC_KEY`、流量入库 DSN、插件密钥）。管理员没有默认口令，安装时交互创建，最短 12 字符（`redamon.sh:2654,2712-2715`）。这条路径是合理的。

绕过脚本、直接 `docker compose up` 时，compose 里的回退值会生效：

| 回退 | 位置 | 后果 |
| --- | --- | --- |
| `AUTH_SECRET` 默认 `changeme` | `docker-compose.yml:1124` | 可伪造登录票据。未确认具体 JWT 算法与是否还有第二道校验 |
| `INTERNAL_API_KEY` / `SCANNER_API_KEY` / `ORCHESTRATOR_API_KEY` 默认 `changeme` | `docker-compose.yml:519-532,939-940,1125-1126,1237` | 见下一行 |
| `changeme` 被当成「没设密钥」 | `agentic/llm_guard.py:69-95` | Agent 上计费 LLM 接口**失败打开**，且 Agent 端口在 `0.0.0.0:8090`。`redamon.sh:2049-2065` 的注释写的就是这个组合 |
| `GVM_PASSWORD` 默认 `admin`，用户名 `admin` | `docker-compose.yml:10-14,699-700` | Greenbone 镜像首次启动创建 `admin/admin`。`redamon.sh:2588-2606` 只在启用 GVM 时生成强密码并在启动后轮换 |
| 流量入库 DSN 回退 `traffic_ingest:changeme` | `docker-compose.yml:1376` | 仅在未生成 DSN 时。主路径会生成随机口令 |
| 独立 compose 的 Postgres 回退 `redamon_secret` | `services/postgres_db/docker-compose.yml:7`，`webapp/docker-compose.yml:15` | 主 `docker-compose.yml:31` 反而要求必须设置。不要用旁边的 compose 文件单独起库 |
| 内部密钥路由白名单默认不强制 | `docker-compose.yml:1127-1131` `INTERNAL_KEY_ALLOWLIST_ENFORCE` 默认 `false` | 注释写明是失败打开的滚动发布 |

Kali MCP 本身在令牌为空时**失败关闭**（`mcp/servers/_auth_middleware.py:10-14,70-81`）。变量名 `_warned_failopen` 是旧名字，行为与注释一致，是拒绝而不是放行。

GVM 与脚本的不一致：`docker-compose.yml:6-9` 写「`docker compose up -d` 会自动启动 GVM」。服务没有 `profiles:`（对比 tools/capture/plugins 在 303 行之后才有 profile）。`redamon.sh` 在未创建 GVM 旗标文件时只 `up` 核心服务（`3442-3446`）。因此：

- 用 `./redamon.sh install`（不加 `--gvm`）：不拉 GVM，也不会去轮换一个不存在的 `admin/admin`。
- 用文件头写的裸 `docker compose up -d`：会拉 Greenbone 全家桶，并在首次初始化留下 `admin/admin`，直到有人执行 `redamon.sh` 的轮换。轮换函数在 GVM 未启用时直接返回（`2599-2600`）。

### 2.5 日志里的秘密

`agentic/orchestrator_helpers/nodes/execute_tool_node.py:88-94` 把工具参数打到日志，单字段最多保留 10000 字符。`execute_curl` / `kali_shell` 的参数可以含 `Authorization`、Cookie、命令行里的令牌。没有看到针对该字段的脱敏。

`docker-compose.yml:1054-1078` 的 KB 刷新 sidecar 把 `NEO4J_PASSWORD` 放进 `python -m ... --neo4j-password`。该服务默认在 `kb-refresh` profile，不随核心启动。一旦开启，口令会出现在容器进程列表里。

js_recon 验证函数会把令牌放到出站 HTTP 头里（1.3）。那些请求若被代理或调试日志记下，秘密会再次落地。本次未逐个读响应日志是否打印 body，标「未确认」。

### 2.6 其他默认行为

- DNS：Kali 服务使用 `8.8.8.8` / `8.8.4.4`（`docker-compose.yml:740-741`）。实验室若要求 DNS 不出网，这是一条泄露查询的路径。
- 知识库嵌入默认本地模型，不默认调用 OpenAI（`.env.example:58` `KB_EMBEDDING_USE_API=false`）。模型名默认 `intfloat/e5-large-v2` 与 `BAAI/bge-reranker-base`，在构建 Agent 镜像且未 `--skipkbase` 时从 Hugging Face 下载（`agentic/Dockerfile:143-156`）。
- 捕获代理默认脱敏：`CAPTURE_PROXY_REDACT_SECRETS` 默认 `true`（`docker-compose.yml:546,1373`）。未运行验证，仅确认默认值。

---

## 3. 依赖供应链

本章列出**构建或启动时会被拉取的东西**。传递依赖在没有锁文件时无法在不安装的前提下展开，那些条目标「未确认」。

实验室若不能接受「构建时出网」，应事先在可控镜像仓库做离线镜像，并禁止容器运行时访问 GitHub / PyPI / npm / Kali 镜像 / `go.dev`。

### 3.1 清单与锁

| 种类 | 路径 | 锁定方式 | 校验 |
| --- | --- | --- | --- |
| npm 应用 | `webapp/package.json` + `webapp/package-lock.json`（lockfileVersion 3） | 锁文件有解析版本和 `integrity` | 直接依赖的版本范围仍是 `^`，以锁为准。未见 `.npmrc` 把 registry 指到非官方源 |
| npm e2e | `testing/e2e/package.json` + `package-lock.json` | 有锁 | 只在 e2e 时安装，不是 `redamon.sh install` 的核心路径 |
| npm 实验靶场 | `testing/guinea_pigs/**/package.json` | 靶场 | 故意脆弱，不要装进生产镜像 |
| Python 核心 | `agentic/requirements.txt`、`agentic/requirements-kb.txt`、`recon/requirements.txt`、`recon_orchestrator/requirements.txt`、`mcp/requirements.txt`、`requirements-test.txt`、各 `scanners/*/requirements.txt` | **没有** `poetry.lock` / `uv.lock` / `pip-tools` 锁 | 除特别标明 `==` 或 git commit 的行外，`pip install` 会取当时的最新兼容版本，无 hash |
| Python 插件运行器 | `services/plugin_runner/requirements.txt` | 全部 `==`，且 Dockerfile `--no-deps` | 无 hash。这是仓库里最干净的一份 Python 清单 |
| Go | 无根级 `go.mod` 提交为应用依赖 | Dockerfile 里 `go install module@ref` | Go 模块校验数据库会校验 zip。`@latest` / `@master` 的 ref 本身会漂 |
| Rust / Ruby / PHP / .NET | 无应用级清单 | 仅 Agent / AI 扫描镜像里的工具链安装脚本 | 见 3.5 |
| 子模块 | `.gitmodules` | 提交钉死，工作区未检出 | 无 |

`webapp/package.json` 直接依赖（锁里的解析版本）：`next@16.1.6`（`webapp/package-lock.json:9899-9902`）、`react@19.2.4`、`react-dom@19.2.4`、`prisma` / `@prisma/client@6.19.2`、`jose@6.2.2`、`bcryptjs@2.4.3`、`@modelcontextprotocol/sdk@1.30.0`（package.json 写死 `1.30.0`）、其余多为 `^` 范围但被锁文件钉住。registry 均为 `registry.npmjs.org`。

锁文件中 `hasInstallScript: true` 的包：根包（即 `prisma generate`）、`@prisma/client`、`prisma`、`esbuild`、`fsevents`（可选，darwin）、`sharp`（可选）、`unrs-resolver`（依赖 `napi-postinstall`）。这些是上游官方包的原生绑定/代码生成脚本，仓库没有改写它们。脚本正文在 tarball 里，本次未下载，标「未确认」脚本内容；包名和 registry 没有异常。

未发现仿冒包名（`requets`、`urlib3`、`python-dateutil` 错拼等）。直接依赖名与常见官方包一致。未对照完整 typosquat 词表扫每一个传递依赖，长尾标「未确认」。抽查的锁定版本在 OSV 结果里没有 `MAL-*` 恶意包编号。

### 3.2 已锁定版本的 OSV / GHSA（2026-11-09 查询）

只对**文件里写死的版本**下结论。`>=` 范围没有解析，不用猜测版本冒充结果。

**npm `next@16.1.6`：OSV 返回 38 条，其中 4 条严重、若干高危。** 严重项：

| ID | 摘要 | OSV 事件里的 16.x 修复点 |
| --- | --- | --- |
| GHSA-2464-fhr4-w9xw | Image Optimization 在使用 SVG 时未认证 RCE | fixed `16.4.1` |
| GHSA-2xp9-vwfh-vxw4 | Image Optimization 在使用 AVIF 时未认证 RCE | fixed `16.3.3` |
| GHSA-673q-mjm6-r5xr | `use cache` 返回 typed array 时未认证 RCE | fixed `16.4.1` |
| GHSA-p293-qw3h-jr36 | Windows 托管上的未认证 RCE | fixed `16.3.3` |

另有多条 middleware/proxy 绕过、Server Actions DoS、图片优化 SSRF（例如 GHSA-267c-6grr-h53f、GHSA-c4j6-fc7j-m34r）。38 条是否都能在本仓库的默认 Next 配置上触发：**未确认**（Windows 专用项在 Linux 容器上很可能不适用；image optimization 是否启用未逐路由核对）。锁定版本低于上述修复点，这是事实。Web 若对实验室以外可达，应把 `next` 升到高于全部相关 fixed 版本再暴露端口。

**`@modelcontextprotocol/sdk@1.30.0`：6 条。** 高危包括跨源重定向把自定义头带出去（GHSA-6prh-2h8m-c8cw，fixed `1.32.0`）、服务端 bearer 接受发给别的资源的令牌（GHSA-rvq5-wwqv-78pq，fixed `1.32.0`）、请求体/批处理无上限（GHSA-f897-62hf-6gxq）、实验性 task 未绑定会话（GHSA-22jm-h49p-29qw）。

**PyPI `mcp==1.28.1`（agent）与 `mcp==1.29.0`（Kali venv，`mcp/requirements.txt:16`）：各 4 条，修复点为 `1.30.0`。**

- GHSA-5h93-6whr-6q8j：HTTP 客户端跟随跨源重定向时带走自定义头和 body
- GHSA-84m7-p3x7-pcfv：Streamable HTTP 会话无上限，可耗尽资源
- GHSA-rwrf-2pqf-9j8j：按服务端给出的 `$ref` URL 去拉取以校验工具结果
- GHSA-w4fh-qvv9-3v23：服务端 bearer 接受发给其他资源服务器的令牌

`mcp/requirements.txt:5-11` 写明 semgrep 会把该 venv 的 mcp 钉在 `1.29.0`。因此 Kali 镜像不能单独把 mcp 升到 `1.30.0`，除非同时改 semgrep 约束。本次未安装 semgrep，该约束是否仍成立标「未确认」，但仓库注释是这么写的。

**PyPI `fastmcp==3.2.4`：GHSA-7xgj-8392-5q4r**（直接调用时跳过变换后的组件授权），修复点 `3.4.10`。

**`mitmproxy~=11.1`（`scanners/capture_proxy/Dockerfile:9`）：** 范围是 `>=11.1,<11.2`。GHSA-63cx-g855-hvv4（捆绑的 h2）修复点在 `12.1.2`，因此整个 `11.1` 范围都落在受影响区间。GHSA-wg33-5h85-7q5p / PYSEC-2026-1630（mitmweb API 认证绕过）修复点 `11.1.2`：若解析到 `11.1.0` 或 `11.1.1` 则受影响，若解析到 `11.1.3+` 则这条已过。实际解析版本**未确认**。PYSEC-2026-92 的范围写到 `12.2.2`，摘要为空，是否适用于本仓库的捕获代理标「未确认」。

以下锁定版本在本次 OSV 查询中无记录：`prisma@6.19.2`、`@prisma/client@6.19.2`、`react@19.2.4`、`react-dom@19.2.4`、`jose@6.2.2`、`bcryptjs@2.4.3`、`retire@5.4.3`、`fastapi==0.142.2`、`starlette==1.7.0`、`httpx==0.28.1`、`uvicorn==0.54.0`、`pydantic==2.13.5`（以上四个精确版本来自插件运行器）、`garak==0.15.1`、`pyrit==0.14.0`、`giskard[llm]==2.19.1`、`guarddog==3.0.1`、`baddns==2.1.0`。无记录不等于以后没有；查询日是 2026-11-09。

`agentic/requirements.txt` 里绝大多数是 `>=`（`langchain>=0.3.0`、`langgraph>=0.2.0`、`fastapi>=0.115.0`、`httpx>=0.27.0`、`cryptography` 甚至不是直接声明，会作为传递依赖进来）。这些的具体 CVE **未确认**，因为没有锁、也没有执行 `pip install`。同样未确认的还有 `recon/requirements.txt` 的 `requests>=2.31.0`、`urllib3>=2.0.0`、`neo4j>=5.0.0`、`arjun>=2.2.7`、`mcp>=1.27.0`（与上面钉死的 1.28.1 不是同一份清单）。

钉死得较好的 Python 行：

- `agentic/requirements.txt:18-19` `langchain-mcp-adapters==0.3.0`、`mcp==1.28.1`（后者有 GHSA，见上）
- `agentic/requirements.txt:59-60` `tree-sitter==0.21.3`、`tree-sitter-languages==1.8.0`
- `recon/requirements.txt:6-7,17,31`：`python-whois==0.9.6`、`dnspython==2.8.0`、`publicsuffixlist==1.1.0.20261010`（注释里写了 wheel sha256，pip 命令行并未 `--require-hashes`，所以安装时**不会**强制该 hash）
- `recon/requirements.txt:17` `knock-subdomains @ git+https://github.com/guelfoweb/knock.git@da43fdd2399f9ca5a39229cb8ba3e51249f53e30`
- `recon/requirements.txt:31` ParamSpider `@c44bdaae54789b237028e309b603d1aa5ad52e5e`

### 3.3 容器基础镜像

没有任何业务镜像使用 `image@sha256:`，除了插件运行器和两个实验用靶场。`latest` / 无标签 / `stable` / 发行版浮动标签都会在下次构建或拉取时变。

**自建镜像的 `FROM`（核心，`redamon.sh install` 会构建 tools + capture + 核心服务）：**

| 文件 | 基础镜像 | 锁定 |
| --- | --- | --- |
| `agentic/Dockerfile:4` | `python:3.11-slim` | 浮动标签，无 digest |
| `recon/Dockerfile:9,17` | `golang:1.22-alpine` | 小版本，无 digest |
| `recon/Dockerfile:27` | `golang:1.25-alpine` | 同上 |
| `recon/Dockerfile:36` | `golang:1-bookworm` | **大版本浮动** |
| `recon/Dockerfile:40,53` | `debian:bookworm-slim`、`python:3.11-slim-bookworm` | 发行版标签，无 digest |
| `recon_orchestrator/Dockerfile:1` | `python:3.11-slim` | 浮动 |
| `webapp/Dockerfile:7,25,49` | `node:22-slim` | 大版本浮动 |
| `mcp/kali-sandbox/Dockerfile:5` | `golang:1-bookworm` | 大版本浮动 |
| `mcp/kali-sandbox/Dockerfile:8` | `kalilinux/kali-rolling:latest` | **滚动发行版 + latest**。apt 源先用 HTTP：`19` 行 `deb http://kali.download/kali kali-rolling ...`，装完 CA 后再换 HTTPS（`23` 行）。滚动镜像加上 HTTP 引导，构建内容不可复现，且引导阶段可被篡改 |
| `services/docker_broker/Dockerfile:9` | `python:3.12-alpine` | 浮动 |
| `services/plugin_runner/Dockerfile:7` | `python:3.11-slim@sha256:db3ff2e1800a8581e2c48a27c3995339d47bdf046da21c7627accd3d51053a93` | **有 digest** |
| `scanners/trufflehog_scan/Dockerfile:13` | `python:3.12-slim-bookworm` | 发行版标签；二进制本身有 checksum（见 3.5） |
| `scanners/baddns_scan/Dockerfile:16` | `python:3.12-slim` | 浮动；包 `baddns==2.1.0` |
| `scanners/capture_proxy/Dockerfile:5` | `python:3.12-slim` | 浮动 |
| `scanners/gvm_scan/Dockerfile:8`、`github_secret_hunt/Dockerfile:8`、`ai_attack_surface_scan/Dockerfile:11` | `python:3.12-slim` | 浮动 |
| `scanners/wcvs/Dockerfile:14,44` | `golang:1.23-bookworm`、`debian:bookworm-slim` | 小版本/发行版，无 digest |
| `scanners/supply_chain_scan/Dockerfile:17,20` 与 `supply_chain_analyzer/Dockerfile:19,23` | `golang:1-bookworm`、`python:3.11-slim-bookworm` | Go 侧大版本浮动 |
| `scanners/codefix_sandbox/Dockerfile:16` | `node:20-bookworm-slim` | 大版本浮动 |
| `docker-compose.dev.yml:13` | `node:22-alpine` | 仅 dev |

**compose 直接引用、不由本仓库 Dockerfile 构建的镜像：**

| 镜像 | 位置 | 说明 |
| --- | --- | --- |
| `postgres:16-alpine` | `docker-compose.yml:24` | 官方库，标签浮动，无 digest |
| `neo4j:5.26-community` | `docker-compose.yml:52` | 官方，小版本，无 digest |
| `registry.community.greenbone.net/community/vulnerability-tests` 及 `notus-data`、`scap-data`、`cert-bund-data`、`dfn-cert-data`、`data-objects`、`report-formats`、`gpg-data` | `docker-compose.yml:106-172` | **无标签，等于 latest**。官方 Greenbone 社区仓库，不是个人镜像，但是完全浮动 |
| `registry.community.greenbone.net/community/redis-server:stable`、`pg-gvm:stable`、`gvmd:stable`、`ospd-openvas:stable` | `182,190,221,250` | `stable` 会前进。`scanners/gvm_scan/docker-compose.yml:132` 另有 `ospd-openvas:22.7.1`，与主 compose 的 `:stable` 不一致 |
| `redamon-*:latest` | 多处，例如 `302,1017` | 本地构建标签，不是从 Docker Hub 拉 `redamon`。风险在构建上下文，不在公网上的同名镜像。不要把这些标签推到或从不可信仓库拉取 |

**侦察启动时额外 `docker pull`（`recon/entrypoint.sh:133-146`）以及 `recon_settings/registry.yaml` 里登记的工具镜像：**

`projectdiscovery/naabu:latest`、`httpx:latest`、`katana:latest`、`nuclei:latest`、`subfinder:latest`、`tlsx:latest`、`uncover:latest`、`sxcurity/gau:latest`、`caffix/amass:latest`、`frost19k/puredns:latest`、`jauderho/hakrawler:latest`、`dolevf/graphql-cop:1.14`、`ghcr.io/zaproxy/zaproxy:stable`，以及本地的 `redamon-wcvs:latest`、`redamon-baddns:latest`。

除 `graphql-cop:1.14` 外都是 `latest` 或 `stable`，无 digest。`sxcurity/gau`、`caffix/amass`、`frost19k/puredns`、`jauderho/hakrawler` 是社区个人/组织镜像，不是 ProjectDiscovery 官方仓库。本次未核对镜像维护者是否仍是原作者，标「未确认」。

实验靶场（`testing/guinea_pigs/`）还有 `nginx:alpine`、`mongo:latest`、`python:3.12-slim`、`node:8.17.0-slim`（已知过时）、`php:8.4.26-apache` 等。它们是故意脆弱的靶子。其中 `urlscan_lab` 与 `nested_wildcard_lab` 的 CoreDNS、nginx **带 digest**。不要把靶场 compose 和主栈放在同一台可路由的机器上。

### 3.4 `go install` / `git clone` / `pip` 的工具

**侦察镜像（版本钉得相对好）：** `recon/Dockerfile`

- `jsluice` 钉在 commit `0ddfab153e060a9eeaded4d8669233f7c071e7e4`（`recon/Dockerfile:14`）
- `ffuf/v2@v2.1.0`（21）
- `subjack@b53899ce6230767beb1c4a9f879c6ebba23a98fa`（31）
- `osv-scanner@v2.4.0`（37）
- masscan `git checkout 94e118ccd26c2fb263fb2fe731043f7b3240723c`（47-49）
- SecLists 三个词表钉在 commit `47c02ddb...`（161-165），无文件 checksum
- jhaddix `all.txt` 钉在 gist raw 的 blob `96f4e51d...`（174），无 checksum

**Kali 镜像（大面积 `@latest` / `@master`，无 checksum）：** `mcp/kali-sandbox/Dockerfile`

| 行 | 来源 | 锁定 |
| --- | --- | --- |
| 129-130 | `github.com/frohoff/ysoserial` `v0.0.6` jar | 版本钉死，无 checksum |
| 139 | `https://go.dev/dl/go1.25.7.linux-*.tar.gz` | 版本钉死，**无 sha256**（对比 Agent 镜像里的 Go 1.22.10 有校验） |
| 152-156 | naabu、nuclei、interactsh-client、subfinder、katana | `@latest` |
| 164-168 | ffuf、httpx、dalfox、dnsx、`github.com/Emoe/kxss` | `@latest` |
| 173 | jsluice | `@latest` |
| 179 | `github.com/betterleaks/betterleaks` | `@latest`。组织较小，维护者身份未确认 |
| 183 | `owasp-amass/amass/v4/...@master` | **分支名，浮动** |
| 187 | gau | `@latest` |
| 195 | vulnx | `@latest` |
| 202 | `github.com/PentestPad/subzy` | `@latest` |
| 223 | `pip install neo4j` | 无版本 |
| 233 | `guarddog==3.0.1` | 钉死 |
| 238-239 | `pycryptodomex termcolor ratelimit` 无版本，然后 `git clone https://github.com/ticarpi/jwt_tool.git` | **默认分支，无 checkout** |
| 246-260 | graphql-cop、GraphQLmap `git clone` 后 `pip install -e .` | 默认分支 |
| 279 | `pip install git+https://github.com/devanshbatham/ParamSpider.git` | **无 commit**（侦察镜像里的那份是有 commit 的，Kali 这份没有） |
| 286 | `pip install semgrep` | 无版本 |
| 307 一带 | 若干 pip 包无版本 | 见文件 |
| 321-343 | linpeas 钉在 `peass-ng` release `20260708-abaa95f3`；`LinEnum.sh` 与 `deepce.sh` 取 `master`/`main` raw；`pspy64` `v1.2.1`；winPEAS 同一 PEASS release；PowerUp.ps1 取 PowerSploit `master`；PrivescCheck release `2026.07.02-1` | **全部无 checksum**。`master`/`main` 的脚本可被上游改写后进入下一次构建 |
| 358 | `git clone` gMSADumper | 默认分支 |
| 367 | kerbrute `@latest` | 浮动 |
| 419,432,455,475,497,508 | SSTImap、tplmap、phpggc、viewgen、smuggler、h2csmuggler | `git clone` 默认分支，再 pip 装它们的 requirements（那些 requirements 不在本仓库，内容未确认） |
| 492 | `clairvoyance==2.5.5` | 钉死 |
| 557-559 | ngrok：`https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-linux-${ARCH}.tgz` | **稳定通道，无版本、无 checksum**。下载失败只打警告，构建仍继续 |
| 562-566 | chisel `v1.11.4` | 版本钉死，无 checksum |

Kali 的 apt 包（nmap、metasploit-framework、sqlmap、hydra、hashcat、john、exploitdb、nikto、wpscan、masscan 等，约 43-117 行）来自 `kali-rolling`，版本由构建当日的镜像决定，无 apt 版本钉死。

**其他构建期下载：**

| 位置 | 内容 | 锁定 / 校验 |
| --- | --- | --- |
| `agentic/Dockerfile:38-44` | `https://deb.nodesource.com/setup_20.x` 再 `bash` | 脚本在 NodeSource 的浮动路径上，无 checksum |
| `agentic/Dockerfile:54-62` | Go `1.22.10` | **有 sha256**（amd64/arm64） |
| `agentic/Dockerfile:88-91` | `https://getcomposer.org/installer` | 无 checksum |
| `agentic/Dockerfile:95-98` | `https://dot.net/v1/dotnet-install.sh` channel `8.0` | 安装脚本浮动，运行时版本跟随 8.0 通道 |
| `agentic/Dockerfile:132-156` | PyTorch CPU index、`sentence-transformers`、Hugging Face 上的 `intfloat/e5-large-v2` 与 `BAAI/bge-reranker-base` | 无版本钉死，无 digest |
| `agentic/Dockerfile:168` | `pip install git+https://github.com/mukul975/cve-mcp-server.git@main` | **个人仓库的 `main`**。未发现恶意证据，也未审计该仓库内容，标「未确认」 |
| `agentic/Dockerfile:179-181` | `curl .../aquasecurity/trivy/main/contrib/install.sh \| sh`，参数 `TRIVY_VERSION=v0.73.0`，然后 `trivy plugin install mcp` | 版本参数钉了二进制，**安装脚本来自 `main`**，插件未钉版本 |
| `scanners/ai_attack_surface_scan/Dockerfile:38,48,57` | `torch` 从 `download.pytorch.org/whl/cpu` | 无版本 |
| 同文件 `49` | `curl https://sh.rustup.rs \| sh`，toolchain `stable` | 经典的管道安装，通道浮动 |
| 同文件 `88` | `deb.nodesource.com/setup_22.x \| bash` | 同 NodeSource |
| `scanners/trufflehog_scan/Dockerfile:24-39` | TruffleHog `3.96.0` | **下载官方 checksum 文件并 `sha256sum -c`**。这是仓库里做得最好的二进制安装 |
| `scanners/wcvs/Dockerfile:23-28` | clone Hackmanit WCVS，`ARG WCVS_REF=master` | 默认 `master` |
| 同文件 `38` | `GOPROXY=https://goproxy.io,https://proxy.golang.org,direct` | 首选第三方代理。注释称 sumdb 仍会校验。代理是否可替换校验过的模块：**未确认**（Go 的设计是 sumdb 失败则构建失败，但本次未构建） |
| `scanners/supply_chain_analyzer/Dockerfile:43` | `npm install -g retire@5.4.3` | 版本钉死，无 integrity 参数（npm 默认会用 registry 的 integrity） |
| `recon/Dockerfile:77` | Docker apt 源的 Debian key `download.docker.com` | 用官方 keyring，无额外 pin |
| `tooling/deploy/single-host/modules/host_bootstrap.sh:71` | Docker 的 Ubuntu gpg，再 dearmor | 仅在单机部署脚本里，不是 clone 后自动跑 |

`redamon.sh` 本身不 `curl` 外部安装脚本。它调用的是本机 `docker compose`。OSV 离线库同步（约 4140 行）会在安装时拉漏洞库数据，那是声明过的功能，体积注释写约 208 MB（npm）。数据来自 Google OSV，不是隐蔽通道。具体 URL 在同步实现里，本次未逐行展开每个生态系统镜像站，标「未确认」是否还有第二个镜像。

### 3.5 风险等级与拉取建议

| 项 | 等级 | 建议 |
| --- | --- | --- |
| `kalilinux/kali-rolling:latest` + HTTP apt 引导 + `@latest` Go 工具 + `git clone` 默认分支 | 高 | 实验室构建一次后导出镜像，禁止容器启动时 `msfupdate` / `nuclei -update-templates` / `docker pull`。把 `@latest` 改成 commit 或 release tag，并记录 sha256。apt 从第一行就用 HTTPS |
| 侦察入口拉取的 `:latest` 社区镜像 | 高 | 改为 digest 钉死；`sxcurity/gau`、`caffix/amass`、`frost19k/puredns`、`jauderho/hakrawler` 先核对发布者再进离线仓库 |
| Greenbone 无标签与 `:stable`，以及裸 `docker compose up` 会启动它们 | 高 | 只用 `redamon.sh` 且不加 `--gvm`，除非需要 OpenVAS。需要时钉 digest，并确认口令已轮换，不要依赖 `admin/admin` |
| `next@16.1.6` 的已知 RCE/SSRF/DoS | 高（若 Web 端口可达） | 升级到高于 OSV fixed 事件的版本后再把 `:3000` 暴露到 loopback 以外。隔离实验室可先只绑 `127.0.0.1` |
| PyPI `mcp` 1.28.1 / 1.29.0、`fastmcp` 3.2.4、npm MCP SDK 1.30.0 | 高 | 升到各 GHSA 的修复版本。Kali 侧先解开与 semgrep 的版本冲突再升 |
| `mitmproxy~=11.1` | 中高 | 升到至少 `12.1.2` 以后（h2 那条），并锁精确版本 |
| ngrok `v3-stable` 无校验、chisel 无校验、PEASS/LinEnum/PowerUp 无校验 | 中高 | 下载后核对上游发布的 sha256；不需要隧道就不要把 ngrok 装进镜像 |
| `cve-mcp-server.git@main`、ParamSpider 无 commit（Kali）、jwt_tool 等默认分支 | 中 | 改为完整 commit。个人仓库在合入镜像前应单独读一遍 |
| Trivy `install.sh` 来自 `main`、NodeSource、rustup、dotnet-install、Composer installer | 中 | 改为校验过的发布包，不要管道执行浮动脚本 |
| `python:*` / `node:22-*` / `golang:1-*` 无 digest | 中 | 构建机上 `docker pull` 后把 digest 写进 Dockerfile，或使用内部镜像仓库的不可变标签 |
| 插件运行器 requirements 与 TruffleHog checksum | 低（相对） | 保持。仍建议给基础镜像加 digest |
| 官方 npm 锁文件与 prisma/react/jose 本次无 OSV 记录 | 低 | 继续用 `npm ci`，不要 `npm install` 刷新锁而不审查 |
| 未锁的 `langchain`/`fastapi`/`requests` 等 | 未确认 | 用 `pip-compile --generate-hashes` 或 uv lock 生成锁再查 OSV。本次不能给出具体 CVE |

没有证据表明这些来源是仿冒包或已知恶意包投毒；证据是它们**可变、无校验、构建时出网**。对一个要在隔离实验室长期使用的系统，这已经足够构成供应链事故的入口。

---

## 4. 结论

### 4.1 总体评级

| 维度 | 等级 | 理由 |
| --- | --- | --- |
| 隐藏恶意代码 / 后门 | 低 | 与上游 `046921e6` 同一提交；未发现混淆载荷、隐蔽 C2、偷 SSH/浏览器数据后外发、恶意 postinstall |
| 产品自身的危险能力 | 高 | 设计上就能在容器内执行任意命令、跑漏洞利用、监听反弹 shell、可选把端口送到 ngrok |
| 默认配置 | 高 | 裸 compose 会起 GVM `admin/admin`、Agent/Web 绑 `0.0.0.0`、内部密钥 `changeme` 时 Agent 认证失败打开、`:4444` 对所有接口、Kali `seccomp:unconfined`、编排器持有 Docker 套接字 |
| 供应链 | 高 | Kali rolling、大量 `@latest`/`master`、几乎无镜像 digest、运行时自更新和 `docker pull` |
| 已知漏洞（已锁定版本） | 高 | `next@16.1.6`、两处 `mcp`、`fastmcp`、MCP TypeScript SDK、`mitmproxy~=11.1` 在 OSV 有记录 |
| **实验室自行部署** | **高** | 可以做，但必须隔离，并且不要把「脚本能装起来」当成「配置是安全的」 |

### 4.2 可否在隔离实验室使用

可以，前提是实验室满足下面全部条件：

- 专用虚拟机或专用物理机，不与办公网、生产网、跳板机路由互通。
- 构建和运行都经过出口过滤。至少在验收完成后切断对 GitHub raw、`kali.download`、Docker Hub、`bin.equinox.io`、PyPI、npm、`go.dev` 的访问，否则自更新和 `:latest` 仍会在下次启动时变。
- 只用 `./redamon.sh`，不要按 `docker-compose.yml` 文件头的裸 `docker compose up -d`。
- 扫描目标只包括实验室自己的靶场。本仓库的 `testing/guinea_pigs/` 就是这类靶场，其中有故意的老旧软件（例如 `node:8.17.0`）。
- 操作员理解：模型在确认开关关闭时，或操作员习惯性点批准时，会在 Kali 容器里执行任意命令。容器持有原始网络能力，编排器持有 Docker 套接字。

不满足隔离时，不建议安装。这不是因为树里藏了后门，而是因为默认姿势会把进攻工具和未修补的 Web 栈放到一个可被局域网访问的主机上，并且构建过程信任一大片可变的上游。

### 4.3 使用前必须做的加固

1. 生成并使用 `redamon.sh` 写入的随机密钥。确认 `.env` 里没有 `changeme`。不要手写 `AUTH_SECRET=changeme`。
2. 不要启用 GVM，除非确实需要。启用后确认 `GVM_PASSWORD` 已生成，且 `reconcile` 已经把 gvmd 的 `admin` 从 `admin/admin` 转走（`redamon.sh:2609-2613`）。在此之前不要把 GVM 所在的 Docker 网络暴露出去。
3. 将 Web `:3000` 和 Agent `:8090` 绑到 `127.0.0.1`，或直接使用 `tooling/deploy/single-host/compose/docker-compose.prod.yml` 的端口覆盖。裸 compose 的 `0.0.0.0` 不要用于任何多用户或多网卡主机。
4. 反弹 shell `:4444` 默认不要对实验室以外开放。不需要时不要映射这个端口。不要配置 ngrok token。
5. 设置 `MSF_AUTO_UPDATE=false`、`NUCLEI_AUTO_UPDATE=false`。去掉或改掉 `recon/entrypoint.sh` 里对 `trickest/resolvers` `main` 的下载和对 `:latest` 镜像的 `docker pull`，改为使用已经导出的本地镜像。
6. 保持 `REQUIRE_TOOL_CONFIRMATION` 与两个阶段审批为 `true`。不要为了演示把它们关掉。把 Agent 和 Kali 当作不可信代码执行环境。
7. 升级或替换：`next@16.1.6`、`mcp` 1.28.1/1.29.0、`fastmcp==3.2.4`、`@modelcontextprotocol/sdk@1.30.0`、`mitmproxy~=11.1`。升级前在隔离环境重新构建，不要在已有数据卷的机器上边试边暴露端口。
8. 给基础镜像加 digest；把 Kali 里的 `@latest`、`@master` 和 `git clone` 默认分支改成 commit，并对 ngrok、chisel、ysoserial、PEASS、Go tarball 做 sha256 校验。TruffleHog 与插件运行器的钉扎方式可以当模板。
9. `cve-mcp-server.git@main` 在钉 commit 之前不要当可信代码。本次未读该仓库，标「未确认」。
10. 日志与进程列表：接受工具参数会进 Agent 日志（`execute_tool_node.py:88-94`）。不要在会归档日志的环境里让模型携带真实令牌。不要开启 `kb-refresh`，除非能接受 Neo4j 口令出现在进程命令行。
11. 插件目录来自 `samugit83/redamon-plugins` 的 `master`。只在验证签名密钥与 `webapp/src/lib/plugins/keyring.ts` 一致之后安装插件。未审核的插件不要装。
12. 编排器与 docker-broker 等同于宿主机 root。不要在这台机器上挂载无关的生产密钥或 SSH agent。

### 4.4 本次没有做、因此不能声称的事

- 未运行容器，未验证 broker 过滤、认证中间件、GVM 口令轮换在运行时是否与源码一致。
- 未对未锁的 Python/Go 传递依赖做完整解析，因此不能给出「依赖树零 CVE」或「某条 `>=` 一定命中某个 GHSA」。
- 未下载 Kali `@latest` 当天的模块 zip，不能证明今天的 `latest` 与上游签名发布一致。
- 未审计 `redamon-plugins` 仓库和 `cve-mcp-server` 仓库的内容。
- 未对 `next` 的 38 条 advisory 做「本仓库默认路由能否触发」的逐条可达性分析。
