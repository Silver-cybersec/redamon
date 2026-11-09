# 静态细查补充（docker-broker、CodeFix、两个外部仓）

- 日期：2026-11-09
- 对象：本工作区 `master`，提交 `046921e65f7168bbc15946a257df4d14663e9b56`（`feat(settings): Save stays on screen in every Global Settings form`）
- 对照的原审计：分支 `cursor/security-audit-fb1c` 提交 `8c1663850dd2e53b65adb17b951b0ae1b419d865` 的 `SECURITY_AUDIT.md`（该文件不在 `master` 上）。下文「原审计」都指这一份
- 方法：只读。读了本仓库源码、Dockerfile、锁与清单，以及两个外部仓库的检出、发布包字节和公开漏洞库。没有运行镜像、二进制或仓库代码，没有 `pip install` / `npm ci`，没有 `docker run`，没有执行 `services/docker_broker` 里的测试，没有对任何扫描目标发包
- 文中「已核实」表示源码或所读字节支持该句。「有冲突」表示两处材料互相矛盾。「无法确认」表示要运行时或未读的材料才能下结论，不是暗示它有问题
- 宿主机根目录绑定的字面写法、密钥和可直接照做的请求不写入本文

`broker.py` 在上述提交上的 SHA-256：`fb60a94483e2aaba3fc4763ac23bd278875c2b7a531ef3bd393a9fbcf550faf9`。`agentic/Dockerfile` 的 SHA-256：`18e9f446af9a691ec596ffe44821d7fae752aa77c7f8faa9d6fa30efd9b65b1a`。

---

## 1. 结论摘要

| 项 | 一句结论 | 对原审计定级的影响 |
| --- | --- | --- |
| (1) docker-broker | 创建请求会拒绝它显式检查的那些字段（特权、套接字路径、词法上的宿主机根绑定、非白名单镜像）；其余大量 Engine API 原样转发，所以过滤层不是完整边界 | **上调**。原审计第 2.2 节把「过滤能否挡住宿主机根绑定」标为未确认。创建路径上的拒绝已经能从代码读出来，但未覆盖的 API 使「侦察容器只有过滤后的套接字」弱于文件头的承诺。实验室总体「高」维持：编排器仍然直接持有真实套接字 |
| (2) CodeFix 令牌与沙箱 | 令牌以明文项目列保存，并随项目 GET 回到所有者浏览器；交给 git 时不进 URL。沙箱进程环境是空的，能力被丢掉，根文件系统只读。网络是普通 bridge，不是无出网 | **维持**。原审计没有单列 CodeFix。沙箱「不持有该令牌」由代码证实，秘密仍以明文存在，日志脱敏只覆盖 git 的 stderr。不足以把第 2.5 节的秘密处理关注拿掉，也不必为此把总体再往上调 |
| (3) `redamon-plugins` 与 `cve-mcp-server` | 所读提交里没有混淆载荷，也没有插件或 CVE 服务自己起本地 shell。插件发布包的 SHA-256 与已签名目录一致。CVE 服务仍由 `git @main` 安装，锁文件不参与这次安装 | **下调**「这两个仓库没读过、因此可能藏着后门」。`@main` 不锁定，原审计供应链「高」维持 |

---

## 2. 逐项细查

### 2.1 docker-broker

状态：**已核实**（过滤函数与转发分支）；若干条「daemon 会不会照做」为 **无法确认**，写在第 4 节。文件头与后文有一处 **有冲突**。

#### 谁拿着哪只套接字

| 角色 | 证据 | 套接字 |
| --- | --- | --- |
| broker 进程 | `docker-compose.yml:409` 把宿主机 Docker 套接字挂进容器；`broker.py:49` 默认上游就是这只套接字 | 真实套接字。进程被攻破等于宿主机上的 Docker 控制面。原审计这一点维持 |
| 编排器 | `docker-compose.yml:461` | 真实套接字。CodeFix 沙箱由它创建，不经过 broker |
| 全量侦察、部分侦察、供应链扫描 | `recon_orchestrator/container_manager.py:1273`、`2568`、`5116` 设置 `DOCKER_HOST` 指向 broker 套接字；`1293`、`2588`、`5149` 把命名卷 `redamon_broker_socket` 挂到 `/var/run/broker` | 过滤后的套接字 |
| 监听权限 | `broker.py:819` 把监听套接字设为 `0660`。套接字在命名卷上，不映射宿主机端口（`docker-compose.yml:410`、`1629-1630`） | 能打开该卷里这只套接字的容器，就是过滤层的调用方 |

打开文档（`broker.py:15-18`）写的是：除了 `POST /containers/create`，其余都透明转发。后面的 E1 又给一部分「操作已有容器」加了所有权门（`153-168`、`682-714`）。**有冲突**：文件头没有把后来加上的门算进去，也没有改掉「只校验创建」这句话。默认转发这一支仍然在（`773-793`）。`test_plumbing.py:114-118` 把「非创建请求会被转发」写成测试应有的行为。这些测试本次没有运行。

#### 创建请求：会拒绝什么

只在方法为 `POST` 且归一化后的路径匹配 `^/(v[\d.]+/)?containers/create$` 时进入 `validate_create`（`149`、`171-179`、`731-742`）。归一化会去掉查询串、折叠重复斜线、去掉末尾斜线。路径本身不解码百分号。

`validate_create`（`233-314`）对正文做这些检查。镜像名先经 `_canonical_image`（`90-117`）：去掉一层 `docker.io/` 或 `index.docker.io/`，再去掉官方镜像的 `library/`。比对的是字符串，不是内容摘要。默认名单在 `53-80`，几乎都是 `:latest` 或 `:stable`，外加 `dolevf/graphql-cop:1.14`。环境变量 `DOCKER_BROKER_ALLOWED_IMAGES` 会并进名单（`87`）。

| 字段 | 结果 |
| --- | --- |
| `Image` 不在名单，或为空 | 拒绝 |
| `HostConfig.Privileged` 为真 | 拒绝 |
| `CapAdd` 里有 `NET_RAW` / `NET_ADMIN` 及其 `CAP_` 前缀以外的能力 | 拒绝（`147`） |
| `Devices` 非空 | 拒绝 |
| `PidMode` / `IpcMode` / `UsernsMode` / `CgroupnsMode` 以 `host` 或 `container:` 开头 | 拒绝 |
| `NetworkMode` 以 `container:` 开头 | 拒绝。`host` 不拒绝。`test_policy.py:51` 把宿主机网络写成应放行 |
| `VolumesFrom` 非空 | 拒绝 |
| `MaskedPaths` 或 `ReadonlyPaths` 出现（含空列表） | 拒绝 |
| `SecurityOpt` 的字符串里含有 `unconfined` | 拒绝。不含这个子串的值不拒绝 |
| `Binds` 的源不是允许前缀，或归一化后是根路径，或路径字符串里含有 `docker.sock` | 拒绝（`204-217`） |
| 允许前缀上的宿主机路径要读写挂载，但前缀不在读写名单 | 拒绝（`279-288`、`297-303`） |
| `Mounts` 的 `Type` 不是 `bind` 或 `volume`，且 `Type` 非空 | 拒绝 |
| 卷名不在 `ALLOWED_VOLUMES` | 拒绝 |

绑定源用 `os.path.normpath`（`211`）。这是词法归一：`..` 会被折回去，`/tmp/redamon` 与 `/tmp/redamon-evil` 不会被当成同一个前缀（`214` 要求相等或以「前缀加斜线」开头）。它不调用 `realpath`，因此不看符号链接。

通过校验之后，broker 会改写正文：压入内存和 pid 上限（`379-394`）、打上 `redamon.broker-owned=1`（`397-405`）、按请求头重写运行标签（`432-445`）。这一支会重写 `Content-Length`（`783-786`）。创建正文不是「原样转发」。

拉取（`POST /images/create`）另走 `validate_pull`（`586-596`、`765-771`）。它只读查询参数 `fromImage` 和 `tag`。上游 Moby 在 `fromImage` 非空时走拉取，否则走导入（见 2.1 末的上游引用，`image_routes.go:65-117`）。`fromImage` 为空时 `_image_allowed` 为假，导入这条会被 broker 拒绝。**已核实**：单靠 `fromSrc`、不带允许的 `fromImage`，过不了 broker。两边同时带时，上游走进拉取分支，不走进导入分支。

#### 创建请求：不看什么

下面这些 `HostConfig` 字段不在 `validate_create` 里。这是代码缺口，不是已经跑通的绕过。daemon 是否接受它们，本次未运行。

- `Sysctls`、`DeviceCgroupRules`、`DeviceRequests`、`CgroupParent`、`Runtime`、`UTSMode`、`CapDrop`、端口发布
- `Mounts` 里 `Type` 为空或缺失的项：循环直接跳过（`291-312` 只有 `bind`、`volume` 和非空的其他类型）
- `SecurityOpt` 里不含 `unconfined` 的值，包括指向一份配置文件的值
- `Mounts` 上的 `BindOptions`（传播方式等）不读
- 镜像引用的摘要形式。名单是标签字符串。`projectdiscovery/naabu:latest` 在名单里，同一个仓库的摘要引用不在

读写卷的条件有一处和注释相反。注释（`129-131`）说 `redamon-sca-intel` 不在 `ALLOWED_RW_VOLUMES` 里，所以只能只读。条件是（`307-310`）：

```text
源卷名存在，且不是 ReadOnly，且 ALLOWED_RW_VOLUMES 非空，且卷名不在该集合
```

`ALLOWED_RW_VOLUMES` 只来自环境变量（`143`）。compose 没有设置 `DOCKER_BROKER_ALLOWED_RW_VOLUMES`。集合为空时，第三个合取为假，读写检查不执行。默认并集里的卷名是 `nuclei-templates`、`redamon-osv-db`、`redamon-sca-intel`（`132-133`），再加上 compose 再写一次的 `nuclei-templates`（`docker-compose.yml:419`）。**有冲突**：注释描述的「不在读写名单就不能写」在默认空集合下不成立。这允许把这些名字读写挂进容器。名字本身不是宿主机路径。和下面未过滤的卷 API 合在一起，才是「名单里的名字可以指向别处」。

compose 的绑定前缀（`418`）是 `/tmp/redamon` 加上 `${PWD}`，`PWD` 为空时退回作者机器上的一条路径。原审计已经记下这条。读写前缀默认仍只有 `/tmp/redamon`（`141-142`、`438` 把额外读写前缀默认成空）。仓库树可以被只读绑定，默认不能被读写绑定。宿主机根目录不在前缀里，创建路径的词法检查会拒绝它。

#### 已有容器：所有权门覆盖哪些动词

`_CONTAINER_OP_RE`（`163-166`）在任意方法上匹配这些结尾：`exec`、`start`、`stop`、`kill`、`restart`、`wait`、`logs`、`archive`、`pause`、`unpause`、`update`、`rename`、`resize`。容器标识不带 `redamon.broker-owned=1` 就拒绝，并且不把该操作转到上游（`688-696`、`507-509`）。`attach` 在劫持分支里再查一次（`167`、`699-704`）。`GET /containers/json` 会被改写，强制带上这个标签（`550-583`、`713-714`）。直接按名字 `GET /containers/{id}/json` 不在这组动词里。

`POST /exec/{id}/start` 在劫持正则里（`150`），不再按容器所有权查一遍。代码注释把这一点放在「exec 的创建已经查过」上（`685-686`）。exec 标识从创建响应里来。本次没有测量该标识的熵。

`update` 的正文不重新经过 `validate_create`。

#### 原样转发的 API，以及上游是否真有这些路由

broker 只为上面三类路径做决定。下表是同一类调用在上游 Moby `master` 提交 `3111b9d71267cf3d970f3750a0d66a149b57e759`（2026-11-09 读取的 `master` SHA）里的注册。实验室安装的引擎版本没有查询，所以「本机 daemon 仍提供该路由」是 **无法确认**。路由在该提交的源码里存在，是 **已核实**。

| 上游路由 | 上游位置 | broker |
| --- | --- | --- |
| `POST /containers/create` | `daemon/server/router/container/container.go:42` | 校验 |
| `POST /images/create` | `daemon/server/router/image/image.go:42` | 只校验 `fromImage` / `tag` |
| `POST /images/load` | `image.go:41` | 转发 |
| `POST /images/{name}/tag` | `image.go:44` | 转发 |
| `POST /build`、`/build/prune`、`/build/cancel` | `daemon/server/router/build/build.go:34-36` | 转发 |
| `POST /commit` | `container.go:58` | 转发。查询参数可以选择任意容器，不经过所有权门 |
| `GET /containers/{name}/json` | `container.go:34` | 转发。响应含容器配置 |
| `GET /containers/{name}/top`、`/stats`、`/export` | `container.go:32-37` | 转发 |
| `GET /containers/{name}/attach/ws` | `container.go:38` | 转发。路径不以 `/attach` 结尾，三个正则都不匹配 |
| `DELETE /containers/{name}` | `container.go:62` | 转发。操作正则没有 delete |
| `POST /containers/prune` | `container.go:57` | 转发 |
| `POST /volumes/create`、`PUT /volumes/{name}`、`DELETE /volumes/{name}` | `daemon/server/router/volume/volume.go:33-38` | 转发。创建处理把 `DriverOpts` 交给卷后端（`volume_routes.go:125`） |
| `POST /networks/create`、`POST /networks/{id}/connect` | `daemon/server/router/network/network.go:36-37` | 转发。创建时的 `NetworkMode=container:` 拒绝不覆盖事后把容器接进另一个网络 |
| `POST /plugins/pull`、`POST /plugins/create` | `daemon/server/router/plugin/plugin.go:33`、`37` | 转发 |
| `POST /session` | `daemon/server/router/session/session.go:30` | 转发。上游注释写明该端点已弃用，仍注册着 |
| `POST /grpc` | `daemon/server/router/grpc/grpc.go:65` | 转发 |
| `POST /swarm/init`、`POST /services/create`、`GET /swarm/unlockkey` | `daemon/server/router/swarm/cluster.go:27`、`31`、`37` | 转发。Swarm 没开时 daemon 通常会拒绝管理类调用；本机是否开了 Swarm 未查 |

镜像名单比对的是引用字符串。`load`、`tag`、`build`、`commit` 都能在 daemon 上产生或改写本地镜像名，而创建请求只检查名字。这是允许名单被换内容的类，不是「创建函数没写拒绝特权」。构建和插件接口在上游的职责就是在 daemon 侧构建镜像或安装插件。具体请求体不写入本文。

卷名单比对的是卷名。卷的创建和删除不进 `validate_create`。上游创建函数接受驱动选项。因此名单中的卷名可以在创建容器之前被换成另一个后端。驱动参数的写法不写入本文。

符号链接是另一类，而且停在静态推理：侦察、部分侦察和供应链容器都以读写方式挂着 `/tmp/redamon`（`container_manager.py:1308`、`2597`、`5137`）。broker 只对路径字符串做词法检查。daemon 是否跟随链接，未运行。

创建路径上，直接把宿主机根目录或套接字路径写进它检查的 `Binds` / `Mounts` 字段，会被拒绝。这一点和 `test_policy.py` 里对应的拒绝用例一致；那些用例本次没有执行。文件头承诺的「不能逃到宿主机」覆盖不了上表里原样转发的那些路由。

基础镜像 `services/docker_broker/Dockerfile:9` 是 `python:3.12-alpine`，无摘要。2026-11-09 该标签在 Docker Hub 上的清单摘要是 `sha256:e064671ca452259bab50e8e2c7bd896e39e9a343bb06ca25234adf6fe18d0fc7`（标签更新时间 `2026-11-06T08:07:25Z`），amd64 子清单 `sha256:a61cbd76a882645de7f91423329fe43a67eed60d7da24f9e5331414bb3618b20`。这是查询当日标签指向哪里，不是本仓库某次构建用过的摘要。镜像没有拉取，也没有运行。

### 2.2 CodeFix：令牌与沙箱

状态：令牌路径和沙箱参数 **已核实**。Dockerfile 开头与后文 **有冲突**。提示词里的工具链和镜像里安装的包 **有冲突**。网桥能否摸到宿主机上对所有接口发布的端口，**无法确认**（未做连通测试）。

#### 获取和保存

项目列是普通字符串，默认空，没有应用层加密字段：

- `webapp/prisma/schema.prisma:1363` `cypherfixGithubToken`，列名 `cypherfix_github_token`
- 注册表 `webapp/src/lib/reconSettings/registry.json:2101-2113`：`group` 为 `secret`，`mcp` 为 `never`，`readable` 为 `false`，`read_deny_reason` 为 `credential`

`GET /api/projects/[id]` 在去掉 RoE 二进制之后，把其余 Prisma 标量放进 JSON（`webapp/src/app/api/projects/[id]/route.ts:126-151`、`191`）。浏览器调用者要先过项目所有权（`88-94`）；内部密钥和扫描器密钥可以读任意项目（`88`）。两条路都不会剥掉这个列。注册表自己把「项目 GET 会摊开每一个标量」写成了另一项凭据改用关联表的理由（`registry.json:15485`）。设置表单把该字段绑在 `type="password"` 的输入上（`webapp/src/components/projects/ProjectForm/sections/CypherFixSettingsSection.tsx:147-152`）。输入框不显示字符，响应体里仍是全文。

MCP 读路径用 `readable !== false` 过滤（`webapp/src/lib/reconSettings/registry.ts:279-281`，`webapp/src/lib/mcpReadableFields.ts:44-47`）。这个列两边都不满足，不会出现在 MCP 的设置投影里（`webapp/src/lib/reconSettings/filter.ts:279-288`）。**已核实**：MCP 不读它；项目 GET 和内部调用方会读到全文。

代理启动时用内部密钥拉项目，把该字段放进 `github_token`（`agentic/cypherfix_codefix/project_settings.py:18-24`）。系统提示只写入仓库名和分支（`agentic/cypherfix_codefix/prompts/system.py:34`），不写入令牌。仓库名只取项目设置，不取整改记录里的 `targetRepo`（`orchestrator.py:182-186`）。

#### 传递

`GitHubRepoManager`（`agentic/cypherfix_codefix/tools/github_repo.py`）：

- 克隆 URL 只有用户名 `x-access-token`，没有口令（`121-122`）
- 口令放在子进程环境 `GIT_PASS`；`GIT_ASKPASS` 指向一个临时脚本，脚本内容是读这个环境变量并写到标准输出（`79-95`）。令牌字面量不写进脚本文件
- 脚本用 `tempfile.mkstemp`，模式 `0700`（`84-87`）。注释写明不要放在共享卷上。共享卷是 `cypherfix-work`（`docker-compose.yml:503`、`969`）
- 每次 git 都带 `-c core.hooksPath=/dev/null`（`98-100`）
- 环境是代理容器的全部环境再加上上述两个变量（`91-95`）。没有清空 `credential.helper`。镜像里只看到把 git 的 HTTP 版本设成 HTTP/1.1（`agentic/Dockerfile:167-168`），没有配置凭据助手。助手是否会在某次运行里被别处打开，**无法确认**
- 推送拒绝默认分支以及 `main` / `master`，并要求配置的前缀（`179-191`）。允许的分支会 `--force`
- 拉取请求用 PyGithub，令牌留在代理进程里（`199-202`）

克隆之后对整个工作区 `chmod -R a+rwX`（`137-139`），包括 `.git`。沙箱侧再用第二个挂载把 `.git` 标成只读（见下）。卷上的目录模式本身是其他人可写。

#### 日志和落盘的脱敏

`_sanitize` 只在令牌非空时做一次精确子串替换（`106-109`）。它用在 git 失败后放进异常消息的 stderr 上（`130-131`、`150`、`166`、`177`、`194-196`）。标准输出不记。百分号编码或被拆开的同一令牌不会被这行替换。

这些路径不经过 `_sanitize`：

- `logger.exception("Clone failed")` 和 `logger.exception("PR creation failed")`（`orchestrator.py:218`、`544`）会记异常文本。git 失败的异常文本已经替换过。`create_pr` 抛出的 PyGithub 异常没有先替换。本次没有读进镜像的 PyGithub 源码，响应体是否回显令牌 **无法确认**。Python 的 traceback 记的是源码行，不是局部变量的值
- 失败时 `agentNotes` 写成 `Push/PR failed: {e}`（`545-548`）。git 路径的 `{e}` 已替换；PyGithub 路径没有
- 工具入参在 DEBUG 全量记录，`github_bash` 的命令在 INFO 保留前 200 字符（`336-339`、`407-419`）。系统提示不含令牌，所以命令里出现令牌只能是模型自己写进去。这里没有再做一次替换
- 工具输出在 DEBUG 全量记录，完成回调保留前 500 字符（`435-437`）。沙箱输出不经过 `_sanitize`

原审计第 2.5 节写的是主代理 `execute_tool_node.py` 的工具参数日志。CodeFix 是另一条日志路径，git stderr 比那条窄，调试输出和整改备注仍是原文。

#### 沙箱隔离

构建命令不在代理容器里执行。`github_bash` 把命令交给 `sandbox_client`（`agentic/cypherfix_codefix/tools/bash_tool.py:15-23`）。客户端用内部密钥调 webapp（`sandbox_client.py:24-53`）。webapp 只允许 `start` / `exec` / `stop`，并改用编排器密钥转发（`webapp/src/app/api/internal/codefix-sandbox/[jobId]/[action]/route.ts:11-37`）。编排器对除健康检查和 CORS 预检以外的请求校验编排器密钥，密钥为空则拒绝（`recon_orchestrator/api.py:757-776`）。代理按设计持有内部密钥，因此被攻破的代理仍能让沙箱执行命令。边界是沙箱，不是这条 API 不存在。

作业标识在代理和编排器各滤一遍，只留字母、数字、下划线和连字符（`orchestrator.py:180`，`container_manager.py:1351-1357`）。`.` 会被换成 `_`，不能再构成 `..` 路径段。

`start_codefix_sandbox`（`container_manager.py:1417-1442`）的参数：

| 参数 | 值 | 含义 |
| --- | --- | --- |
| 镜像 | `CODEFIX_SANDBOX_IMAGE`，compose 默认 `redamon-codefix-sandbox:latest`（`docker-compose.yml:516`） | 无摘要。不在 broker 的镜像名单里。创建走编排器的真实套接字（`1344-1345`） |
| 网络 | `networks.create(name, driver="bridge")`（`1370-1377`） | 没有 `internal=True`，没有对端服务。compose 不定义这个网络，因为没有任何服务接入它（`1365-1368`）。默认 bridge 有出网地址转换。这和系统概览里「有 NAT、没有 RedAmon 对端」一致，弱于「没有网络」 |
| `cap_drop` | `["ALL"]`，没有 `cap_add` | 不保留 Docker 的默认能力集 |
| `read_only` | `True` | 根文件系统只读 |
| `tmpfs` | `/tmp`，`size=1g,exec` | 缓存可执行。注释写明安装器要从这里跑辅助程序（`1429-1431`） |
| `environment` | `{}` | API 不注入变量。镜像 ENV 仍在（`scanners/codefix_sandbox/Dockerfile:52-58`），其中没有令牌 |
| 卷 | 工作区读写；`工作区/.git` 只读（`1437-1440`） | 两个挂载都写在同一次 `containers.run` 里。嵌套只读挂载在运行时是否盖住下层，未执行 |
| 用户 | 调用里没有 `user=` | 依赖镜像 `USER sandbox`（Dockerfile `60`），uid `1001`（`36`）。`exec_run` 也没有 `user`（`1471-1476`） |
| 特权、宿主机 pid / 网络、`security_opt` | 都没设置 | 不会变成特权容器，也不会加入宿主机网络命名空间 |
| 资源 | 内存默认 `2g`，2 CPU，pid `512`（`554-556`、`1432-1434`） | 限额，不是隔离边界 |
| 命令通道 | `timeout -k 10 <秒> bash -c <命令>`（`1471-1474`） | 命令来自模型。超时夹在 1 到 1800 秒（`1466`）。没有命令白名单，这是功能 |

`no-new-privileges`：**有冲突**。Dockerfile `8-10` 的文件头把它写成启动器会设置的加固。同文件 `44-48` 和 `container_manager.py:1422-1426` 写明故意不设置，因为在一类 snap Docker 与 AppArmor 的组合上它会让非 root 的 `execve` 失败。替代措施是构建时去掉本层文件系统上的 setuid / setgid 位（Dockerfile `44-49`）。工作区和 `/tmp` 不在这层只读根里。沙箱用户新建的文件属主是 1001，把 setuid 打在自己的文件上不会变成 root。镜像里原本属于 root 的 setuid 位在构建时清掉。运行之后有没有被别的层加回来，未构建镜像，**无法确认**。

提示词 **有冲突**。`prompts/system.py:40-49` 列出 Go、Java、Ruby、PHP、.NET、`jq`、`wget`、`ssh`。Dockerfile `21-31` 安装的是 Python 3、pip、venv、git、ripgrep、CA 证书、curl、build-essential、coreutils，基镜像是 Node 20。隔离判断以 Dockerfile 和 `start_codefix_sandbox` 为准，不以这段提示词为准。

镜像 `FROM node:20-bookworm-slim`（Dockerfile `16`），无摘要。2026-11-09 Docker Hub 该标签的清单摘要是 `sha256:2cf067cfed83d5ea958367df9f966191a942351a2df77d6f0193e162b5febfc0`（标签更新时间 `2026-04-22T08:38:28Z`），amd64 子清单 `sha256:3d0f05455dea2c82e2f76e7e2543964c30f6b7d673fc1a83286736d44fe4c41c`。未拉取、未运行。

从沙箱到宿主机上 `0.0.0.0` 发布端口的连通性没有测试。代码能确定的是：网络不是 `internal`，也没有第二条禁止出网的规则。编排器 API 绑在 `127.0.0.1`（`docker-compose.yml:459`），这和「容器经网关访问环回发布」不是同一件事，本次也不把后者写成已测到。

### 2.3 两个外部仓库

#### `samugit83/redamon-plugins`

检出：`master` 提交 `fc62e5bf6f79e15b11ffcb77dbd4df592bdbadf7`，2026-10-14 15:01 +0200，说明 `docs(skiller): bring the docs in line with 1.1.0`。浅克隆，只这一层。标签 `skiller-v1.0.0` 指向 `4a12937cfd844e27cd4fc25ca6202301523fa164`，`skiller-v1.1.0` 指向 `4a8cd78f9d424b4510958eff206252733225ef10`。

本仓库不把这个 git 树装进进程。默认目录 URL 是 `master` 上的 `catalog.json`（`webapp/src/lib/plugins/catalog.ts:29`）。验的是 Ed25519 签名、序号和每个包的 SHA-256。keyring 里的官方密钥（`webapp/src/lib/plugins/keyring.ts:19-23`）`keyId` 为 `ee4a2df9065d36b1`。本次用该公钥的原始 32 字节对检出的 `catalog.json` 做了 Ed25519 校验，结果为通过。公钥 SHA-256 的前 16 个十六进制字符等于这个 `keyId`。`catalog.json` 的 SHA-256 是 `1d810a75eb2746fc49ae93a947ca9513ebdfce0acf1e39cff4596e9756e331b8`。签名文件的 SHA-256 是 `9f742499944866e386707de62e34988d77462288a39a244c13e5c3b751265465`。目录 `serial` 为 3，`revoked` 为空，只有插件 `skiller`。

发布包只下载、计算 SHA-256 并列了 tar 成员，没有执行成员里的文件。

| 版本 | 目录中的 SHA-256 | 下载字节的 SHA-256 | 结果 |
| --- | --- | --- | --- |
| 1.0.0 | `5e1aaa40ba89bf098b782232b49739c5710245ebe49fa00f76211bb803747b4b` | 相同 | **已核实** |
| 1.1.0 | `801afb494b79d793dde51ac1f1e9a34b6878750402f5d23759764c047a4f4391` | 相同 | **已核实** |

1.1.0 包内是 `plugin.json`、`README.md`、`CHANGELOG.md` 和 `engine/` 下 12 个 Python 文件。没有原生二进制、没有 wheel。`plugin.json` 的权限是 `session:read`、`llm:invoke`、`override:skill.text`、`override:user_skill.text`。动作入口是 `engine/main.py:analyze_session`。

`skiller/engine/` 里没有 `subprocess`、`os.system`、`eval`、`exec` 或自行发往任意主机的 HTTP 客户端。出站只有随 SDK 拷进仓库的 Gateway 客户端：只向配置的 Gateway 基址追加固定前缀，禁止环境代理，禁止跟随重定向（`.platform-sdk/1.1.0/redamon_plugin_sdk/client.py:41-63`、`71-79`）。`tools/requirements-tools.txt` 是这个仓库自己的打包和测试依赖，注释写明插件代码不导入它们。其中 `cryptography==45.0.7` 的 OSV 见第 3 节。它不在 RedAmon 安装插件的路径上。

`file` 对检出文件的分类是文本、两张图片和 shell 脚本。没有 ELF 或共享库。「Python script, executable」是 shebang 的文件类型，不是独立二进制。

发布工作流把第三方 action 钉在完整 SHA 上，打包容器使用带摘要的 `python:3.11-slim`（`.github/workflows/release.yml:23`、`33`、`77`）。签名发生在名为 `release` 的环境保护规则之后。本次没有登录 GitHub 去核对环境保护规则是否真的要求人工批准，这一点 **无法确认**。

目录 URL 仍是 `master` 上的原始文件。签名通过只说明「这份字节是这把密钥签的」，不说明下一次 `master` 不会换成另一份同样签过的目录。序号防的是回滚，不防持有这把密钥的人发布新目录。

#### `mukul975/cve-mcp-server`

检出：`main` 提交 `d666bac3743574cecc98bcbf524558c2bf0d8e61`，2026-06-22 18:51 +0200。标签 `v0.2.0` 的提交是 `43c33955232306af792806ecee7beafdd1c8600e`，`v0.1.0` 是 `cd79e93b0beb150dbf9272b06bed76a87e174899`。`main` 与 `v0.2.0` 相差 6 个文件。抽查 `server.py` 与 `validators.py` 的差异是引号和换行，不是新的出站目标。RedAmon 哪一个都不钉。

安装行是 `agentic/Dockerfile:167-168`：

```text
pip install --no-cache-dir "git+https://github.com/mukul975/cve-mcp-server.git@main"
```

控制台脚本 `cve-mcp` 指向 `cve_mcp.server:main`（上游 `pyproject.toml:43-44`）。代理预设调用的就是这个名字（`webapp/src/lib/mcp/presets.ts:850`），可选环境变量是 `NVD_API_KEY` 和 `GITHUB_TOKEN`（`852`）。进程跑在代理容器里，传输是 stdio。上游自己的 Dockerfile 不会被这条 `pip` 使用。

`src/` 下没有 `subprocess`、`os.system`、`eval`、`exec` 或 `pickle`。出站是 `httpx`。`server.py:109-114` 的共享客户端 `verify=True`、`follow_redirects=True`、最多 3 次重定向。`validators.validate_outbound_url`（`validators.py:119-135`）实现了协议名单、主机名单和「解析到非公网地址则拒绝」。全仓库检索，这个函数只有定义、没有调用点。实际请求的主机写在各客户端的常量里（`config.py:78-122`）：NVD、OSV、EPSS、CISA KEV、GitHub、MITRE、VulnCheck、CIRCL、HIBP 的口令范围接口、Shodan、VirusTotal、urlscan、crt.sh、AbuseIPDB、GreyNoise、Microsoft、Red Hat、Ubuntu、ThreatFox、Ransomwhere，以及 `raw.githubusercontent.com` 上的 KEV 备用文件和 MITRE ATT&CK 的 `master`。调用方输入进的是这些主机上的查询参数，不是请求的主机名。重定向是否被客户端跟到名单外，代码允许跟，本次没有发这些请求，运行结果 **无法确认**。

`poc_checker.py:16-18` 拉取 Exploit-DB 的 CSV（上限 8 MB，`19`）并查询 GitHub。读到的函数把 CSV 当表格解析，没有把内容交给解释器。`dependency_scan.py:338-401` 在配置了 `GITHUB_TOKEN` 时查询 GitHub 代码搜索。这些是声明过的情报功能。没有本地执行 PoC 的调用。

`config.py:9-15` 承认密钥同时以 `SecretStr` 和普通字符串存在，因为大约 20 个模块仍导入普通字符串（`66-68`）。普通字符串会进进程内存。没有看到把整个 `os.environ` 发到某个固定外带地址的代码。

`validate_outbound_url` 未被调用，和 `server.py:12-16` 的注释 **有冲突**。注释要求新的 URL 先过这个函数；现有调用点没有这样做。现有调用点使用的是上面的常量主机。

上游 `uv.lock` 的 SHA-256 是 `e8c3af7eb6df726cbb0305e49a1814db14f7a0a49229351b0026e151cc0ca39d`。它给直接和传递依赖写了 PyPI URL 和 SHA-256。`pyproject.toml:23-31` 的直接依赖仍是下界：`mcp[cli]>=1.7.0`、`httpx>=0.27.0`、`aiosqlite>=0.20.0`、`cvss>=3.0`、`python-dotenv>=1.0.0`、`pydantic>=2.0.0`、`pydantic-settings>=2.0`、`defusedxml>=0.7.1`。没有安装钩子，构建后端是 hatchling。

上游 Dockerfile `41-49` 的注释说仓库里没有 `uv.lock`，所以不能 `--frozen`。同一提交里 `uv.lock` 存在，但 Dockerfile 的 `COPY` 没有把它拷进去，`uv sync` 也没有 `--frozen`。**有冲突**：注释的前提是错的，构建命令的效果仍是不按锁安装。RedAmon 的 `pip install git+...@main` 同样不读 `uv.lock`。锁里的版本不能当成代理镜像里已经装上的版本。

PyPI 上有同名发行版 `cve-mcp-server`，最新 0.5.0，上传于 2025-05-09，无作者、无主页、无 `project_urls`。sdist SHA-256 `47b86ae2bbc1ae114d691c74ffb119a77dbd6891b99f908ebd26941541810bd7`，wheel SHA-256 `4d2f57cfc4e5b5988b9abf9e3269350f9ffb3ec9fa7cb0403cd215a55009a528`。读了 sdist，没有执行。它的导入包是 `cve_mcp_server`，控制台脚本是 `cve-mcp-server`，依赖是 `mcp` 和 `requests`。源码查询 MITRE 的 CVE JSON，并把一份 nuclei 模板正文取回来放进返回值，没有 `subprocess`。`pyproject.toml` 里有一段腾讯 PyPI 索引，只存在于这个 sdist，RedAmon 的安装行不使用它。**已核实**：这不是 `mukul975/cve-mcp-server` 的 0.2.0 树。RedAmon 用 git URL 和脚本名 `cve-mcp`，不会装到这个 wheel。同名仍是一条看名字安装就会装错的路径。OSV 对 `cve-mcp-server` 0.5.0 和 0.2.0 都没有记录；0.2.0 本来也不是 PyPI 上的那个树。没有记录不等于已经鉴定为恶意或清白，只是这个库在查询日没有给这个名字编号。

---

## 3. 供应链补充

查询日 2026-11-09。OSV 用的是 `https://api.osv.dev/v1/querybatch` 和 `https://api.osv.dev/v1/vulns/<id>`。只对文件里写死的版本，或查询当日 PyPI 元数据里的版本下结论。`>=` 在不安装的前提下没有解析，标无法确认。

### 3.1 版本锁定

| 来源 | 锁定 | RedAmon 实际用不用 |
| --- | --- | --- |
| `cve-mcp-server` `uv.lock` | 有包版本和每个 wheel / sdist 的 SHA-256。直接相关的锁定版本：`mcp==1.28.0`、`httpx==0.28.1`、`cryptography==49.0.0`、`starlette==1.3.1`、`uvicorn==0.49.0`、`sse-starlette==3.4.5`、`pydantic==2.13.4`、`h11==0.16.0`、`defusedxml==0.7.1`、`python-dotenv==1.2.2`、`aiosqlite==0.22.1`、`cvss==3.6` | **不用**。`pip install git+...@main` 不读 uv 锁。上游 Dockerfile 也不拷贝这把锁 |
| `pyproject.toml` | 只有下界 | 这是 pip 会拿去解析的那一份 |
| 插件 `catalog.json` | 每个 tar 有 URL 和 SHA-256，目录有签名和序号 | **用**。本次下载的两个包与目录摘要一致 |
| `tools/requirements-tools.txt` | 全部 `==`，注释要求 `--no-deps` | 只用在插件仓库自己的 CI / 工具里 |
| broker、CodeFix 基镜像 | 浮动标签，无摘要 | 构建或拉取时取标签当时的内容 |
| PyPI `cve-mcp-server` 0.5.0 | 发行文件有 SHA-256 | RedAmon 的 Dockerfile 不安装这个名字 |

2026-11-09 PyPI 元数据里的 `mcp` 最新版本是 `2.3.0`，未标记 yanked。一次在这一天执行的 `pip install 'mcp[cli]>=1.7.0'` 会解析到这个版本还是别的版本，取决于解析器和依赖交集，本次没有执行 pip，**无法确认**已经建好的 `redamon-agent` 镜像里装的是哪一版。能确定的是 Dockerfile 没有把它钉死。

### 3.2 OSV / GHSA

`mcp==1.28.0`（只存在于未被使用的锁里）6 条：

| ID | 摘要 | 修复版本（OSV 事件） |
| --- | --- | --- |
| GHSA-vj7q-gjh5-988w / PYSEC-2026-3483 | WebSocket 服务端传输没有 Host / Origin 校验 | `1.28.1` |
| GHSA-5h93-6whr-6q8j | HTTP 客户端跟随跨源重定向时带走自定义头和正文 | `1.30.0`（2.x 线为 `2.2.0`） |
| GHSA-84m7-p3x7-pcfv | Streamable HTTP 会话无上限 | `1.30.0` |
| GHSA-rwrf-2pqf-9j8j | 按服务端给出的 `$ref` URL 去拉取以校验工具结果 | `1.30.0` |
| GHSA-w4fh-qvv9-3v23 | 服务端 bearer 接受发给其他资源服务器的令牌 | `1.30.0` |

`mcp==1.30.0` 和查询当日的 `mcp==2.3.0` 在这次查询中无记录。无记录只覆盖查询日。若构建日解析到 `2.3.0`，上表的 1.28.0 条目不自动落到镜像里；下一次解析仍可能变。

`cryptography==49.0.0`（锁内，未被 RedAmon 的 pip 行使用）：GHSA-g6cj-pr64-35w5 / PYSEC-2026-3552，PKCS#7 EnvelopedData 解密的错误和时序可区分，修复点 `50.0.0`，引入点 `44.0.0`。`cryptography==45.0.7`（插件仓库 `tools/requirements-tools.txt:7`）除这一条外还有 11 条，其中 GHSA-537c-gmf6-5ccf、GHSA-jwv3-5hgf-82ww、GHSA-m2h6-j472-rp4c、GHSA-m959-cc7f-wv43、GHSA-p423-j2cm-9vmq、GHSA-r6ph-v2qm-q3c2，以及 PYSEC-2026-2141、PYSEC-2026-35、PYSEC-2026-3553、PYSEC-2026-3554、PYSEC-2026-36。这条 pin 不进入 Skiller 的运行进程。

以下锁定版本在本次查询中无记录：`httpx==0.28.1`、`starlette==1.3.1`、`uvicorn==0.49.0`、`sse-starlette==3.4.5`、`pydantic==2.13.4`、`h11==0.16.0`、`defusedxml==0.7.1`、`python-dotenv==1.2.2`、`aiosqlite==0.22.1`、`cvss==3.6`。

PyPI 同名包依赖的 `requests>=2.32.3` 若解析到 `2.32.3`：GHSA-9hjg-9r4m-mvj7（`.netrc` 经恶意 URL 泄露，修复 `2.32.4`）、GHSA-gc5v-m9x4-r6x2（`extract_zipped_paths()` 的临时文件重用，修复 `2.33.0`），以及 PYSEC-2026-1872、PYSEC-2026-2275。RedAmon 的 git 安装不依赖 `requests`。这个条目只属于那个同名 PyPI 树。

没有一条 OSV 编号以 `MAL-` 开头出现在上述结果里。这只说明这些精确版本没有被 OSV 标成恶意包编号，不是对整个传递闭包的鉴定。

### 3.3 来源

| 来源 | 判断 |
| --- | --- |
| `samugit83/redamon-plugins` | 与本仓库 keyring 注释中的仓库一致。目录签名用的是 keyring 里的那把密钥。发布包摘要与目录一致。git `master` 仍是浮动的目录 URL |
| `mukul975/cve-mcp-server` | `pyproject.toml:12` 的作者字段是 `Mahipal Jangra`，邮箱写成 `mukul975@github`。仓库、标签和 `main` 都在这个 GitHub 用户下。没有看到第二份隐蔽远程。安装 ref 是分支名 `main` |
| PyPI `cve-mcp-server` | 同名、不同树、无主页。不在 RedAmon 的安装命令里。控制台脚本名字也不同，不会悄悄接上预设里的 `cve-mcp` |
| Docker Hub `python:3.12-alpine`、`node:20-bookworm-slim` | 官方库标签。查询日的清单摘要见第 2 节。Dockerfile 没有把摘要写进去 |
| Moby `3111b9d7` | 用来核对 Engine API 有哪些路由。不是 RedAmon 的依赖 pin，也不是实验室引擎的版本 |

---

## 4. 未确认项与原因

| 项 | 原因 |
| --- | --- |
| 实验室 Docker 引擎是否仍注册第 2.1 节那张上游路由表 | 没有查询本机引擎，也没有对 daemon 发包。路由证据是 Moby `3111b9d7` 的源码 |
| 创建正文里大小写不同的 `HostConfig` 键，daemon 的 JSON 解码会不会把它和 broker 后加的键当成同一个字段 | 没有对照运行中的解码器。不作为已确认的绕过 |
| 允许前缀下的符号链接会被不会被 daemon 当成链接目标来挂载 | 代码只做词法 `normpath`。没有创建容器 |
| `.git` 的只读挂载在运行时是否盖住下层的读写挂载 | 两次挂载都写在 API 参数里。没有启动容器 |
| CodeFix 网桥能否到达宿主机上对所有接口发布的端口 | 代码没有 `internal`。没有做连通测试 |
| 已构建的 `redamon-agent` 镜像里 `cve-mcp-server` 及其传递依赖的精确版本 | Dockerfile 使用 `git @main`，没有锁。没有从镜像里读已安装的发行版 |
| `credential.helper` 或 PyGithub 的异常文本会不会在某次失败里带出令牌 | 仓库里没有配置助手；没有读镜像内的 PyGithub 源码，也没有触发一次失败 |
| 插件仓库 `release` 环境是否强制人工批准 | 工作流文本这么写。没有用有权限的身份读取环境规则 |
| 共享 httpx 客户端跟随重定向时会不会离开常量主机 | 客户端参数允许跟随，最多 3 次。没有发送这些请求 |
| OSV 没有编号的传递依赖，以及查询日之后的新编号 | 没有安装，没有展开 `>=` |

---

## 5. 方法与读取过的 URL

本仓库文件都在提交 `046921e6` 上阅读，行号对应该提交。外部 Git 仓库用 `git clone --depth 1` 或 `git ls-remote` / `git fetch tag` 取得，没有执行它们的入口、测试或安装脚本。发布包和 PyPI sdist 只解清单或解出文本来读。签名校验是独立的 Ed25519 验签，不是运行插件仓库的 `tools/sign.py`。

- `https://github.com/samugit83/redamon-plugins` ，`master` = `fc62e5bf6f79e15b11ffcb77dbd4df592bdbadf7`
- `https://github.com/samugit83/redamon-plugins/releases/download/skiller-v1.0.0/skiller-1.0.0.tar.gz`
- `https://github.com/samugit83/redamon-plugins/releases/download/skiller-v1.1.0/skiller-1.1.0.tar.gz`
- `https://github.com/mukul975/cve-mcp-server` ，`main` = `d666bac3743574cecc98bcbf524558c2bf0d8e61` ，标签 `v0.2.0` = `43c33955232306af792806ecee7beafdd1c8600e`
- `https://pypi.org/pypi/mcp/json` （最新版本元数据）
- `https://pypi.org/pypi/cve-mcp-server/json` （同名发行版元数据；`cve_mcp` 这个名字返回 404）
- `https://files.pythonhosted.org/packages/source/c/cve-mcp-server/cve_mcp_server-0.5.0.tar.gz`
- `https://api.osv.dev/v1/querybatch`
- `https://api.osv.dev/v1/vulns/GHSA-vj7q-gjh5-988w`
- `https://api.osv.dev/v1/vulns/PYSEC-2026-3483`
- `https://api.osv.dev/v1/vulns/GHSA-5h93-6whr-6q8j`
- `https://api.osv.dev/v1/vulns/GHSA-84m7-p3x7-pcfv`
- `https://api.osv.dev/v1/vulns/GHSA-rwrf-2pqf-9j8j`
- `https://api.osv.dev/v1/vulns/GHSA-w4fh-qvv9-3v23`
- `https://api.osv.dev/v1/vulns/GHSA-g6cj-pr64-35w5`
- `https://api.osv.dev/v1/vulns/PYSEC-2026-3552`
- `https://api.osv.dev/v1/vulns/GHSA-9hjg-9r4m-mvj7`
- `https://api.osv.dev/v1/vulns/GHSA-gc5v-m9x4-r6x2`
- `https://hub.docker.com/v2/repositories/library/python/tags/3.12-alpine`
- `https://hub.docker.com/v2/repositories/library/node/tags/20-bookworm-slim`
- `https://api.github.com/repos/moby/moby/commits/master` （得到 `3111b9d71267cf3d970f3750a0d66a149b57e759`）
- `https://api.github.com/repos/moby/moby/git/trees/3111b9d71267cf3d970f3750a0d66a149b57e759?recursive=1` （只用来定位路由文件）
- `https://raw.githubusercontent.com/moby/moby/3111b9d71267cf3d970f3750a0d66a149b57e759/daemon/server/router/container/container.go`
- `https://raw.githubusercontent.com/moby/moby/3111b9d71267cf3d970f3750a0d66a149b57e759/daemon/server/router/container/container_routes.go`
- `https://raw.githubusercontent.com/moby/moby/3111b9d71267cf3d970f3750a0d66a149b57e759/daemon/server/router/image/image.go`
- `https://raw.githubusercontent.com/moby/moby/3111b9d71267cf3d970f3750a0d66a149b57e759/daemon/server/router/image/image_routes.go`
- `https://raw.githubusercontent.com/moby/moby/3111b9d71267cf3d970f3750a0d66a149b57e759/daemon/server/router/volume/volume.go`
- `https://raw.githubusercontent.com/moby/moby/3111b9d71267cf3d970f3750a0d66a149b57e759/daemon/server/router/volume/volume_routes.go`
- `https://raw.githubusercontent.com/moby/moby/3111b9d71267cf3d970f3750a0d66a149b57e759/daemon/server/router/network/network.go`
- `https://raw.githubusercontent.com/moby/moby/3111b9d71267cf3d970f3750a0d66a149b57e759/daemon/server/router/plugin/plugin.go`
- `https://raw.githubusercontent.com/moby/moby/3111b9d71267cf3d970f3750a0d66a149b57e759/daemon/server/router/build/build.go`
- `https://raw.githubusercontent.com/moby/moby/3111b9d71267cf3d970f3750a0d66a149b57e759/daemon/server/router/session/session.go`
- `https://raw.githubusercontent.com/moby/moby/3111b9d71267cf3d970f3750a0d66a149b57e759/daemon/server/router/grpc/grpc.go`
- `https://raw.githubusercontent.com/moby/moby/3111b9d71267cf3d970f3750a0d66a149b57e759/daemon/server/router/swarm/cluster.go`

本仓库里对照过、正文已经引用的路径：`services/docker_broker/broker.py`、`Dockerfile`、`test_policy.py`、`test_plumbing.py`、`docker-compose.yml`、`recon_orchestrator/container_manager.py`、`recon_orchestrator/api.py`、`scanners/codefix_sandbox/Dockerfile`、`agentic/cypherfix_codefix/` 下的 `github_repo.py`、`sandbox_client.py`、`tools/bash_tool.py`、`orchestrator.py`、`project_settings.py`、`prompts/system.py`、`agentic/Dockerfile`、`webapp/prisma/schema.prisma`、`webapp/src/app/api/projects/[id]/route.ts`、`webapp/src/app/api/internal/codefix-sandbox/[jobId]/[action]/route.ts`、`webapp/src/lib/plugins/catalog.ts`、`keyring.ts`、`webapp/src/lib/reconSettings/registry.json`、`registry.ts`、`filter.ts`、`webapp/src/lib/mcpReadableFields.ts`、`webapp/src/lib/mcp/presets.ts`、`webapp/src/components/projects/ProjectForm/sections/CypherFixSettingsSection.tsx`。
