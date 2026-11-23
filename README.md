# TG Guardian — Telegram 账号安全守护机器人

作者：TG https://t.me/ziixiix

一个帮你看住 Telegram 账号的反登录守护机器人。有人在别处登录你的账号（轮号）、或者有人拿到你的验证码想登录时，它会立刻在 Telegram 上提醒你，你可以在机器人里一键同意、或者一键踢掉对方并冻结登录。

## 它能做什么

- **新设备登录提醒**：你的账号在新设备上登录时，机器人马上发提醒，显示设备、应用、地点、IP 和时间，你点“是我本人”放行，点“踢掉”就把那个会话注销掉。10 分钟没反应，它自动帮你踢掉。
- **验证码提醒（防半登录）**：有人请求了你的登录验证码（777000 的消息），机器人马上提醒你。验证码本身就是一次“半登录”，点“同意”放行，点“拒绝”就冻结。
- **冻结验证码**：拒绝后，监控端让这个验证码失效，对方拿着验证码也登不进来。
- **Flood 保护**：拒绝后，监控端触发 Telegram 的登录次数限制（Flood），在一段时间内谁也登不进这个账号——包括你自己。已经登录的设备不受影响。
- **持续 Flood 保护**：定时触发一次 Flood 保护，可以只触发一次、每隔一段时间循环触发、或者触发指定次数后停止。
- **多账号**：一个机器人可以同时看住你名下的多个 Telegram 账号（共用一个 API ID / Hash）。
- **改账号显示名**：机器人里显示的账号名字可以自定义（`/rename_account`），名字不能重复。
- **添加账号（短信 / 扫码）**：`/add_account` 可以选短信登录或扫码登录；扫码需要两个设备（一台显示二维码、一台扫码），二维码 30 秒有效、最多自动刷新 10 次，点“停止扫码登录”或发 `/stop_qr` 可以停。
- **暂停保护**：`/pause_guard [账号] [分钟]` 可以暂停全部或单个账号的自动注销 / 自动冻结（不填分钟 = 一直暂停，填分钟 = 到点自动恢复）；暂停期间告警照常发、按钮手动点照常生效，`/resume_guard [账号]` 恢复。
- **换号码迁移**：在 Telegram 里换了手机号后，用 `/change_phone <旧手机号> <新手机号>` 把 TG Guardian 里这个账号的记录迁到新号码。
- **自检与状态**：`/status` 看账号和会话，`/devices` 看设备列表，`/security_check` 做安全检查，`/flood_status` 看 Flood 状态。

## 架构

```
你的 Telegram 账号 ──(MTProto)──► 监控端（monitor/main.py，跑在你自己的服务器上）
                                          │
                                          │ 每 120 秒轮询一次
                                          ▼
                             Cloudflare Worker（worker.js）＋ KV
                                          │
                                          │ Telegram Bot API
                                          ▼
                              守护机器人（@你的机器人）
```

- **Worker**：Cloudflare 上的管理机器人，负责收发消息、按钮、命令，状态存在 Cloudflare KV 里。
- **监控端**：一台服务器上跑的 Python 程序（Telethon / MTProto），用你自己的 Telegram 账号登录，负责检测新设备和验证码、执行注销和冻结。
- Worker 不能主动推给监控端，所以监控端每 120 秒问一次 Worker“有没有新指令”，你的按钮操作最慢 2 分钟生效（决定类操作会走唤醒消息，一般 2–5 秒内就执行）。

## 原理：反登录是怎么实现的

Telegram 登录分两步：先请求验证码（发到你的 Telegram 应用内，就是 777000 发来的那条消息），再输验证码和二级密码。只要有人请求了验证码，哪怕他还没输对，就已经是一次“半登录”。

- **监控端**：它用你自己的 Telegram 账号保持一个已授权会话（Telethon / MTProto），所以能看到这个账号的全部授权会话，也能实时收到 777000 的验证码消息。
- **新设备**：监控端会检查授权会话，发现多出来的会话就提醒你；你点“踢掉”，它就用自己的已授权会话把那个会话注销掉。收到验证码后的 5 分钟内，检查会加快到每 3 秒一次，5 分钟后恢复每 5 分钟。
- **验证码**：777000 的消息一到就实时提醒你；你点“拒绝”，监控端让这个验证码失效，对方拿着它也登不进来。
- **Flood 保护**：监控端触发 Telegram 的Flood保护。触发后一段时间内，这个手机号收不到验证码、谁也登不进新设备——包括你自己；已经登录的设备不受影响。这就是“反登录”：不是去改密码，而是让 Telegram 暂时拒绝所有新登录。

## 快速开始

### 1. 准备工作

你需要：

- 一个 Telegram 账号（要被守护的账号）。
- 一台能长期运行 Python 的服务器（VPS、家里的电脑、树莓派都行，Python 3.10 以上）。
- 一个 Cloudflare 账号（免费版就够）。

### 2. 创建 Telegram 机器人

1. 在 Telegram 里打开 [@BotFather](https://t.me/BotFather)，发 `/newbot`，按提示起个名字和用户名。
2. 记下它给你的 **BOT_TOKEN**（一长串 `数字:字母`）。
3. 再去 [@userinfobot](https://t.me/userinfobot) 发任意消息，它会告诉你自己的 Telegram 用户 ID，记下这个 **OWNER_ID**（一串数字）。

### 3. 申请 Telegram API ID / Hash

1. 打开 https://my.telegram.org ，用你的 Telegram 账号登录。
2. 点 **API development tools**，填一个应用名（随便填，比如 `tg-guardian`），平台选 Desktop，其他留空，点创建。
3. 记下 **API_ID**（数字）和 **API_HASH**（字符串）。这两个只标识“你的应用”，不标识账号，多个账号共用同一份。

### 4. 部署 Cloudflare Worker

1. 登录 Cloudflare Dashboard → **Workers & Pages** → **Create** → 选 **Worker**，起个名字（比如 `tg-guardian`），点 **Deploy**。
2. 点 **Edit code**，把本仓库根目录的 `worker.js` 全部内容粘贴进去，点 **Deploy**。
3. 创建 KV 命名空间：左侧 **Workers & Pages** → **KV** → **Create a namespace**，名字填 `TG_GUARD_DATA`。
4. 绑定 KV：回到你的 Worker → **Settings** → **Variables** → **KV Namespace Bindings** → **Add binding**，变量名填 `TG_GUARD_DATA`，选刚才创建的命名空间，点 **Deploy**。
5. 设置环境变量（同一页 **Variables** → **Environment Variables**，点 **Add variable**）：
   - `BOT_TOKEN`：第 2 步得到的机器人 token。
   - `OWNER_ID`：第 2 步得到的你的用户 ID。
   - `WEBHOOK_SECRET`：自己随便想一个随机字符串（比如用密码生成器生成 32 位），后面设置 webhook 时要用同一个。
   - 点 **Deploy** 保存。
6. 设置 webhook（让 Telegram 把消息推给 Worker）。把下面这条命令里的三处换成你自己的值，在终端里执行一次：
   ```bash
   curl "https://api.telegram.org/bot<BOT_TOKEN>/setWebhook?url=https://<你的Worker地址>/webhook&secret_token=<WEBHOOK_SECRET>"
   ```
   你的 Worker 地址形如 `https://tg-guardian.<你的子域名>.workers.dev`（子域名在 Cloudflare Dashboard 的 Workers 页面能看到）。
   返回 `{"ok":true,...}` 就是成功。
7. 验证：打开 `https://<你的Worker地址>/`，应该看到 `{"ok":true,"service":"TG Guardian","version":"1.4.29",...}`，并且 `checks` 里的 `BOT_TOKEN`、`OWNER_ID`、`WEBHOOK_SECRET`、`TG_GUARD_DATA`、`KV_PUT`、`KV_GET` 全是 `true`。然后去 Telegram 给机器人发 `/start`，它应该回你菜单。

### 5. 部署监控端

1. 把本仓库克隆到你的服务器：
   ```bash
   git clone https://github.com/<你的用户名>/tg-guardian.git
   cd tg-guardian/monitor
   pip install -r requirements.txt
   ```
2. 设置环境变量（见下面的变量表，必填的 6 个）：
   ```bash
   export API_ID="你的 API ID"
   export API_HASH="你的 API Hash"
   export BOT_TOKEN="你的机器人 token"
   export OWNER_ID="你的用户 ID"
   export PHONE="+8613800138000"        # 主账号手机号，带国家码
   export WORKER_URL="https://tg-guardian.<你的子域名>.workers.dev"
   ```
   建议把这些写进一个 `.env` 文件或者系统的服务配置里，不要写进代码、不要提交到 Git。
3. 启动：
   ```bash
   python3 -u main.py
   ```
   第一次启动没有会话文件，它会在终端里问你要手机号和验证码（Telegram 发来的登录验证码），照着输就行。登录成功后会生成会话文件（`tg_guardian.session`），以后启动就不用再登录了。
   - 如果你不想交互登录，可以先用 Telethon 生成一个 `SESSION_STRING`（会话字符串），设到环境变量里，监控端启动时直接用它登录。
4. 验证：机器人应该给你发一条“监控端已启动”的提醒，`/status` 能看到主账号的会话数。日志里出现 `TG Guardian MTProto monitor v0.5.27 started as ...` 就是正常启动。

### 6. 添加账号

主账号是启动时用 `PHONE` 指定的那个。想再加账号，在机器人里发：

```
/add_account +8613800138000 小号
```

机器人会让你选登录方式：

- **短信登录**：然后按提示操作：

```
/code 12345        # 填 Telegram 发给那个账号的验证码
/2fa 你的二级密码    # 那个账号如果开了二级密码才需要
```

- **扫码登录**：需要两个设备（一台显示二维码、一台扫码）；二维码 30 秒有效、最多自动刷新 10 次；不想扫了点“停止扫码登录”，或发 `/stop_qr [账号]` 停止。开了二级密码的账号扫码后同样用 `/2fa` 提交。

加完后 `/accounts` 能看到所有账号。想删账号：`/remove_account +8613800138000`，再发一次带 `确认`。

想改机器人里显示的名字：

```
/rename_account 0968 小号
```

名字是自定义的显示名，不会改你的 Telegram 账号本身的名字，名字不能和别的账号重复。

### 7. 常用命令

| 命令 | 说明 |
| --- | --- |
| `/status` | 看账号、会话和 Flood 状态 |
| `/devices` | 看设备列表 |
| `/logs` | 看最近的提醒记录 |
| `/login_guard` | 看登录保护和持续 Flood 保护的状态 |
| `/flood_status` | 看 Flood 状态和预计恢复时间 |
| `/security_check` | 安全自检 |
| `/accounts` | 账号列表 |
| `/add_account <手机号> [名字]` | 添加一个账号（短信登录 / 扫码登录） |
| `/stop_qr [账号]` | 停止扫码登录 |
| `/change_phone <旧手机号> <新手机号>` | 在 Telegram 换了号码后，把记录迁到新号码 |
| `/security` | 安全状态 |
| `/code <验证码>` | 完成添加账号时的验证码 |
| `/2fa <二级密码>` | 完成添加账号时的二级密码 |
| `/cancel_add <手机号>` | 取消正在添加的账号 |
| `/remove_account <手机号>` | 删除一个账号（要确认两次） |
| `/rename_account [手机号或名字] <新名字>` | 改机器人里显示的账号名字 |
| `/set_guard <秒>` | 验证码提醒后多久无操作自动冻结（60–3600 秒） |
| `/set_revoke <秒>` | 新设备提醒后多久无操作自动注销（60–3600 秒） |
| `/alert_on [账号]` / `/alert_off [账号]` | 开 / 关提醒弹窗（只关弹窗，保护照常运行） |
| `/pause_guard [账号] [分钟]` | 暂停保护（不填 = 所有账号一直暂停；填分钟 = 到点自动恢复） |
| `/resume_guard [账号]` | 恢复保护 |
| `/clear_alerts [账号]` | 清空提醒记录 |
| `/clear_flood [账号]` | 手动清除一条 Flood 记录 |
| `/check_flood [账号]` | 手动探测 Flood 是不是已经解除了（可能会收到一次验证码，忽略即可） |
| `/sustain_flood_on [分钟] [账号]` | 开启持续 Flood 保护（默认 30 分钟，最长 1440 分钟） |
| `/sustain_flood_off [账号]` | 关闭持续 Flood 保护 |
| `/test` | KV 读写测试 |
| `/ping` | 机器人是否在线 |
| `/start` | 启动机器人 |
| `/help` | 帮助 |

持续 Flood 保护的三种模式（设好时间后，在机器人弹出的按钮里选）：

- **只触发一次**（默认）：到时间触发一次 Flood 保护，然后自动关闭。
- **🔁 循环**：每隔你设定的时间触发一次，一直循环，直到你用 `/sustain_flood_off` 关掉。
- **🔢 选择次数**：每隔你设定的时间触发一次，触发 1 / 3 / 5 / 10 次后自动停止。

## 环境变量表

### Worker（Cloudflare 侧）

| 变量名 | 类型 | 说明 | 重要程度 |
| --- | --- | --- | --- |
| `BOT_TOKEN` | 密钥 · 字符串 | Telegram 机器人的 token（@BotFather 创建机器人后得到） | 必填 |
| `OWNER_ID` | 文本 · 整数 | 你的 Telegram 用户 ID（只有这个 ID 能用机器人，其他人发消息会被忽略） | 必填 |
| `WEBHOOK_SECRET` | 密钥 · 字符串 | Webhook 密钥，自己随便设一个随机字符串；设置 webhook 时 `secret_token` 要填同一个 | 必填 |
| `TG_GUARD_DATA` | 文本 · KV 命名空间绑定 | Cloudflare KV 命名空间，用来存账号、待处理事项、提醒记录 | 必填 |
| `API_ID` | 文本 · 整数 | CF 端已设置，但 Worker 代码不用它；真正用它的是监控端（见下表） | 不需要（CF 端） |
| `API_HASH` | 密钥 · 字符串 | 同上 | 不需要（CF 端） |
| `ENCRYPTION_KEY` | 密钥 · 字符串 | 早期设计留下的变量，Worker 和监控端代码都不读它，用不上；留着无害，也可以删掉 | 不需要 |

### 监控端（服务器侧）

| 变量名 | 类型 | 说明 | 重要程度 |
| --- | --- | --- | --- |
| `API_ID` | 文本 · 整数 | Telegram API ID（my.telegram.org 申请） | 必填 |
| `API_HASH` | 密钥 · 字符串 | Telegram API Hash（同上） | 必填 |
| `BOT_TOKEN` | 密钥 · 字符串 | 和 Worker 填同一个机器人 token | 必填 |
| `OWNER_ID` | 文本 · 整数 | 和 Worker 填同一个你的用户 ID | 必填 |
| `PHONE` | 文本 · 字符串 | 主账号手机号，带国家码，如 `+8613800138000` | 必填 |
| `WORKER_URL` | 文本 · 字符串 | 你的 Worker 地址，如 `https://tg-guardian.<你的子域名>.workers.dev` | 必填 |
| `SESSION_STRING` | 密钥 · 字符串 | Telethon 会话字符串；填了它启动时就不用交互登录 | 可选 |
| `SESSION_STRING_<手机号>` | 密钥 · 字符串 | 某个账号的会话字符串（手机号只写数字）；无状态容器（如 Northflank）重启后靠它恢复该账号的会话，监控端心跳也会把当前会话备份到 Worker KV | 可选 |
| `CHECK_INTERVAL` | 文本 · 整数（秒） | 每隔多久检查一次授权会话，默认 300 | 可选 |
| `POLL_INTERVAL` | 文本 · 整数（秒） | 每隔多久问一次 Worker 有没有新指令，默认 120 | 可选 |
| `AUTO_REVOKE_AFTER` | 文本 · 整数（秒） | 新设备提醒后多久无操作自动注销，默认 600 | 可选 |
| `AUTO_CODE_AFTER` | 文本 · 整数（秒） | 验证码提醒后多久无操作自动冻结，默认 300 | 可选 |
| `HEARTBEAT_INTERVAL` | 文本 · 整数（秒） | 每隔多久上传一次设备快照（心跳），默认 3600 | 可选 |
| `STATE_FILE` | 文本 · 字符串 | 状态文件路径，默认 `devices.json` | 可选 |
| `ENCRYPTION_KEY` | 密钥 · 字符串 | 早期设计留下的变量，监控端和 Worker 代码都不读它，用不上；留着无害，也可以删掉 | 不需要 |

## 脱敏说明

这个仓库是开源版，里面没有任何真实密钥和个人信息。脱敏的地方一共就这几处：

| 脱敏项 | 开源版的样子 | 你需要做的事 |
| --- | --- | --- |
| `monitor/main.py` 里的 `WORKER_URL` 默认值 | 占位符 `https://your-worker.your-subdomain.workers.dev` | 改成你自己部署的 Worker 地址，或者设环境变量 `WORKER_URL` |
| 所有密钥和账号信息（`BOT_TOKEN`、`OWNER_ID`、`WEBHOOK_SECRET`、`API_ID`、`API_HASH`、`PHONE`） | 本来就不在代码里，全部走环境变量 | 按上面的变量表填你自己的值，不要写进代码、不要提交到 Git |
| 会话文件（`tg_guardian.session`、`tg_guardian_<手机号>.session`） | 不在仓库里。会话文件是监控端第一次登录 Telegram 后自动生成的登录凭证，相当于浏览器的“记住登录状态”，有了它不用验证码就能以你的身份登录 | 第一次启动监控端时自动生成，`.gitignore` 已排除，绝不要提交或发给别人 |
| 作者名 | TG https://t.me/ziixiix 

除此之外代码完整，没有删功能、没有留后门，可接受审查。

## 安全提醒

- **会话文件就是你的 Telegram 登录态**。`tg_guardian.session` 和 `tg_guardian_<手机号>.session` 一定要保管好，绝不要发给别人、不要提交到 Git、不要上传到公开的地方。丢了它就等于丢了账号。
- **不要在 Telegram 里点“注销所有其它设备上的会话”**。监控端自己的会话也在里面，注销了它监控就断了，得重新授权。只单独注销你不认识的会话。
- **监控端会话不满 24 小时不能注销别的会话**。这是 Telegram 的限制（FRESH_RESET_AUTHORISATION_FORBIDDEN），不是 bug。刚部署好的一天内，新的半登录只能靠你手动在 Telegram 里结束。
- **Flood 保护会把你自己也锁在外面**。它触发后的一段时间内（通常约 1 小时），这个手机号收不到登录验证码、登不进新设备，已经登录的设备不受影响。用之前想清楚，持续 Flood 保护不要设得太频繁。
- **验证码和二级密码只在机器人和 KV 里短暂经过**。添加账号时，验证码/二级密码从机器人发到 Worker 的 KV，监控端下一次轮询（最多 2 分钟）取走后 Worker 立刻删掉，监控端只在内存里用一次，绝不写日志。
- **机器人只认 OWNER_ID**。不是你的用户 ID 发来的消息和按钮，机器人一律不理。

## 开源协议

MIT License，详见 [LICENSE](LICENSE)。

作者：TG https://t.me/ziixiix
