# 本地设备授权服务（无浏览器终端）

一个运行在本机、面向无浏览器终端的**设备授权登录**参考实现。术语借鉴
OAuth 2.0 Device Authorization Grant，但这是一套**自定义协议，不宣称完整
OAuth 兼容**（无授权服务器发现、无 token refresh、无标准 HTTP 端点封装，
状态机与错误码按本文件定义）。

仅依赖 Python 3.12 标准库（`sqlite3`、`secrets`、`hashlib`、`random`、
`subprocess`、`unittest` 等），不使用 Docker，不访问任何真实外部服务。

---

## 1. 快速开始

```bash
# 入口一：执行 cases.json 脚本，产出断言结果
python -m solution --input cases/cases.json --output cases/result.json
# 退出码 0 = 全部用例通过；1 = 存在失败

# 入口二：自动化测试（42 个用例，含两个独立 OS 进程轮询、重启、竞争）
python -m unittest discover -s tests -v
```

所有产物都在项目目录内：SQLite 库与审计日志默认落在 `cases/runtime/`，
测试使用系统临时目录并在结束时清理。

---

## 2. 四个入口

| 入口 | 方法 | 作用 |
|---|---|---|
| 申请 | `DeviceAuthService.register(client_id, scope, ttl=300)` | 生成 device_code 与 user_code，创建 pending 申请 |
| 批准 | `DeviceAuthService.approve(caller_id, user_code, account_id, decision="approve"/"deny")` | 用户在另一终端用短码批准或拒绝 |
| 轮询 | `DeviceAuthService.poll(device_code, client_id, scope, request_id=None)` | 终端轮询状态；批准后携带 request_id 兑换令牌 |
| 取消 | `DeviceAuthService.cancel(device_code)` | 申请方主动取消 |

### 2.1 两类代码的关系

- **device_code**：256 位（32 字节）随机秘密，base64url 无填充文本，只在
  设备终端持有，是轮询/取消/兑换的唯一凭据。
- **user_code**：8 位人类可输入短码，展示为 `XXXX-XXXX`；字母表为
  `23456789ABCDEFGHJKMNPQRSTUVWXYZ`，剔除 `0/O`、`1/I/L` 等易混字符；
  输入忽略大小写、连字符与空格。
- 两者由**独立随机字节**生成，分别以各自的 SHA-256 哈希索引同一条申请，
  **互相不可推导**；数据库只存哈希，不存原始代码。
- user_code **只能用于查找待批准申请，不能直接换取令牌**；批准后短码即失效。

### 2.2 状态机

```
                 approve(approve)                poll + request_id
 pending ───────────────────────► approved ───────────────────────► consumed
   │  │  │  │
   │  │  │  └─ approve(deny) ──► denied        （终态）
   │  │  └──── cancel ─────────► cancelled     （终态，取消可幂等重放）
   │  └─────── now>=expires_at ► expired       （终态，惰性落库）
   └─ 轮询只在 pending 上做节流；终态结果彼此分离、永不互转
```

批准时把申请上的 `client_id` 与 `scope` 一并冻结；轮询兑换时必须原样匹配，
**不能在轮询时扩大 scope 或替换 client_id**（见错误码 `invalid_client` /
`invalid_scope`）。scope 在申请时做排序去重归一化（`"write read"` 与
`"read write"` 视为同一范围）。

---

## 3. 轮询节流（slow_down）

- 每份申请起始最小轮询间隔 **5 秒**（`interval_seconds=5`）。
- 当 `now - last_poll_at < interval_seconds` 时返回 `slow_down`，并把该申请的
  间隔**永久增加 5 秒**（5 → 10 → 15 → …），在申请到期前只增不减。
- 间隔与 `last_poll_at` 都在 SQLite 事务内更新并**先提交再返回错误**，
  进程重启后从库中读取，**重启不重置间隔也不重置寿命**。
- 节流只作用于 pending 申请；批准后的兑换不再受间隔约束。

## 4. 到期规则

- 申请寿命在创建时固定为 `expires_at = created_at + ttl`。
- 采用显式整数秒时钟，**`now >= expires_at` 即过期**（边界等于而非大于）。
- 到期是惰性落库：轮询、批准、取消任一入口碰到到期 pending 申请时把它置为
  `expired` 终态。已批准申请的兑换资格不被到期抹掉（批准即完成授权决定）。

## 5. 短码入口限流（暴力猜测防护）

- 以 **caller_id（调用方 ID）** 为键的滑动窗口：**60 秒内最多 5 次失败**。
- 失败事件持久化在 `rate_events` 表，重启不消失；窗口按
  `[now-59, now]` 闭区间统计，事件随窗口滑出自动清理。
- 达到上限后，即使短码正确也直接返回 `rate_limited`（带 `retry_after`），
  不接触申请状态。不同 caller_id 的窗口互相独立。
- **账号不存在与短码错误返回完全相同的外部错误**
  （`invalid_user_code` + 相同描述），且两者都计入失败次数，不泄露账号是否
  存在。仅当短码能定位到已老化 `expired` 申请时才明确返回 `grant_expired`
  （此时短码本身有效，不计失败）。

## 6. 兑换幂等（request_id）

- 批准后的兑换**必须**携带客户端预先声明的非空 `request_id`，否则返回
  `request_id_required`。
- 同一 `request_id` + 相同参数（device_code/client_id/scope 规范化后参与
  哈希）的重试返回**同一结果、同一令牌、同一签发时间**，`result="replay"`，
  用于“成功后丢响应”的安全重试。
- `request_id` 全局唯一并绑定到具体申请：
  - 同 ID 用于其他申请 → `idempotency_conflict`（该检查优先于状态判断）；
  - 同 ID 但参数变化 → `idempotency_conflict`；
  - 申请已被**其他** request_id 兑换 → `grant_consumed`，不能再次消费。
- 兑换在一个 `BEGIN IMMEDIATE` 事务内完成：写 `exchanges` 摘要
  （request_id、grant_id、参数哈希、令牌、签发时间）并把申请置 `consumed`，
  并发兑换由 SQLite 写锁串行化，保证只有一个 request_id 获胜。

## 7. 竞争与终态

批准与取消、两次批准、两个 request_id 并发兑换都通过 SQLite 的
`BEGIN IMMEDIATE` 写锁串行化：**只允许一个终态落库**，败方随后读到胜方
写入的状态并拿到 `conflict_state` / `invalid_user_code` /
`grant_consumed`。取消本身幂等（重复取消返回 `cancelled`）。

---

## 8. 输入 / 输出 Schema

### 8.1 cases.json（`python -m solution` 的输入）

```json
{
  "seed": 20261117,
  "start_time": 1000000,
  "cases": [
    {
      "name": "用例名",
      "db": "runtime/01.db",
      "log": "runtime/01.log",
      "accounts": ["alice", "bob"],
      "steps": [ {"op": "register", "args": {...}, "expect": {...}, "save": "reg"} ]
    }
  ]
}
```

- 相对路径以 cases.json 所在目录为基准；每个用例独立数据库，运行前清空重建。
- `seed` 固定随机种子；代码流与令牌流使用两个派生 RNG，**跨运行逐字节重放**。
- `start_time` 是虚拟整数时钟起点；步骤 `{"op":"advance","seconds":N}` 推进。
- 步骤操作：`register` / `approve` / `poll` / `cancel`（进程内调用）、
  `advance`（推进时钟）、`restart`（关闭并重新打开库，模拟进程重启）、
  `worker`（在**独立 OS 进程**里执行一次调用）、`thread_race`（多线程同库
  竞争）、`hash_file`（引用项目内文件算 SHA-256）、
  `assert_log_no_secrets`（断言日志不含秘密原文）。
- `save` 把返回值存入变量，后续参数可用 `"$reg.device_code"` 引用；
  `expect` 是对实际值的子集断言，支持匹配器 `"__nonempty__"` 与
  `"__one_of:a:b:c__"`。

### 8.2 result.json（输出）

```json
{
  "passed": true,
  "total_cases": 8,
  "passed_cases": 8,
  "seed": 20261117,
  "start_time": 1000000,
  "input": "…绝对路径…",
  "cases": [
    {
      "name": "01_happy_path_slow_terminal",
      "passed": true,
      "db": "runtime/01.db",
      "log": "runtime/01.log",
      "failures": [],
      "steps": [
        {"index": 0, "op": "register", "passed": true,
         "actual": {"result": "registered", "status": "pending",
                    "device_code": "…", "user_code": "ABCD-EFGH",
                    "interval": 5, "expires_at": 1000300, "ttl": 300}}
      ]
    }
  ]
}
```

成功响应公共字段：`result`、`status`；错误响应统一为
`{"error": <错误码>, "error_description": <说明>, ...附加字段}`。

### 8.3 错误码表（自定义协议）

| 错误码 | 触发场景 | 附加字段 |
|---|---|---|
| `invalid_request` | 入参缺失/类型错误、ttl 非正整数、decision 非法 | — |
| `invalid_client` | 轮询 client_id 与申请绑定不一致 | — |
| `invalid_scope` | 轮询 scope 与批准绑定范围不一致/被扩大 | — |
| `invalid_grant` | device_code 查无对应申请 | — |
| `invalid_user_code` | 短码错误、无待处理申请、账号不存在（三者同形） | — |
| `rate_limited` | 短码入口 60s 内失败达 5 次 | `retry_after` |
| `authorization_pending` | 轮询时申请仍在等待用户处理 | `interval` |
| `slow_down` | 轮询过快，间隔已永久 +5s | `interval`, `retry_after` |
| `access_denied` | 用户拒绝申请 | — |
| `grant_expired` | `now >= expires_at`，申请到期 | — |
| `grant_cancelled` | 申请已被取消 | — |
| `grant_consumed` | 申请已被其他 request_id 兑换 | — |
| `idempotency_conflict` | request_id 绑定了其他申请或参数发生变化 | — |
| `request_id_required` | 批准后兑换未带 request_id | — |
| `conflict_state` | 对已处终态的申请执行取消竞争 | `current_status` |

---

## 9. 持久化与安全

### 9.1 SQLite 表结构

- `meta(key, value)`：保存虚拟时钟 `now` 等元数据（供独立进程 DBClock 读取）。
- `accounts(account_id, created_at)`：模拟本地账号目录。
- `grants(...)`：申请主表，含 `status`、`interval_seconds`、`last_poll_at`、
  `expires_at`、两个代码哈希、决定时间与账号。
- `exchanges(request_id PK, grant_id, params_hash, token, issued_at)`：兑换
  结果摘要，支撑幂等重放。
- `rate_events(caller_id, ts)`：短码失败事件，滑动窗口计数。

库启用 WAL 与 `busy_timeout`，支持两个独立进程同时打开；所有状态变更走
`BEGIN IMMEDIATE` 写事务。需要“先持久化再抛错”的路径（限流计数、间隔升级、
惰性到期、last_poll_at）在事务内显式 `COMMIT` 后再抛异常。

### 9.2 日志脱敏

`SafeLogger` 只接受白名单字段（ts/action/grant_id/client_id/scope/status/
error/caller_id/account_id/decision/interval/expires_at/retry_after 等），
误传 `device_code`、`user_code`、`token`、`request_id` 会直接抛
`ValueError`。测试 `test_audit.py` 与用例 01/08 的
`assert_log_no_secrets` 会扫描日志，断言任何秘密原文都不落盘。

### 9.3 时钟

- `ManualClock`：测试/脚本用的整数秒时钟，只能前进不能回拨。
- `SystemClock`：真实部署用 `int(time.time())`。
- `DBClock`：独立子进程从 SQLite `meta.now` 读时间，使多进程共享同一个
  确定性时钟；父进程用 `advance` 写库，子进程 worker 通过
  `--action set-time --now N` 或父进程写值对齐。

---

## 10. 验收场景对照表

| 要求场景 | 覆盖位置 |
|---|---|
| 两个独立轮询进程 | `tests/test_multiprocess.py`、cases 08（worker 子进程） |
| 批准与取消交错 | `tests/test_race.py`、cases 06（thread_race + 串行交错） |
| 到期边界（off-by-one） | `tests/test_polling.py::test_expiry_boundary_off_by_one`、cases 04 |
| 成功后丢响应（幂等重放） | `tests/test_idempotency.py::test_same_request_id_replays_same_token`、cases 01/03/08 |
| 间隔升级后重启 | `tests/test_polling.py::test_interval_upgrade_survives_restart`、cases 05 |
| 短码暴力猜测限流 | `tests/test_approve.py`、cases 07（含窗口滑出、重启持久化、按调用方隔离） |
| 正常慢速终端完成登录 | cases 01 全流程（严格按 interval 轮询 → 批准 → 兑换） |

## 11. 目录结构

```
solution/            库代码（storage/service/codes/clock/audit/worker/runner）
tests/               42 个 unittest 用例（7 个测试模块 + 公共夹具）
cases/cases.json     8 个脚本化验收场景
cases/result.json    最近一次运行的断言结果
cases/sample_notes.txt / sample_blob.bin   项目内文本/二进制样例（可被脚本引用）
cases/runtime/       脚本运行产生的 *.db 与 *.log（已被 .gitignore 忽略）
```

## 12. 设计边界（未写明的非安全性细节）

- 令牌为不透明随机串，本实现不做刷新、撤销或有效期校验（issued_at 仅记录）。
- 账号目录是库内模拟表，不接真实身份系统；caller_id 由调用方自报，限流只
  保证“按 ID 计数持久化”，不解决调用方伪造 ID 的问题（超出本题范围）。
- worker 子进程默认用 OS CSPRNG；传入 `--seed` 时切换为确定性 RNG，仅供
  测试与可重放脚本使用。
- 并发模型只承诺单主机、单库文件下的正确性；不涉及网络服务与多机部署。
