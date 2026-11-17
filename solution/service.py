"""设备授权服务：申请 / 批准 / 轮询兑换 / 取消 四个入口。

协议为本地自定义协议（术语借鉴 OAuth 2.0 Device Flow，但不宣称完整兼容）。
所有“当前时间”来自可注入的整数秒时钟，状态全部在 SQLite 事务内变更。
"""

import json
import sqlite3

from . import errors
from .audit import SafeLogger
from .codes import CodeGenerator, format_user_code, normalize_user_code, sha256_hex
from .storage import Storage

# 申请状态机
PENDING = "pending"
APPROVED = "approved"
DENIED = "denied"
EXPIRED = "expired"
CANCELLED = "cancelled"
CONSUMED = "consumed"

BASE_INTERVAL = 5        # 起始最小轮询间隔（秒）
SLOW_DOWN_STEP = 5       # 每次过快轮询的永久增量（秒）
RATE_WINDOW = 60         # 短码入口限流窗口（秒）
RATE_MAX_FAILURES = 5    # 窗口内最多失败次数
DEFAULT_TTL = 300        # 默认申请寿命（秒）


def _require_str(value, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise errors.DeviceAuthError(
            errors.INVALID_REQUEST, f"参数 {name} 必须是非空字符串"
        )
    return value.strip()


def _normalize_scope(scope: str) -> str:
    _require_str(scope, "scope")
    tokens = sorted(set(scope.split()))
    if not tokens:
        raise errors.DeviceAuthError(
            errors.INVALID_REQUEST, "scope 至少包含一个权限标记"
        )
    return " ".join(tokens)


class DeviceAuthService:
    def __init__(self, storage: Storage, clock, code_generator: CodeGenerator | None = None,
                 logger: SafeLogger | None = None):
        self.storage = storage
        self.clock = clock
        self.codes = code_generator or CodeGenerator()
        self.log = logger or SafeLogger("device-auth.log")

    # ---- 入口 1：申请 ----
    def register(self, client_id: str, scope: str, ttl: int = DEFAULT_TTL) -> dict:
        client_id = _require_str(client_id, "client_id")
        scope = _normalize_scope(scope)
        if not isinstance(ttl, int) or ttl <= 0:
            raise errors.DeviceAuthError(
                errors.INVALID_REQUEST, "ttl 必须是正整数秒"
            )
        now = self.clock.now()
        expires_at = now + ttl

        # 唯一索引兜底哈希碰撞；两类代码独立生成，互不可推
        for _ in range(5):
            device_code = self.codes.device_code()
            user_code = self.codes.user_code()
            try:
                with self.storage.tx():
                    grant_id = self.storage.insert_grant({
                        "client_id": client_id,
                        "scope": scope,
                        "device_code_hash": sha256_hex(device_code),
                        "user_code_hash": sha256_hex(user_code),
                        "status": PENDING,
                        "interval_seconds": BASE_INTERVAL,
                        "last_poll_at": None,
                        "expires_at": expires_at,
                        "created_at": now,
                        "decided_at": None,
                        "account_id": None,
                    })
                break
            except sqlite3.IntegrityError:
                continue
        else:
            raise errors.DeviceAuthError(errors.INVALID_REQUEST, "代码生成冲突，请重试")

        self.log.event(
            "register", ts=now, grant_id=grant_id, client_id=client_id,
            scope=scope, ttl=ttl, expires_at=expires_at, interval=BASE_INTERVAL,
            status=PENDING,
        )
        return {
            "result": "registered",
            "grant_id": grant_id,
            "device_code": device_code,
            "user_code": format_user_code(user_code),
            "interval": BASE_INTERVAL,
            "expires_at": expires_at,
            "ttl": ttl,
            "status": PENDING,
        }

    # ---- 入口 2：用户短码批准/拒绝 ----
    def approve(self, caller_id: str, user_code: str, account_id: str,
                decision: str = "approve") -> dict:
        caller_id = _require_str(caller_id, "caller_id")
        account_id = _require_str(account_id, "account_id")
        _require_str(user_code, "user_code")
        if decision not in ("approve", "deny"):
            raise errors.DeviceAuthError(
                errors.INVALID_REQUEST, "decision 只能是 approve 或 deny"
            )
        now = self.clock.now()
        window_start = now - RATE_WINDOW + 1  # 闭区间 [window_start, now]

        with self.storage.tx():
            failures = self.storage.count_rate_events(
                caller_id, window_start, now
            )
            if failures >= RATE_MAX_FAILURES:
                oldest = self.storage.oldest_rate_event(caller_id, window_start, now)
                retry_after = max(1, (oldest + RATE_WINDOW) - now)
                self.log.event(
                    "approve_rate_limited", ts=now, caller_id=caller_id,
                    error=errors.RATE_LIMITED, retry_after=retry_after,
                    window_failures=failures,
                )
                raise errors.DeviceAuthError(
                    errors.RATE_LIMITED,
                    "短码尝试失败过多，请稍后再试",
                    {"retry_after": retry_after},
                )

            compact = normalize_user_code(user_code)
            grant = self.storage.get_grant_by_user_hash(sha256_hex(compact)) \
                if compact else None

            # 短码能定位到申请但已老化到期：明确报到期（短码本身有效，不计失败）
            if grant is not None and grant["status"] == EXPIRED:
                self.log.event(
                    "approve_expired", ts=now, grant_id=grant["id"],
                    caller_id=caller_id, status=EXPIRED, error=errors.GRANT_EXPIRED,
                )
                raise errors.DeviceAuthError(
                    errors.GRANT_EXPIRED, "申请已到期，无法批准"
                )

            # 短码查无申请或申请不在待处理状态：记一次失败，返回统一外部错误
            if grant is None or grant["status"] != PENDING:
                self.storage.add_rate_event(caller_id, now)
                self.storage.prune_rate_events(window_start)
                self.storage.commit()  # 失败计数必须持久化，先提交再抛错
                self.log.event(
                    "approve_failed", ts=now, caller_id=caller_id,
                    reason="user_code_not_pending", window_failures=failures + 1,
                    error=errors.INVALID_USER_CODE,
                )
                raise errors.DeviceAuthError(
                    errors.INVALID_USER_CODE,
                    "短码无效或没有待批准的申请",
                )

            # 到期边界：now >= expires_at 即过期，惰性落库
            if now >= grant["expires_at"]:
                self.storage.update_grant(grant["id"], status=EXPIRED,
                                          decided_at=now)
                self.storage.commit()
                self.log.event(
                    "approve_expired", ts=now, grant_id=grant["id"],
                    caller_id=caller_id, status=EXPIRED, error=errors.GRANT_EXPIRED,
                )
                raise errors.DeviceAuthError(
                    errors.GRANT_EXPIRED, "申请已到期，无法批准"
                )

            # 账号不存在与短码错误返回相同外部错误、同样计入限流
            if not self.storage.has_account(account_id):
                self.storage.add_rate_event(caller_id, now)
                self.storage.prune_rate_events(window_start)
                self.storage.commit()
                self.log.event(
                    "approve_failed", ts=now, caller_id=caller_id,
                    reason="unknown_account", window_failures=failures + 1,
                    error=errors.INVALID_USER_CODE,
                )
                raise errors.DeviceAuthError(
                    errors.INVALID_USER_CODE,
                    "短码无效或没有待批准的申请",
                )

            if decision == "deny":
                self.storage.update_grant(
                    grant["id"], status=DENIED, decided_at=now,
                    account_id=account_id,
                )
                self.log.event(
                    "approve_decided", ts=now, grant_id=grant["id"],
                    caller_id=caller_id, account_id=account_id,
                    decision="deny", status=DENIED, result="denied",
                )
                return {
                    "result": "denied", "status": DENIED,
                    "grant_id": grant["id"], "account_id": account_id,
                }

            # 批准：client_id 与 scope 从此冻结在申请上，轮询兑换不得扩大
            self.storage.update_grant(
                grant["id"], status=APPROVED, decided_at=now,
                account_id=account_id,
            )
            self.log.event(
                "approve_decided", ts=now, grant_id=grant["id"],
                caller_id=caller_id, account_id=account_id,
                decision="approve", status=APPROVED, result="approved",
                client_id=grant["client_id"], scope=grant["scope"],
            )
            return {
                "result": "approved", "status": APPROVED,
                "grant_id": grant["id"], "account_id": account_id,
                "client_id": grant["client_id"], "scope": grant["scope"],
            }

    # ---- 入口 3：轮询与兑换 ----
    def poll(self, device_code: str, client_id: str, scope: str,
             request_id: str | None = None) -> dict:
        device_code = _require_str(device_code, "device_code")
        client_id = _require_str(client_id, "client_id")
        scope = _normalize_scope(scope)
        if request_id is not None:
            _require_str(request_id, "request_id")
        now = self.clock.now()
        params_hash = self._params_hash(device_code, client_id, scope, request_id)

        with self.storage.tx():
            grant = self.storage.get_grant_by_device_hash(sha256_hex(device_code))
            if grant is None:
                raise errors.DeviceAuthError(
                    errors.INVALID_GRANT, "device_code 查无对应申请"
                )

            # 幂等优先于一切状态判断：
            # - 同 request_id 且同申请同参数 -> 重放同一结果（不受时序影响）
            # - 同 request_id 但绑定其他申请或参数变化 -> 立即冲突
            if request_id is not None:
                prior = self.storage.get_exchange(request_id)
                if prior is not None:
                    if prior["grant_id"] != grant["id"]:
                        self.log.event(
                            "poll_idempotency_conflict", ts=now,
                            grant_id=grant["id"], client_id=client_id,
                            error=errors.IDEMPOTENCY_CONFLICT,
                        )
                        raise errors.DeviceAuthError(
                            errors.IDEMPOTENCY_CONFLICT,
                            "request_id 已绑定其他申请",
                        )
                    if prior["params_hash"] != params_hash:
                        raise errors.DeviceAuthError(
                            errors.IDEMPOTENCY_CONFLICT,
                            "request_id 重试参数与首次调用不一致",
                        )
                    self.log.event(
                        "poll_replay", ts=now, grant_id=grant["id"],
                        client_id=client_id, status=CONSUMED, result="replay",
                    )
                    return {
                        "result": "replay", "status": CONSUMED,
                        "request_id": request_id,
                        "token": prior["token"], "token_type": "Bearer",
                        "issued_at": prior["issued_at"],
                        "client_id": grant["client_id"],
                        "scope": grant["scope"],
                    }

            # 惰性到期：仅 pending 会老化（已批准的兑换资格不被到期抹掉）
            if grant["status"] == PENDING and now >= grant["expires_at"]:
                self.storage.update_grant(grant["id"], status=EXPIRED)
                self.storage.commit()  # 终态先落库再报错，否则 with 回滚会抹掉
                grant = self.storage.get_grant_by_device_hash(sha256_hex(device_code))

            # 节流只针对等待中的申请；批准后兑换不再受间隔约束
            if grant["status"] == PENDING:
                last = grant["last_poll_at"]
                if last is not None and now - last < grant["interval_seconds"]:
                    new_interval = grant["interval_seconds"] + SLOW_DOWN_STEP
                    self.storage.update_grant(
                        grant["id"], interval_seconds=new_interval,
                        last_poll_at=now,
                    )
                    self.storage.commit()  # 间隔升级必须落库后再返回 slow_down
                    self.log.event(
                        "poll_slow_down", ts=now, grant_id=grant["id"],
                        client_id=client_id, interval=new_interval,
                        retry_after=new_interval, error=errors.SLOW_DOWN,
                    )
                    raise errors.DeviceAuthError(
                        errors.SLOW_DOWN,
                        "轮询过快，最小间隔已永久增加 5 秒",
                        {"interval": new_interval, "retry_after": new_interval},
                    )
                self.storage.update_grant(grant["id"], last_poll_at=now)
                self.storage.commit()  # last_poll_at 是下次节流判断依据，必须持久化

            status = grant["status"]
            if status == PENDING:
                self.log.event(
                    "poll_pending", ts=now, grant_id=grant["id"],
                    client_id=client_id, interval=grant["interval_seconds"],
                    status=PENDING, error=errors.AUTHORIZATION_PENDING,
                )
                raise errors.DeviceAuthError(
                    errors.AUTHORIZATION_PENDING,
                    "申请尚未被用户处理",
                    {"interval": grant["interval_seconds"]},
                )
            if status == EXPIRED:
                self.log.event("poll_expired", ts=now, grant_id=grant["id"],
                               client_id=client_id, status=EXPIRED,
                               error=errors.GRANT_EXPIRED)
                raise errors.DeviceAuthError(
                    errors.GRANT_EXPIRED, "申请已到期"
                )
            if status == DENIED:
                self.log.event("poll_denied", ts=now, grant_id=grant["id"],
                               client_id=client_id, status=DENIED,
                               error=errors.ACCESS_DENIED)
                raise errors.DeviceAuthError(
                    errors.ACCESS_DENIED, "用户拒绝了该申请"
                )
            if status == CANCELLED:
                self.log.event("poll_cancelled", ts=now, grant_id=grant["id"],
                               client_id=client_id, status=CANCELLED,
                               error=errors.GRANT_CANCELLED)
                raise errors.DeviceAuthError(
                    errors.GRANT_CANCELLED, "申请已被取消"
                )
            if status == CONSUMED:
                self.log.event("poll_consumed", ts=now, grant_id=grant["id"],
                               client_id=client_id, status=CONSUMED,
                               error=errors.GRANT_CONSUMED)
                raise errors.DeviceAuthError(
                    errors.GRANT_CONSUMED,
                    "该申请已被其他 request_id 兑换，不能再次消费",
                )

            # status == APPROVED：兑换路径，强制绑定校验，禁止扩大 scope
            if client_id != grant["client_id"]:
                self.log.event("poll_bad_client", ts=now, grant_id=grant["id"],
                               client_id=client_id, error=errors.INVALID_CLIENT)
                raise errors.DeviceAuthError(
                    errors.INVALID_CLIENT, "client_id 与申请绑定不一致"
                )
            if scope != grant["scope"]:
                self.log.event("poll_bad_scope", ts=now, grant_id=grant["id"],
                               client_id=client_id, scope=scope,
                               error=errors.INVALID_SCOPE)
                raise errors.DeviceAuthError(
                    errors.INVALID_SCOPE,
                    "scope 与批准时绑定的范围不一致，不得扩大或变更",
                )
            if request_id is None:
                raise errors.DeviceAuthError(
                    errors.REQUEST_ID_REQUIRED,
                    "兑换必须携带客户端预先声明的 request_id",
                )

            existing = self.storage.get_exchange_by_grant(grant["id"])
            if existing is not None:
                raise errors.DeviceAuthError(
                    errors.GRANT_CONSUMED,
                    "该申请已被其他 request_id 兑换，不能再次消费",
                )

            token = self.codes.token()
            try:
                self.storage.insert_exchange({
                    "request_id": request_id,
                    "grant_id": grant["id"],
                    "params_hash": params_hash,
                    "token": token,
                    "issued_at": now,
                })
            except sqlite3.IntegrityError:
                # 并发下 request_id 撞车：重读裁决，能重放就重放
                raced = self.storage.get_exchange(request_id)
                if raced is not None and raced["params_hash"] == params_hash:
                    return {
                        "result": "replay", "status": CONSUMED,
                        "request_id": request_id,
                        "token": raced["token"], "token_type": "Bearer",
                        "issued_at": raced["issued_at"],
                        "client_id": grant["client_id"],
                        "scope": grant["scope"],
                    }
                raise errors.DeviceAuthError(
                    errors.GRANT_CONSUMED, "申请已被并发兑换"
                )
            self.storage.update_grant(grant["id"], status=CONSUMED)
            self.log.event(
                "poll_issued", ts=now, grant_id=grant["id"],
                client_id=client_id, scope=scope, status=CONSUMED,
                result="issued",
            )
            return {
                "result": "issued", "status": CONSUMED,
                "request_id": request_id,
                "token": token, "token_type": "Bearer",
                "issued_at": now,
                "client_id": grant["client_id"], "scope": grant["scope"],
            }

    # ---- 入口 4：取消 ----
    def cancel(self, device_code: str) -> dict:
        device_code = _require_str(device_code, "device_code")
        now = self.clock.now()
        with self.storage.tx():
            grant = self.storage.get_grant_by_device_hash(sha256_hex(device_code))
            if grant is None:
                raise errors.DeviceAuthError(
                    errors.INVALID_GRANT, "device_code 查无对应申请"
                )
            if grant["status"] == CANCELLED:
                return {"result": "cancelled", "status": CANCELLED,
                        "grant_id": grant["id"]}
            if grant["status"] == EXPIRED:
                self.log.event("cancel_expired", ts=now,
                               grant_id=grant["id"], status=EXPIRED,
                               error=errors.GRANT_EXPIRED)
                raise errors.DeviceAuthError(
                    errors.GRANT_EXPIRED, "申请已到期"
                )
            if grant["status"] == PENDING:
                if now >= grant["expires_at"]:
                    self.storage.update_grant(grant["id"], status=EXPIRED)
                    self.storage.commit()
                    self.log.event("cancel_expired", ts=now,
                                   grant_id=grant["id"], status=EXPIRED,
                                   error=errors.GRANT_EXPIRED)
                    raise errors.DeviceAuthError(
                        errors.GRANT_EXPIRED, "申请已到期，取消前已老化"
                    )
                self.storage.update_grant(
                    grant["id"], status=CANCELLED, decided_at=now
                )
                self.log.event("cancel", ts=now, grant_id=grant["id"],
                               status=CANCELLED, result="cancelled")
                return {"result": "cancelled", "status": CANCELLED,
                        "grant_id": grant["id"]}
            # 批准/拒绝/到期/已消费均为终态，竞争败方拿到 conflict_state
            self.log.event("cancel_conflict", ts=now, grant_id=grant["id"],
                           status=grant["status"], error=errors.CONFLICT_STATE)
            raise errors.DeviceAuthError(
                errors.CONFLICT_STATE,
                "申请已处于终态，无法取消",
                {"current_status": grant["status"]},
            )

    @staticmethod
    def _params_hash(device_code: str, client_id: str, scope: str,
                     request_id: str | None) -> str:
        canonical = json.dumps(
            {
                "device_code": device_code,
                "client_id": client_id,
                "scope": scope,
                "request_id": request_id,
            },
            sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        )
        return sha256_hex(canonical)
