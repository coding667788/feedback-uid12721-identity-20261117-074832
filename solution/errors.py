"""协议错误码与统一异常类型。

错误码为自定义协议的一部分（命名借鉴 OAuth Device Flow 但不宣称兼容）。
所有外部错误响应结构固定为::

    {"error": <错误码>, "error_description": <人类可读说明>, ...附加字段}
"""


class DeviceAuthError(Exception):
    """所有可预期的协议失败都抛此异常，由入口层序列化为统一结构。"""

    def __init__(self, code: str, message: str, extra: dict | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.extra = dict(extra or {})

    def to_dict(self) -> dict:
        payload = {"error": self.code, "error_description": self.message}
        payload.update(self.extra)
        return payload


# ---- 错误码常量（README“错误码表”与测试均引用这些名字） ----

INVALID_REQUEST = "invalid_request"              # 入参缺失或类型错误
INVALID_CLIENT = "invalid_client"                # client_id 与申请绑定不一致
INVALID_SCOPE = "invalid_scope"                  # scope 与申请绑定不一致/被扩大
INVALID_GRANT = "invalid_grant"                  # device_code 查无此申请
INVALID_USER_CODE = "invalid_user_code"          # 短码错误（与账号不存在同形）
RATE_LIMITED = "rate_limited"                    # 短码入口滑动窗口限流
AUTHORIZATION_PENDING = "authorization_pending"  # 轮询时申请尚未被处理
SLOW_DOWN = "slow_down"                          # 轮询过快，间隔永久 +5s
ACCESS_DENIED = "access_denied"                  # 用户拒绝
GRANT_EXPIRED = "grant_expired"                  # 申请到期（now >= expires_at）
GRANT_CANCELLED = "grant_cancelled"              # 申请被取消
GRANT_CONSUMED = "grant_consumed"                # 已被别的 request_id 兑换
IDEMPOTENCY_CONFLICT = "idempotency_conflict"    # 同 request_id 参数发生变化
CONFLICT_STATE = "conflict_state"                # 批准/取消竞争中的败方状态
REQUEST_ID_REQUIRED = "request_id_required"      # 批准后兑换缺少预声明 request_id
