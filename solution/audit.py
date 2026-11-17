"""脱敏审计日志。

只允许白名单字段落盘；device_code、user_code、令牌、request_id 等秘密
一律没有对应的白名单键，误传会直接抛错，避免日志泄密。
"""

import json


class SafeLogger:
    ALLOWED_KEYS = {
        "ts", "action", "grant_id", "client_id", "scope", "status", "result",
        "error", "caller_id", "account_id", "decision", "interval",
        "expires_at", "ttl", "retry_after", "reason", "window_failures",
    }

    def __init__(self, path: str):
        # utf-8 + 换行刷新，跨进程 append 在同机本地盘上足够
        self._fp = open(path, "a", encoding="utf-8", newline="\n")

    def event(self, action: str, **fields) -> None:
        bad = set(fields) - self.ALLOWED_KEYS
        if bad:
            raise ValueError(f"审计日志禁止记录字段: {sorted(bad)}")
        record = {"action": action}
        record.update(fields)
        self._fp.write(json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n")
        self._fp.flush()

    def close(self) -> None:
        self._fp.close()
