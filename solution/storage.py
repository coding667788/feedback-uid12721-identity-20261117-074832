"""SQLite 持久化层。

设计要点：
- WAL + busy_timeout，支持两个独立 OS 进程同时打开同一个库做轮询。
- 所有状态变更走 BEGIN IMMEDIATE 写事务，批准/取消竞争由数据库串行化裁决，
  只允许一个终态落库。
- device_code、user_code 只存 SHA-256 哈希；令牌仅在 exchanges 表内留存
  （为支持 request_id 幂等重放），日志层另有脱敏约束。
- 轮询间隔、寿命、限流计数全部落库，进程重启不重置。
"""

import sqlite3
from contextlib import contextmanager

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS accounts (
    account_id TEXT PRIMARY KEY,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS grants (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id          TEXT NOT NULL,
    scope              TEXT NOT NULL,
    device_code_hash   TEXT NOT NULL UNIQUE,
    user_code_hash     TEXT NOT NULL UNIQUE,
    status             TEXT NOT NULL,
    interval_seconds   INTEGER NOT NULL,
    last_poll_at       INTEGER,
    expires_at         INTEGER NOT NULL,
    created_at         INTEGER NOT NULL,
    decided_at         INTEGER,
    account_id         TEXT
);

CREATE TABLE IF NOT EXISTS exchanges (
    request_id      TEXT PRIMARY KEY,
    grant_id        INTEGER NOT NULL,
    params_hash     TEXT NOT NULL,
    token           TEXT NOT NULL,
    issued_at       INTEGER NOT NULL,
    FOREIGN KEY (grant_id) REFERENCES grants(id)
);

CREATE TABLE IF NOT EXISTS rate_events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    caller_id  TEXT NOT NULL,
    ts         INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_grants_user_hash ON grants(user_code_hash);
CREATE INDEX IF NOT EXISTS idx_rate_caller_ts ON rate_events(caller_id, ts);
"""


class Storage:
    def __init__(self, path: str):
        self.path = path
        self.conn = sqlite3.connect(
            path, timeout=30.0, isolation_level=None, check_same_thread=False
        )
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.execute("PRAGMA busy_timeout=30000")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.executescript(SCHEMA)

    def close(self) -> None:
        self.conn.close()

    # ---- 事务 ----
    @contextmanager
    def tx(self):
        """BEGIN IMMEDIATE 立即取写锁；提交/回滚在退出时完成。

        允许在 with 块内显式 commit()（例如先持久化限流计数再抛错），
        此时退出时的回滚是空操作。
        """
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            yield self.conn
            if self.conn.in_transaction:
                self.conn.execute("COMMIT")
        except Exception:
            if self.conn.in_transaction:
                self.conn.execute("ROLLBACK")
            raise

    def commit(self) -> None:
        """供“先持久化计数再抛错”的场景显式提交。"""
        if self.conn.in_transaction:
            self.conn.execute("COMMIT")

    # ---- meta（含 DBClock 使用的虚拟时间） ----
    def set_meta(self, key: str, value) -> None:
        self.conn.execute(
            "INSERT INTO meta(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, str(value)),
        )

    def get_meta(self, key: str):
        row = self.conn.execute(
            "SELECT value FROM meta WHERE key=?", (key,)
        ).fetchone()
        return row["value"] if row else None

    # ---- 账号（模拟本地账号目录） ----
    def add_account(self, account_id: str, now: int) -> None:
        self.conn.execute(
            "INSERT OR IGNORE INTO accounts(account_id, created_at) VALUES(?, ?)",
            (account_id, now),
        )

    def has_account(self, account_id: str) -> bool:
        row = self.conn.execute(
            "SELECT 1 FROM accounts WHERE account_id=?", (account_id,)
        ).fetchone()
        return row is not None

    # ---- grants ----
    def insert_grant(self, row: dict) -> int:
        cur = self.conn.execute(
            "INSERT INTO grants(client_id, scope, device_code_hash, user_code_hash,"
            " status, interval_seconds, last_poll_at, expires_at, created_at,"
            " decided_at, account_id) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                row["client_id"],
                row["scope"],
                row["device_code_hash"],
                row["user_code_hash"],
                row["status"],
                row["interval_seconds"],
                row.get("last_poll_at"),
                row["expires_at"],
                row["created_at"],
                row.get("decided_at"),
                row.get("account_id"),
            ),
        )
        return cur.lastrowid

    def get_grant_by_device_hash(self, device_code_hash: str):
        return self.conn.execute(
            "SELECT * FROM grants WHERE device_code_hash=?", (device_code_hash,)
        ).fetchone()

    def get_grant_by_user_hash(self, user_code_hash: str):
        return self.conn.execute(
            "SELECT * FROM grants WHERE user_code_hash=?", (user_code_hash,)
        ).fetchone()

    def update_grant(self, grant_id: int, **fields) -> None:
        if not fields:
            return
        cols = ", ".join(f"{k}=?" for k in fields)
        self.conn.execute(
            f"UPDATE grants SET {cols} WHERE id=?",
            (*fields.values(), grant_id),
        )

    # ---- exchanges（兑换结果摘要 + 幂等） ----
    def insert_exchange(self, row: dict) -> None:
        self.conn.execute(
            "INSERT INTO exchanges(request_id, grant_id, params_hash, token, issued_at)"
            " VALUES(?,?,?,?,?)",
            (
                row["request_id"],
                row["grant_id"],
                row["params_hash"],
                row["token"],
                row["issued_at"],
            ),
        )

    def get_exchange(self, request_id: str):
        return self.conn.execute(
            "SELECT * FROM exchanges WHERE request_id=?", (request_id,)
        ).fetchone()

    def get_exchange_by_grant(self, grant_id: int):
        return self.conn.execute(
            "SELECT * FROM exchanges WHERE grant_id=? LIMIT 1", (grant_id,)
        ).fetchone()

    # ---- 短码入口限流事件 ----
    def add_rate_event(self, caller_id: str, ts: int) -> None:
        self.conn.execute(
            "INSERT INTO rate_events(caller_id, ts) VALUES(?, ?)", (caller_id, ts)
        )

    def count_rate_events(self, caller_id: str, window_start: int, now: int) -> int:
        """滑动窗口 [window_start, now] 内的失败次数。"""
        row = self.conn.execute(
            "SELECT COUNT(*) AS c FROM rate_events "
            "WHERE caller_id=? AND ts >= ? AND ts <= ?",
            (caller_id, window_start, now),
        ).fetchone()
        return row["c"]

    def oldest_rate_event(self, caller_id: str, window_start: int, now: int):
        row = self.conn.execute(
            "SELECT MIN(ts) AS ts FROM rate_events "
            "WHERE caller_id=? AND ts >= ? AND ts <= ?",
            (caller_id, window_start, now),
        ).fetchone()
        return row["ts"] if row and row["ts"] is not None else None

    def prune_rate_events(self, before: int) -> None:
        self.conn.execute("DELETE FROM rate_events WHERE ts < ?", (before,))
