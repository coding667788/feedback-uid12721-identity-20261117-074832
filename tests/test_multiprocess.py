"""两个独立 OS 进程轮同一个 SQLite 库（验收场景硬要求）。

子进程通过 solution.worker 以 `python -I -X utf8` 启动，时间由数据库
meta.now 共享（DBClock），从而在确定性整数时钟下验证跨进程行为。
"""

import json
import os
import subprocess
import sys

from solution.audit import SafeLogger
from solution.clock import ManualClock
from solution.codes import CodeGenerator
from solution.service import DeviceAuthService
from solution.storage import Storage
from tests._base import SEED, ServiceTestCase

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class MultiProcessTests(ServiceTestCase):
    def _worker(self, action, _seed=SEED, **kwargs):
        bootstrap = (
            "import sys; sys.path.insert(0, r'%s'); "
            "from solution.worker import main; raise SystemExit(main())" % ROOT
        )
        cmd = [sys.executable, "-I", "-X", "utf8", "-c", bootstrap,
               "--db", self.db_path, "--log", self.log_path,
               "--action", action, "--seed", str(_seed)]
        flags = {
            "client_id": "--client-id", "scope": "--scope", "ttl": "--ttl",
            "device_code": "--device-code", "user_code": "--user-code",
            "caller_id": "--caller-id", "account_id": "--account-id",
            "decision": "--decision", "request_id": "--request-id",
        }
        for key, flag in flags.items():
            if key in kwargs and kwargs[key] is not None:
                cmd.extend([flag, str(kwargs[key])])
        proc = subprocess.run(cmd, capture_output=True, encoding="utf-8",
                              errors="replace", cwd=ROOT)
        lines = [ln for ln in proc.stdout.strip().splitlines() if ln.strip()]
        self.assertTrue(lines, f"worker 无输出，stderr={proc.stderr!r}")
        payload = json.loads(lines[-1])
        return proc.returncode, payload

    def _set_time(self, now):
        self.storage.set_meta("now", now)

    def test_two_independent_processes_poll_and_consume(self):
        self._set_time(1_000_000)
        reg = self.register(ttl=600)

        # 进程 A：首次轮询 -> pending（独立解释器、独立连接）
        code, payload = self._worker(
            "poll", device_code=reg["device_code"],
            client_id="client-a", scope="read data")
        self.assertEqual(code, 2)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["error"]["error"], "authorization_pending")

        # 进程 B：同样独立轮询，共享同一 last_poll_at/间隔状态
        self._set_time(1_000_002)
        code, payload = self._worker(
            "poll", device_code=reg["device_code"],
            client_id="client-a", scope="read data")
        self.assertEqual(payload["error"]["error"], "slow_down")
        self.assertEqual(payload["error"]["interval"], 10)

        # 进程 C：在另一进程里完成用户批准
        self._set_time(1_000_030)
        code, payload = self._worker(
            "approve", caller_id="alice", user_code=reg["user_code"],
            account_id="alice")
        self.assertEqual(code, 0)
        self.assertEqual(payload["result"]["result"], "approved")

        # 进程 A 兑换成功
        code, payload_a = self._worker(
            "poll", device_code=reg["device_code"],
            client_id="client-a", scope="read data",
            request_id="req-proc-A")
        self.assertEqual(code, 0)
        self.assertEqual(payload_a["result"]["result"], "issued")
        token = payload_a["result"]["token"]

        # 进程 B 用不同 request_id 不能再次消费
        code, payload_b = self._worker(
            "poll", device_code=reg["device_code"],
            client_id="client-a", scope="read data",
            request_id="req-proc-B")
        self.assertEqual(code, 2)
        self.assertEqual(payload_b["error"]["error"], "grant_consumed")

        # 进程 A 丢响应后重放：同 request_id 返回同一令牌
        code, payload_replay = self._worker(
            "poll", device_code=reg["device_code"],
            client_id="client-a", scope="read data",
            request_id="req-proc-A")
        self.assertEqual(code, 0)
        self.assertEqual(payload_replay["result"]["result"], "replay")
        self.assertEqual(payload_replay["result"]["token"], token)

    def test_interval_upgrade_visible_in_fresh_process(self):
        self._set_time(1_000_000)
        reg = self.register(ttl=600)
        self._worker("poll", device_code=reg["device_code"],
                     client_id="client-a", scope="read data")
        self._set_time(1_000_001)
        code, payload = self._worker(
            "poll", device_code=reg["device_code"],
            client_id="client-a", scope="read data")
        self.assertEqual(payload["error"]["interval"], 10)
        # 再开一个全新进程，间隔状态从库中读取，仍然是 10s
        self._set_time(1_000_002)
        code, payload = self._worker(
            "poll", device_code=reg["device_code"],
            client_id="client-a", scope="read data")
        self.assertEqual(payload["error"]["interval"], 15)

    def test_worker_unknown_device_code(self):
        self._set_time(1_000_000)
        code, payload = self._worker(
            "poll", device_code="nonexistent",
            client_id="client-a", scope="read data")
        self.assertEqual(code, 2)
        self.assertEqual(payload["error"]["error"], "invalid_grant")


if __name__ == "__main__":
    unittest.main()
