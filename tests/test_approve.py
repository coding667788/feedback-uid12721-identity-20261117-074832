"""短码批准入口：同形错误、60s/5 次滑动窗口、窗口持久化、按调用方隔离。"""

from solution import errors
from solution.codes import normalize_user_code, sha256_hex
from tests._base import ServiceTestCase


class ApproveRateLimitTests(ServiceTestCase):
    def test_unknown_account_and_bad_code_return_identical_error(self):
        reg = self.register()
        e1 = self._approve_error("mallory", "ZZZZ-ZZZZ", "alice")
        e2 = self._approve_error("mallory", reg["user_code"], "ghost")
        self.assertEqual(e1.code, errors.INVALID_USER_CODE)
        self.assertEqual(e2.code, errors.INVALID_USER_CODE)
        # 外部错误结构完全同形（相同错误码与描述），不泄露账号是否存在
        self.assertEqual(e1.to_dict()["error"], e2.to_dict()["error"])
        self.assertEqual(e1.to_dict()["error_description"],
                         e2.to_dict()["error_description"])

    def test_sixth_attempt_within_window_is_rate_limited(self):
        reg = self.register(ttl=600)
        for i in range(5):
            err = self._approve_error("mallory", f"2345-678{i}", "alice")
            self.assertEqual(err.code, errors.INVALID_USER_CODE)
        # 第 6 次：哪怕短码正确也被限流，且不消耗该申请
        blocked = self._approve_error("mallory", reg["user_code"], "alice")
        self.assertEqual(blocked.code, errors.RATE_LIMITED)
        self.assertGreaterEqual(blocked.extra["retry_after"], 1)
        # 申请仍是 pending，未被批准
        row = self.storage.get_grant_by_user_hash(
            sha256_hex(normalize_user_code(reg["user_code"])))
        self.assertEqual(row["status"], "pending")

    def test_sliding_window_expires_after_60_seconds(self):
        reg = self.register(ttl=600)
        for i in range(5):
            self._approve_error("mallory", f"2345-678{i}", "alice")
        self.clock.advance(30)
        self.assertEqual(
            self._approve_error("mallory", "AAAA-BBBB", "alice").code,
            errors.RATE_LIMITED)
        # 再推进 31s：最早的失败事件滑出 60s 窗口
        self.clock.advance(31)
        ok = self.service.approve("mallory", reg["user_code"], "alice")
        self.assertEqual(ok["result"], "approved")

    def test_rate_limit_is_per_caller(self):
        for i in range(5):
            self._approve_error("mallory", f"2345-678{i}", "alice")
        # 另一调用方拥有独立窗口，不受 mallory 影响
        err = self._approve_error("carol", "ZZZZ-ZZZZ", "alice")
        self.assertEqual(err.code, errors.INVALID_USER_CODE)

    def test_failures_persist_across_restart(self):
        for i in range(3):
            self._approve_error("mallory", f"2345-678{i}", "alice")
        # 重启进程，计数仍在库中；再错 2 次即触顶
        self.logger.close()
        self.storage.close()
        from solution.storage import Storage
        from solution.audit import SafeLogger
        from solution.service import DeviceAuthService
        from solution.codes import CodeGenerator
        storage2 = Storage(self.db_path)
        logger2 = SafeLogger(self.log_path)
        service2 = DeviceAuthService(storage2, self.clock, CodeGenerator(), logger2)
        try:
            for i in range(2):
                with self.assertRaises(errors.DeviceAuthError) as ctx:
                    service2.approve("mallory", f"AAAA-BB{i}B", "alice")
                self.assertEqual(ctx.exception.code, errors.INVALID_USER_CODE)
            with self.assertRaises(errors.DeviceAuthError) as ctx:
                service2.approve("mallory", "CCCC-DDDD", "alice")
            self.assertEqual(ctx.exception.code, errors.RATE_LIMITED)
        finally:
            logger2.close()
            storage2.close()

    def test_successful_approve_does_not_count_failure(self):
        reg = self.register(ttl=600)
        for i in range(4):
            self._approve_error("mallory", f"2345-678{i}", "alice")
        ok = self.service.approve("mallory", reg["user_code"], "alice")
        self.assertEqual(ok["status"], "approved")
        # 成功后该短码不可再用（申请已非 pending），错误仍是同形 invalid_user_code
        err = self._approve_error("mallory", reg["user_code"], "alice")
        self.assertEqual(err.code, errors.INVALID_USER_CODE)

    def _approve_error(self, caller, code, account):
        with self.assertRaises(errors.DeviceAuthError) as ctx:
            self.service.approve(caller, code, account)
        return ctx.exception


if __name__ == "__main__":
    unittest.main()
