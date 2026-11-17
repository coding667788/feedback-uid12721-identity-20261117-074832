"""审计日志脱敏：任何路径都不得写入原始 device_code、user_code 或令牌。"""

from solution.audit import SafeLogger
from solution import errors
from tests._base import ServiceTestCase


class AuditLogTests(ServiceTestCase):
    def test_log_never_contains_raw_secrets_on_happy_path(self):
        reg = self.register(ttl=600)
        self._poll(reg)
        self.service.approve("alice", reg["user_code"], "alice")
        issued = self.service.poll(reg["device_code"], "client-a",
                                   "read data", "req-secret")
        self.service.poll(reg["device_code"], "client-a",
                          "read data", "req-secret")  # replay
        text = self.read_log()
        self.assertNotIn(reg["device_code"], text)
        self.assertNotIn(reg["user_code"], text)
        self.assertNotIn(reg["user_code"].replace("-", ""), text)
        self.assertNotIn(issued["token"], text)
        self.assertNotIn("req-secret", text)
        # 但允许记录非敏感标识与状态
        self.assertIn("register", text)
        self.assertIn("poll_issued", text)

    def test_log_secrets_absent_under_failures_too(self):
        reg = self.register(ttl=600)
        for i in range(5):
            try:
                self.service.approve("mallory", f"2345-678{i}", "alice")
            except errors.DeviceAuthError:
                pass
        try:
            self.service.poll("wrong-device-code", "client-a", "read data")
        except errors.DeviceAuthError:
            pass
        text = self.read_log()
        self.assertNotIn(reg["device_code"], text)
        self.assertNotIn("wrong-device-code", text)

    def test_safe_logger_rejects_non_whitelisted_fields(self):
        with self.assertRaises(ValueError):
            self.logger.event("bad", device_code="leak")
        with self.assertRaises(ValueError):
            self.logger.event("bad", token="leak")
        # 白名单字段正常写入（action 是位置参数，不要重复传关键字）
        self.logger.event("register", grant_id=1, status="pending")
        self.assertIn("register", self.read_log())

    def _poll(self, reg):
        try:
            self.service.poll(reg["device_code"], "client-a", "read data")
        except errors.DeviceAuthError:
            pass


if __name__ == "__main__":
    unittest.main()
