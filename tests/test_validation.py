"""输入校验与状态机杂项：非法参数、scope 归一化、取消边界。"""

from solution import errors
from solution.audit import SafeLogger
from solution.codes import CodeGenerator
from solution.service import DeviceAuthService
from solution.storage import Storage
from tests._base import ServiceTestCase


class ValidationTests(ServiceTestCase):
    def test_register_rejects_bad_inputs(self):
        for args in (("", "read"), ("c", ""), ("c", "   "), (None, "read")):
            with self.assertRaises(errors.DeviceAuthError) as ctx:
                self.service.register(args[0], args[1])
            self.assertEqual(ctx.exception.code, errors.INVALID_REQUEST)
        with self.assertRaises(errors.DeviceAuthError):
            self.service.register("c", "read", ttl=0)
        with self.assertRaises(errors.DeviceAuthError):
            self.service.register("c", "read", ttl=-5)

    def test_scope_normalized_and_frozen(self):
        reg = self.service.register("c", "write read write", ttl=600)
        # 注册时 scope 被归一化为排序去重形式
        import sqlite3
        conn = sqlite3.connect(self.db_path)
        try:
            scope = conn.execute(
                "SELECT scope FROM grants WHERE id=?", (reg["grant_id"],)
            ).fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(scope, "read write")
        self.service.approve("alice", reg["user_code"], "alice")
        # 轮询端按归一化后的等价形式请求是允许的
        ok = self.service.poll(reg["device_code"], "c", "read  write",
                               "req-norm")
        self.assertEqual(ok["scope"], "read write")

    def test_cancel_unknown_grant(self):
        with self.assertRaises(errors.DeviceAuthError) as ctx:
            self.service.cancel("ghost-device-code")
        self.assertEqual(ctx.exception.code, errors.INVALID_GRANT)

    def test_approve_rejects_bad_decision(self):
        reg = self.register(ttl=600)
        with self.assertRaises(errors.DeviceAuthError):
            self.service.approve("alice", reg["user_code"], "alice",
                                 decision="maybe")

    def test_denied_grant_cannot_be_exchanged(self):
        reg = self.register(ttl=600)
        self.service.approve("bob", reg["user_code"], "bob", "deny")
        with self.assertRaises(errors.DeviceAuthError) as ctx:
            self.service.poll(reg["device_code"], "client-a", "read data",
                              "req-x")
        self.assertEqual(ctx.exception.code, errors.ACCESS_DENIED)

    def test_full_lifecycle_restart_keeps_lifetime(self):
        # 寿命不随重启延长：申请后推进 200s，重启，再推进到到期
        reg = self.register(ttl=300)
        self.clock.advance(200)
        self.logger.close()
        self.storage.close()
        storage2 = Storage(self.db_path)
        logger2 = SafeLogger(self.log_path)
        service2 = DeviceAuthService(storage2, self.clock, CodeGenerator(), logger2)
        self.clock.advance(100)  # 累计 300s，恰好到期
        try:
            with self.assertRaises(errors.DeviceAuthError) as ctx:
                service2.poll(reg["device_code"], "client-a", "read data")
            self.assertEqual(ctx.exception.code, errors.GRANT_EXPIRED)
        finally:
            logger2.close()
            storage2.close()


if __name__ == "__main__":
    unittest.main()
