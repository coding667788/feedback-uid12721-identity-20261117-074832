"""轮询节流：5 秒最小间隔、slow_down 永久 +5s、重启不重置、终态结果分离。"""

from solution import errors
from solution.codes import sha256_hex
from tests._base import ServiceTestCase


class SlowDownTests(ServiceTestCase):
    def test_first_poll_is_pending_and_records_timestamp(self):
        reg = self.register(ttl=600)
        err = self._poll_error(reg)
        self.assertEqual(err.code, errors.AUTHORIZATION_PENDING)
        self.assertEqual(err.extra["interval"], 5)

    def test_too_fast_poll_upgrades_interval_permanently(self):
        reg = self.register(ttl=600)
        self._poll_error(reg)  # t=0 首次，建立 last_poll_at
        self.clock.advance(2)  # 距上次仅 2s < 5s
        err = self._poll_error(reg)
        self.assertEqual(err.code, errors.SLOW_DOWN)
        self.assertEqual(err.extra["interval"], 10)
        self.assertEqual(err.extra["retry_after"], 10)

        # 再次过快：在 10s 基础上再 +5s
        self.clock.advance(3)  # 距上次 3s < 10s
        err = self._poll_error(reg)
        self.assertEqual(err.code, errors.SLOW_DOWN)
        self.assertEqual(err.extra["interval"], 15)

        # 恰好满足间隔的轮询不再升级
        self.clock.advance(15)
        err = self._poll_error(reg)
        self.assertEqual(err.code, errors.AUTHORIZATION_PENDING)
        self.assertEqual(err.extra["interval"], 15, "未触发 slow_down 时间隔不变")

    def test_interval_upgrade_survives_restart(self):
        reg = self.register(ttl=600)
        self._poll_error(reg)
        self.clock.advance(1)
        self._poll_error(reg)  # -> 10s
        self.clock.advance(1)
        self._poll_error(reg)  # -> 15s

        # 模拟进程重启：新建 Storage/Service 指向同一个库
        self.logger.close()
        self.storage.close()
        from solution.storage import Storage
        from solution.audit import SafeLogger
        from solution.service import DeviceAuthService
        from solution.codes import CodeGenerator
        storage2 = Storage(self.db_path)
        logger2 = SafeLogger(self.log_path)
        service2 = DeviceAuthService(storage2, self.clock, CodeGenerator(), logger2)

        # 重启后间隔仍是 15s；立即轮询（距上次 0s）继续升级到 20s
        try:
            with self.assertRaises(errors.DeviceAuthError) as ctx:
                service2.poll(reg["device_code"], "client-a", "read data")
            self.assertEqual(ctx.exception.code, errors.SLOW_DOWN)
            self.assertEqual(ctx.exception.extra["interval"], 20)
            row = storage2.get_grant_by_device_hash(
                sha256_hex(reg["device_code"]))
            self.assertEqual(row["interval_seconds"], 20)
        finally:
            logger2.close()
            storage2.close()

    def test_distinct_results_for_pending_denied_expired_consumed(self):
        # 未批准
        reg = self.register(ttl=600)
        self.assertEqual(self._poll_error(reg).code, errors.AUTHORIZATION_PENDING)
        # 拒绝
        self.service.approve("alice", reg["user_code"], "alice", "deny")
        self.assertEqual(self._poll_error(reg).code, errors.ACCESS_DENIED)

        # 到期
        reg2 = self.register(ttl=10)
        self.clock.advance(10)  # now == expires_at，即过期
        self.assertEqual(self._poll_error(reg2).code, errors.GRANT_EXPIRED)

        # 已消费
        reg3 = self.register(ttl=600)
        self.service.approve("alice", reg3["user_code"], "alice")
        ok = self.service.poll(reg3["device_code"], "client-a", "read data",
                               "req-1")
        self.assertEqual(ok["result"], "issued")
        err = self._poll_error(reg3, request_id="req-other")
        self.assertEqual(err.code, errors.GRANT_CONSUMED)

    def test_expiry_boundary_off_by_one(self):
        reg = self.register(ttl=60)
        self.assertEqual(reg["expires_at"], 1_000_060)
        self.clock.advance(59)
        # now = expires_at - 1，仍有效，可批准
        approved = self.service.approve("alice", reg["user_code"], "alice")
        self.assertEqual(approved["result"], "approved")
        # 批准后即使跨过 expires_at，兑换资格仍然有效
        self.clock.advance(5)
        ok = self.service.poll(reg["device_code"], "client-a", "read data",
                               "req-boundary")
        self.assertEqual(ok["result"], "issued")

    def _poll_error(self, reg, request_id=None):
        with self.assertRaises(errors.DeviceAuthError) as ctx:
            self.service.poll(reg["device_code"], "client-a", "read data",
                              request_id)
        return ctx.exception


if __name__ == "__main__":
    unittest.main()
