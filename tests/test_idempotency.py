"""绑定冻结与兑换幂等：client_id/scope 不得扩大、request_id 重放与冲突。"""

from solution import errors
from solution.codes import sha256_hex
from tests._base import ServiceTestCase


class BindingAndIdempotencyTests(ServiceTestCase):
    def setUp(self):
        super().setUp()
        self.reg = self.register("client-x", "read write", ttl=600)
        self.service.approve("alice", self.reg["user_code"], "alice")

    def test_poll_cannot_change_client_id(self):
        with self.assertRaises(errors.DeviceAuthError) as ctx:
            self.service.poll(self.reg["device_code"], "client-evil",
                              "read write", "req-1")
        self.assertEqual(ctx.exception.code, errors.INVALID_CLIENT)

    def test_poll_cannot_expand_scope(self):
        for scope in ("read write admin", "read", "write read delete",
                      "READ WRITE"):
            with self.assertRaises(errors.DeviceAuthError) as ctx:
                self.service.poll(self.reg["device_code"], "client-x",
                                  scope, "req-scope")
            self.assertEqual(ctx.exception.code, errors.INVALID_SCOPE,
                             f"scope={scope!r} 必须被拒绝")

    def test_request_id_required_for_exchange(self):
        with self.assertRaises(errors.DeviceAuthError) as ctx:
            self.service.poll(self.reg["device_code"], "client-x", "read write")
        self.assertEqual(ctx.exception.code, errors.REQUEST_ID_REQUIRED)

    def test_same_request_id_replays_same_token(self):
        first = self.service.poll(self.reg["device_code"], "client-x",
                                  "read write", "req-42")
        self.assertEqual(first["result"], "issued")
        # 模拟“成功后丢响应”：客户端用相同 ID 与相同参数重试
        second = self.service.poll(self.reg["device_code"], "client-x",
                                   "read write", "req-42")
        self.assertEqual(second["result"], "replay")
        self.assertEqual(second["token"], first["token"])
        self.assertEqual(second["issued_at"], first["issued_at"])
        third = self.service.poll(self.reg["device_code"], "client-x",
                                  "read write", "req-42")
        self.assertEqual(third["token"], first["token"])

    def test_replay_with_changed_params_is_conflict(self):
        self.service.poll(self.reg["device_code"], "client-x",
                          "read write", "req-42")
        with self.assertRaises(errors.DeviceAuthError) as ctx:
            self.service.poll(self.reg["device_code"], "client-x",
                              "read write", "req-42-different")  # 不同 ID
        # 不同 request_id 不能再次兑换
        self.assertEqual(ctx.exception.code, errors.GRANT_CONSUMED)

    def test_request_id_bound_to_grant_and_params(self):
        # 先在 setUp 的申请上完成 req-42 兑换，占用该 request_id
        first = self.service.poll(self.reg["device_code"], "client-x",
                                  "read write", "req-42")
        self.assertEqual(first["result"], "issued")
        # 新申请用各自合法的绑定参数复用同一 ID，
        # 必须仅凭 request_id 归属就报冲突（而不是放行或报别的错误）
        reg2 = self.register("client-y", "read", ttl=600)
        self.service.approve("alice", reg2["user_code"], "alice")
        with self.assertRaises(errors.DeviceAuthError) as ctx:
            self.service.poll(reg2["device_code"], "client-y", "read", "req-42")
        self.assertEqual(ctx.exception.code, errors.IDEMPOTENCY_CONFLICT)

        # 同一申请上用同 ID 但改变参数（这里 scope 变化）同样冲突
        reg3 = self.register("client-z", "read write", ttl=600)
        self.service.approve("alice", reg3["user_code"], "alice")
        ok = self.service.poll(reg3["device_code"], "client-z",
                               "read write", "req-z-1")
        self.assertEqual(ok["result"], "issued")
        with self.assertRaises(errors.DeviceAuthError) as ctx:
            self.service.poll(reg3["device_code"], "client-z",
                              "read write", "req-z-1-different-params")
        # 不同 ID 不能再次消费已兑换申请
        self.assertEqual(ctx.exception.code, errors.GRANT_CONSUMED)

    def test_replay_before_consumption_returns_pending_not_token(self):
        reg = self.register("client-z", "read", ttl=600)
        # 未批准时携带 request_id 轮询：仍是 pending，不会预占兑换
        with self.assertRaises(errors.DeviceAuthError) as ctx:
            self.service.poll(reg["device_code"], "client-z", "read", "req-pre")
        self.assertEqual(ctx.exception.code, errors.AUTHORIZATION_PENDING)
        self.service.approve("bob", reg["user_code"], "bob")
        ok = self.service.poll(reg["device_code"], "client-z", "read", "req-pre")
        self.assertEqual(ok["result"], "issued")

    def test_exchange_summary_persisted_in_sqlite(self):
        import sqlite3
        self.service.poll(self.reg["device_code"], "client-x",
                          "read write", "req-db")
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            row = conn.execute(
                "SELECT request_id, params_hash, token, issued_at "
                "FROM exchanges WHERE request_id=?", ("req-db",)).fetchone()
        finally:
            conn.close()
        self.assertIsNotNone(row)
        self.assertEqual(len(row["token"]), len("lat_") + 43)
        self.assertEqual(len(row["params_hash"]), 64)
        grant = self.storage.get_grant_by_device_hash(
            sha256_hex(self.reg["device_code"]))
        self.assertEqual(grant["status"], "consumed")


if __name__ == "__main__":
    unittest.main()
