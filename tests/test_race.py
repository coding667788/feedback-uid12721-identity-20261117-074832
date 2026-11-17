"""批准/取消竞争与并发兑换：SQLite 事务保证唯一终态。"""

import threading

from solution import errors
from solution.audit import SafeLogger
from solution.codes import normalize_user_code, sha256_hex
from solution.service import DeviceAuthService
from solution.codes import CodeGenerator
from solution.storage import Storage
from tests._base import ServiceTestCase


class RaceTests(ServiceTestCase):
    def _parallel_service(self):
        storage = Storage(self.db_path)
        logger = SafeLogger(self.log_path)
        service = DeviceAuthService(storage, self.clock, CodeGenerator(), logger)
        return storage, logger, service

    def test_approve_and_cancel_single_terminal_state(self):
        reg = self.register(ttl=600)
        outcomes = []
        barrier = threading.Barrier(2)

        def do_approve():
            storage, logger, service = self._parallel_service()
            barrier.wait()
            try:
                outcomes.append(("approve", service.approve(
                    "alice", reg["user_code"], "alice")))
            except errors.DeviceAuthError as exc:
                outcomes.append(("approve_err", exc.code))
            finally:
                logger.close()
                storage.close()

        def do_cancel():
            storage, logger, service = self._parallel_service()
            barrier.wait()
            try:
                outcomes.append(("cancel", service.cancel(reg["device_code"])))
            except errors.DeviceAuthError as exc:
                outcomes.append(("cancel_err", exc.code))
            finally:
                logger.close()
                storage.close()

        t1, t2 = threading.Thread(target=do_approve), threading.Thread(target=do_cancel)
        t1.start(); t2.start(); t1.join(); t2.join()

        row = self.storage.get_grant_by_user_hash(
            sha256_hex(normalize_user_code(reg["user_code"])))
        self.assertIn(row["status"], ("approved", "cancelled"))
        kinds = {name for name, _ in outcomes}
        # 恰好一方成功，另一方失败；不可能双方都成功
        successes = [name for name, value in outcomes
                     if name in ("approve", "cancel")]
        self.assertEqual(len(successes), 1, f"竞争结果: {outcomes}")
        if row["status"] == "approved":
            self.assertIn("approve", kinds)
            self.assertTrue(any(n == "cancel_err" and v == errors.CONFLICT_STATE
                                for n, v in outcomes))
        else:
            self.assertIn("cancel", kinds)

    def test_double_approve_only_one_succeeds(self):
        reg = self.register(ttl=600)
        results = []
        barrier = threading.Barrier(2)

        def attempt():
            storage, logger, service = self._parallel_service()
            barrier.wait()
            try:
                results.append(service.approve("alice", reg["user_code"], "alice"))
            except errors.DeviceAuthError as exc:
                results.append(exc)
            finally:
                logger.close()
                storage.close()

        threads = [threading.Thread(target=attempt) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        oks = [r for r in results if not isinstance(r, errors.DeviceAuthError)]
        self.assertEqual(len(oks), 1)
        row = self.storage.get_grant_by_user_hash(
            sha256_hex(normalize_user_code(reg["user_code"])))
        self.assertEqual(row["status"], "approved")

    def test_concurrent_exchange_only_one_request_id_wins(self):
        reg = self.register(ttl=600)
        self.service.approve("alice", reg["user_code"], "alice")
        results = []
        barrier = threading.Barrier(2)

        def exchange(request_id):
            storage, logger, service = self._parallel_service()
            barrier.wait()
            try:
                results.append((request_id, service.poll(
                    reg["device_code"], "client-a", "read data", request_id)))
            except errors.DeviceAuthError as exc:
                results.append((request_id, exc))
            finally:
                logger.close()
                storage.close()

        t1 = threading.Thread(target=exchange, args=("req-A",))
        t2 = threading.Thread(target=exchange, args=("req-B",))
        t1.start(); t2.start(); t1.join(); t2.join()

        issued = [(rid, r) for rid, r in results
                  if not isinstance(r, errors.DeviceAuthError)]
        rejected = [(rid, r) for rid, r in results
                    if isinstance(r, errors.DeviceAuthError)]
        self.assertEqual(len(issued), 1)
        self.assertEqual(len(rejected), 1)
        self.assertEqual(rejected[0][1].code, errors.GRANT_CONSUMED)
        # 获胜方的 request_id 仍可幂等重放
        winner_id = issued[0][0]
        replay = self.service.poll(reg["device_code"], "client-a",
                                   "read data", winner_id)
        self.assertEqual(replay["result"], "replay")
        self.assertEqual(replay["token"], issued[0][1]["token"])

    def test_cancel_is_idempotent_but_approve_after_cancel_fails(self):
        reg = self.register(ttl=600)
        first = self.service.cancel(reg["device_code"])
        self.assertEqual(first["status"], "cancelled")
        second = self.service.cancel(reg["device_code"])
        self.assertEqual(second["status"], "cancelled")
        with self.assertRaises(errors.DeviceAuthError) as ctx:
            self.service.approve("alice", reg["user_code"], "alice")
        self.assertEqual(ctx.exception.code, errors.INVALID_USER_CODE)


if __name__ == "__main__":
    unittest.main()
