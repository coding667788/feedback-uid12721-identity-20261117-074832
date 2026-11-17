"""测试公共夹具：每个用例独立临时目录 + 固定种子 + 整数时钟。"""

import os
import random
import shutil
import tempfile
import unittest

from solution.audit import SafeLogger
from solution.clock import ManualClock
from solution.codes import CodeGenerator
from solution.service import DeviceAuthService
from solution.storage import Storage

SEED = 20261117
START_TIME = 1_000_000


class ServiceTestCase(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="deviceauth_test_")
        self.db_path = os.path.join(self.tmpdir, "auth.db")
        self.log_path = os.path.join(self.tmpdir, "auth.log")
        self.clock = ManualClock(START_TIME)
        self.rng = random.Random(SEED)
        self.storage = Storage(self.db_path)
        self.storage.set_meta("now", START_TIME)
        self.logger = SafeLogger(self.log_path)
        self.service = DeviceAuthService(
            self.storage, self.clock, CodeGenerator(self.rng), self.logger)
        for account in ("alice", "bob"):
            self.storage.add_account(account, START_TIME)

    def tearDown(self):
        self.logger.close()
        self.storage.close()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def register(self, client_id="client-a", scope="read data", ttl=300):
        return self.service.register(client_id, scope, ttl)

    def read_log(self):
        with open(self.log_path, "r", encoding="utf-8") as fp:
            return fp.read()
