"""代码生成与哈希：256 位秘密、短码空间、二者不可互推、固定种子可重放。"""

import base64
import random
import unittest

from solution.codes import (
    CodeGenerator, USER_CODE_ALPHABET, format_user_code,
    normalize_user_code, sha256_hex,
)
from tests._base import SEED, ServiceTestCase


class CodeGeneratorTests(unittest.TestCase):
    def test_device_code_is_256_bits(self):
        gen = CodeGenerator()
        code = gen.device_code()
        raw = base64.urlsafe_b64decode(code + "=" * (-len(code) % 4))
        self.assertEqual(len(raw), 32, "device_code 必须解码为 32 字节（256 位）")

    def test_device_codes_unique_and_high_entropy(self):
        gen = CodeGenerator()
        codes = {gen.device_code() for _ in range(200)}
        self.assertEqual(len(codes), 200)

    def test_user_code_shape_and_alphabet(self):
        gen = CodeGenerator()
        for _ in range(50):
            code = gen.user_code()
            self.assertEqual(len(code), 8)
            self.assertTrue(all(ch in USER_CODE_ALPHABET for ch in code))
            formatted = format_user_code(code)
            self.assertRegex(formatted, r"^[23456789A-HJ-NP-Z]{4}-[23456789A-HJ-NP-Z]{4}$")

    def test_user_code_normalization(self):
        gen = CodeGenerator()
        code = gen.user_code()
        formatted = format_user_code(code).lower()
        self.assertEqual(normalize_user_code(formatted), code)
        self.assertEqual(normalize_user_code(" " + formatted.replace("-", "  ")),
                         code)

    def test_seeded_generator_is_replayable(self):
        g1, g2 = CodeGenerator(random.Random(SEED)), CodeGenerator(random.Random(SEED))
        for _ in range(10):
            self.assertEqual(g1.device_code(), g2.device_code())
            self.assertEqual(g1.user_code(), g2.user_code())
            self.assertEqual(g1.token(), g2.token())

    def test_device_and_user_codes_independent(self):
        # 固定种子下两串序列都确定，但任一者都不能由另一者派生：
        # 哈希索引不同，且不存在共享前缀/包含关系
        g = CodeGenerator(random.Random(SEED))
        d, u = g.device_code(), g.user_code()
        self.assertNotEqual(sha256_hex(d), sha256_hex(u))
        self.assertNotIn(u, d)
        self.assertNotIn(d, u)
        # 数据库仅存哈希：原始值与其哈希可区分，哈希不可逆推
        self.assertNotEqual(d, sha256_hex(d))
        self.assertEqual(len(sha256_hex(d)), 64)


class StorageSecrecyTests(ServiceTestCase):
    def test_database_never_stores_raw_secrets(self):
        reg = self.register()
        import sqlite3
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute(
                "SELECT device_code_hash, user_code_hash, status FROM grants"
            ).fetchall()
        finally:
            conn.close()
        device_hash, user_hash, status = tuple(rows[0])
        self.assertEqual(device_hash, sha256_hex(reg["device_code"]))
        self.assertEqual(user_hash, sha256_hex(normalize_user_code(reg["user_code"])))
        self.assertEqual(status, "pending")
        # 任何文本列都不得出现原始 device_code
        self.assertNotIn(reg["device_code"], "".join(map(str, rows[0])))


if __name__ == "__main__":
    unittest.main()
