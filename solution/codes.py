"""秘密代码生成与哈希工具。

- device_code：256 位（32 字节）随机秘密，base64url 无填充文本，仅以 SHA-256
  哈希落库，数据库泄露无法还原，也无法由 user_code 反推。
- user_code：人可输入短码，字母表剔除易混字符（0/O、1/I/L 等），展示为
  XXXX-XXXX，输入时忽略大小写与连字符；同样仅以哈希落库。

两类代码使用独立随机字节生成，互相不参与对方的派生，因此索引同一份申请
却不可互推。测试可注入固定种子的 random.Random 实现可重放。
"""

import base64
import hashlib
import random
import secrets

# 去除 0/O、1/I/L 的 32 字符字母表
USER_CODE_ALPHABET = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"
USER_CODE_GROUP = 4
USER_CODE_GROUPS = 2


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def normalize_user_code(code: str) -> str:
    """归一化用户输入：去空白、去连字符、大写。"""
    if not isinstance(code, str):
        return ""
    return "".join(code.strip().upper().split("-")).replace(" ", "")


def format_user_code(code: str) -> str:
    """把紧凑短码格式化为 XXXX-XXXX 展示形式。"""
    return f"{code[:USER_CODE_GROUP]}-{code[USER_CODE_GROUP:]}"


class CodeGenerator:
    def __init__(self, rng=None, token_rng=None):
        # 生产环境默认 secrets（OS CSPRNG）；测试注入固定种子 random.Random。
        # 代码流与令牌流使用独立 RNG：竞争/到期等分支差异不会改变令牌序列，
        # 保证固定种子下逐字节可重放。
        self._rng = rng
        self._token_rng = token_rng if token_rng is not None else rng

    def device_code(self) -> str:
        if self._rng is None:
            raw = secrets.token_bytes(32)
        else:
            raw = bytes(self._rng.getrandbits(8) for _ in range(32))
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    def user_code(self) -> str:
        if self._rng is None:
            return "".join(secrets.choice(USER_CODE_ALPHABET) for _ in range(8))
        return "".join(self._rng.choice(USER_CODE_ALPHABET) for _ in range(8))

    def token(self) -> str:
        """访问令牌同样为 256 位随机秘密，前缀仅作协议标识。"""
        if self._token_rng is None:
            raw = secrets.token_bytes(32)
        else:
            raw = bytes(self._token_rng.getrandbits(8) for _ in range(32))
        return "lat_" + base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
