"""显式整数秒时钟。

- ManualClock：测试/脚本驱动，时间只能整数秒推进，结果可重放。
- SystemClock：真实部署使用，取 int(time.time())。
- DBClock：独立子进程使用，时间从 SQLite meta 表读取（由父进程写入），
  从而多个操作系统进程仍共享同一个确定性整数时钟。
"""

import time


class ManualClock:
    def __init__(self, start: int = 0):
        self._now = int(start)

    def now(self) -> int:
        return self._now

    def advance(self, seconds: int) -> int:
        if seconds < 0:
            raise ValueError("时钟不能回拨")
        self._now += int(seconds)
        return self._now

    def set(self, value: int) -> None:
        self._now = int(value)


class SystemClock:
    def now(self) -> int:
        return int(time.time())

    def advance(self, seconds: int) -> None:  # 真实时钟只能等待
        time.sleep(max(0, int(seconds)))


class DBClock:
    """从 Storage 的 meta 表读取虚拟当前时间。"""

    def __init__(self, storage):
        self._storage = storage

    def now(self) -> int:
        raw = self._storage.get_meta("now")
        if raw is None:
            raise RuntimeError("数据库 meta.now 尚未初始化，无法由 DBClock 读取时间")
        return int(raw)
