"""本地设备授权服务（自定义协议，非完整 OAuth 兼容实现）。

对外暴露四个入口：
- DeviceAuthService.register  申请（device authorization request）
- DeviceAuthService.approve   用户短码批准/拒绝
- DeviceAuthService.poll      终端轮询与兑换（含幂等消费）
- DeviceAuthService.cancel    申请取消

所有时间均为显式整数秒时钟，持久化由 SQLite 承担。
"""

from .clock import ManualClock, SystemClock, DBClock
from .codes import CodeGenerator
from .service import DeviceAuthService
from .storage import Storage

__all__ = [
    "DeviceAuthService",
    "Storage",
    "CodeGenerator",
    "ManualClock",
    "SystemClock",
    "DBClock",
]

__version__ = "1.0.0"
