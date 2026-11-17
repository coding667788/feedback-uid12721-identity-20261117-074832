"""一次性子进程 worker：让两个独立 OS 进程轮询同一个 SQLite 库。

用法（cwd 为项目根，-I 隔离模式下由 sys.path 注入项目根）::

    python -I -c "import sys; sys.path.insert(0, r'<项目根>'); \
        from solution.worker import main; raise SystemExit(main())" \
        --db runtime/x.db --log runtime/x.log --action poll \
        --device-code ... --client-id ... --scope ... [--request-id ...]

action: register | approve | poll | cancel | set-time
成功时 stdout 输出一行 JSON、退出码 0；
协议错误时 stdout 输出错误 JSON、退出码 2；其他失败退出码 1。
时间始终取自数据库 meta.now（DBClock），由 --set-time 或父进程写入。
"""

import argparse
import json
import random
import sys

from .audit import SafeLogger
from .clock import DBClock
from .codes import CodeGenerator
from .errors import DeviceAuthError
from .service import DeviceAuthService
from .storage import Storage


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="设备授权服务一次性进程 worker")
    p.add_argument("--db", required=True)
    p.add_argument("--log", required=False)
    p.add_argument("--action", required=True,
                   choices=["register", "approve", "poll", "cancel", "set-time"])
    p.add_argument("--client-id")
    p.add_argument("--scope")
    p.add_argument("--ttl", type=int, default=300)
    p.add_argument("--device-code")
    p.add_argument("--user-code")
    p.add_argument("--caller-id")
    p.add_argument("--account-id")
    p.add_argument("--decision", default="approve")
    p.add_argument("--request-id")
    p.add_argument("--now", type=int)
    p.add_argument("--seed", type=int,
                   help="固定随机种子；不传则使用 OS CSPRNG（生产模式）")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    storage = Storage(args.db)
    try:
        if args.action == "set-time":
            storage.set_meta("now", int(args.now))
            print(json.dumps({"ok": True, "now": args.now}))
            return 0

        logger = SafeLogger(args.log or (args.db + ".worker.log"))
        if args.seed is None:
            generator = CodeGenerator()
        else:
            # 子进程同样分离代码流与令牌流，保证跨运行逐字节重放
            generator = CodeGenerator(
                random.Random(args.seed), random.Random(args.seed + 10_000_000))
        service = DeviceAuthService(storage, DBClock(storage), generator, logger)
        if args.action == "register":
            result = service.register(args.client_id, args.scope, args.ttl)
        elif args.action == "approve":
            result = service.approve(args.caller_id, args.user_code,
                                     args.account_id, args.decision)
        elif args.action == "poll":
            result = service.poll(args.device_code, args.client_id, args.scope,
                                  args.request_id)
        else:  # cancel
            result = service.cancel(args.device_code)
        logger.close()
        print(json.dumps({"ok": True, "result": result}, ensure_ascii=False))
        return 0
    except DeviceAuthError as exc:
        print(json.dumps({"ok": False, "error": exc.to_dict()},
                         ensure_ascii=False))
        return 2
    finally:
        storage.close()
