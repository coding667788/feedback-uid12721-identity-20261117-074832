"""cases.json 脚本执行引擎（确定性、可重放）。

脚本结构::

    {
      "seed": 20261117,
      "start_time": 100000,
      "cases": [
        {
          "name": "...",
          "db": "runtime/xxx.db",        // 相对 cases.json 所在目录
          "log": "runtime/xxx.log",
          "accounts": ["alice"],
          "steps": [ {"op": "...", ...} ]
        }
      ]
    }

所有相对路径以 cases.json 所在目录为基准；每个用例独立数据库。
步骤可用 "save" 把返回值存为变量，再用 "$变量名.字段" 在后续参数中引用。
"""

import hashlib
import json
import os
import random
import threading

from .audit import SafeLogger
from .clock import ManualClock
from .codes import CodeGenerator, normalize_user_code, sha256_hex
from .errors import DeviceAuthError
from .service import DeviceAuthService
from .storage import Storage


class ScenarioRunner:
    def __init__(self, spec_path: str, spec: dict):
        self.base_dir = os.path.dirname(os.path.abspath(spec_path))
        self.spec = spec
        self.seed = int(spec.get("seed", 20261117))
        self.start_time = int(spec.get("start_time", 1_000_000))
        self.results = []
        self.all_passed = True

    def _path(self, rel: str) -> str:
        return os.path.join(self.base_dir, rel)

    @staticmethod
    def _sha256_file(path: str) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as fp:
            for chunk in iter(lambda: fp.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    def run(self) -> dict:
        for idx, case in enumerate(self.spec["cases"]):
            self.results.append(self._run_case(case, idx))
        return {
            "seed": self.seed,
            "start_time": self.start_time,
            "total_cases": len(self.results),
            "passed_cases": sum(1 for c in self.results if c["passed"]),
            "passed": self.all_passed,
            "cases": self.results,
        }

    def _run_case(self, case: dict, case_idx: int) -> dict:
        name = case["name"]
        db_path = self._path(case["db"])
        log_path = self._path(case["log"])
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        for p in (db_path, db_path + "-wal", db_path + "-shm", log_path):
            if os.path.exists(p):
                os.remove(p)

        clock = ManualClock(self.start_time)
        # 代码流与令牌流独立：同一种子派生两个 Random，互不消耗对方状态
        rng = random.Random(self.seed + case_idx)
        token_rng = random.Random(self.seed + case_idx + 10_000_000)
        storage = Storage(db_path)
        storage.set_meta("now", clock.now())
        logger = SafeLogger(log_path)
        service = DeviceAuthService(
            storage, clock, CodeGenerator(rng, token_rng), logger)
        for account in case.get("accounts", []):
            storage.add_account(account, clock.now())

        variables = {}
        step_records = []
        failures = []
        passed = True

        def resolve(value):
            if isinstance(value, str) and value.startswith("$"):
                head, _, tail = value[1:].partition(".")
                obj = variables[head]
                if tail:
                    for part in tail.split("."):
                        obj = obj[part]
                return obj
            if isinstance(value, dict):
                return {k: resolve(v) for k, v in value.items()}
            if isinstance(value, list):
                return [resolve(v) for v in value]
            return value

        for step_idx, step in enumerate(case["steps"]):
            op = step["op"]
            record = {"index": step_idx, "op": op, "passed": True}
            try:
                if op == "advance":
                    clock.advance(int(step["seconds"]))
                    storage.set_meta("now", clock.now())
                    actual = {"now": clock.now()}
                elif op == "restart":
                    logger.close()
                    storage.close()
                    storage = Storage(db_path)
                    logger = SafeLogger(log_path)
                    # 重启不换 RNG 流：沿用已有 Random 实例，代码/令牌序列连续可重放
                    service = DeviceAuthService(
                        storage, clock, CodeGenerator(rng, token_rng), logger)
                    actual = {"restarted": True, "now": clock.now()}
                elif op == "hash_file":
                    actual = {"sha256": self._sha256_file(self._path(step["path"]))}
                elif op == "worker":
                    step["index"] = step_idx
                    actual = self._run_worker(step, resolve, case_idx)
                elif op == "thread_race":
                    actual = self._run_thread_race(service, step, resolve)
                elif op == "assert_log_no_secrets":
                    with open(log_path, "r", encoding="utf-8") as fp:
                        log_text = fp.read()
                    leaked = [s for s in resolve(step.get("secrets", []))
                              if isinstance(s, str) and s and s in log_text]
                    if leaked:
                        raise AssertionError(f"日志出现秘密内容: {leaked}")
                    actual = {"checked": True, "leaks": 0}
                elif op in ("register", "approve", "poll", "cancel"):
                    args = resolve(step.get("args", {}))
                    actual = getattr(service, op)(**args)
                else:
                    raise ValueError(f"未知操作: {op}")

                record["actual"] = actual
                if "save" in step:
                    variables[step["save"]] = actual
                if "expect" in step:
                    expected = resolve(step["expect"])
                    mismatch = self._check_expect(expected, actual)
                    if mismatch:
                        raise AssertionError("; ".join(mismatch))
            except DeviceAuthError as exc:
                actual = exc.to_dict()
                record["actual"] = actual
                if "save" in step:
                    variables[step["save"]] = actual
                expected = resolve(step["expect"]) if "expect" in step else None
                if not expected:
                    record["passed"] = False
                    failures.append(
                        f"step {step_idx} {op}: 未预期的错误 {actual}")
                else:
                    mismatch = self._check_expect(expected, actual)
                    if mismatch:
                        record["passed"] = False
                        failures.append(
                            f"step {step_idx} {op}: {'; '.join(mismatch)}")
                    # 预期内的错误且断言匹配：record.passed 保持 True
            except Exception as exc:  # noqa: BLE001 - 脚本失败需如实记录
                record["passed"] = False
                record["error"] = repr(exc)
                failures.append(f"step {step_idx} {op}: {exc!r}")
            step_records.append(record)

        passed = not failures
        logger.close()
        storage.close()
        self.all_passed = self.all_passed and passed
        return {
            "name": name, "passed": passed,
            "steps": step_records, "failures": failures,
            "db": os.path.relpath(db_path, self.base_dir),
            "log": os.path.relpath(log_path, self.base_dir),
        }

    @staticmethod
    def _check_expect(expected, actual) -> list[str]:
        """期望为实际值的子集（dict 逐键匹配，标量相等）。

        特殊字符串匹配器：
        - "__nonempty__"：实际值为非空；
        - "__one_of:a:b:c__"：实际值属于给定集合。
        """
        problems = []
        if not isinstance(expected, dict):
            if isinstance(expected, str) and expected == "__nonempty__":
                return [] if actual else ["期望非空值"]
            if isinstance(expected, str) and expected.startswith("__one_of:"):
                choices = expected[len("__one_of:"):-2].split(":")
                return [] if actual in choices else [
                    f"期望实际值属于 {choices}，实际 {actual!r}"]
            return [] if expected == actual else [f"期望 {expected!r}，实际 {actual!r}"]
        for key, want in expected.items():
            if not isinstance(actual, dict) or key not in actual:
                problems.append(f"缺少字段 {key}")
                continue
            got = actual[key]
            if isinstance(want, dict):
                problems.extend(f"{key}.{p}" for p in
                                ScenarioRunner._check_expect(want, got))
            elif isinstance(want, str) and want == "__nonempty__":
                if not got:
                    problems.append(f"字段 {key}: 期望非空，实际 {got!r}")
            elif isinstance(want, str) and want.startswith("__one_of:"):
                choices = want[len("__one_of:"):-2].split(":")
                if got not in choices:
                    problems.append(f"字段 {key}: 期望属于 {choices}，实际 {got!r}")
            elif got != want:
                problems.append(f"字段 {key}: 期望 {want!r}，实际 {got!r}")
        return problems

    def _run_worker(self, step: dict, resolve, case_idx: int) -> dict:
        """在独立 OS 进程中执行一次服务调用（两进程轮询验收场景）。"""
        import subprocess
        import sys

        args = resolve(step.get("args", {}))
        db_path = self._path(step["db"])
        log_path = self._path(step["log"])
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        bootstrap = (
            "import sys; sys.path.insert(0, r'%s'); "
            "from solution.worker import main; raise SystemExit(main())" % root
        )
        # -X utf8 保证隔离模式下子进程仍以 UTF-8 输出（-I 会忽略 PYTHONUTF8）
        cmd = [sys.executable, "-I", "-X", "utf8", "-c", bootstrap,
               "--db", db_path, "--log", log_path,
               "--action", step["action"],
               # 派生种子：用例序号 + 步骤序号，跨运行稳定可重放
               "--seed", str(self.seed + case_idx * 1000 + step.get("index", 0))]
        flag_map = {
            "client_id": "--client-id", "scope": "--scope", "ttl": "--ttl",
            "device_code": "--device-code", "user_code": "--user-code",
            "caller_id": "--caller-id", "account_id": "--account-id",
            "decision": "--decision", "request_id": "--request-id",
        }
        for key, flag in flag_map.items():
            if key in args and args[key] is not None:
                cmd.extend([flag, str(args[key])])
        proc = subprocess.run(cmd, capture_output=True, encoding="utf-8",
                              errors="replace", cwd=root)
        lines = [ln for ln in proc.stdout.strip().splitlines() if ln.strip()]
        payload = json.loads(lines[-1]) if lines else {"ok": False,
                                                       "error": {"error": "no_output"}}
        if proc.stderr.strip():
            payload["stderr"] = proc.stderr.strip()
        # 统一成与进程内调用一致的形状，便于 expect 断言；exit_code 两种形状都保留
        if payload.get("ok"):
            result = payload["result"]
            result["exit_code"] = proc.returncode
            return result
        return payload["error"] | {"exit_code": proc.returncode}

    def _run_thread_race(self, service, step: dict, resolve) -> dict:
        """两个线程在同一屏障放行后并发调用批准/取消，由 SQLite 裁决终态。

        每个线程使用独立 Storage 连接（同一数据库文件），与多进程竞争同构：
        BEGIN IMMEDIATE 写锁由 SQLite 串行化，败方随后读到胜方落库的终态。
        """
        calls = resolve(step["calls"])
        barrier = threading.Barrier(len(calls))
        outcomes = [None] * len(calls)
        db_path = service.storage.path
        # 竞争线程写各自的审计文件，避免多线程同时写同一文件句柄
        race_log = os.path.join(os.path.dirname(db_path),
                                os.path.basename(db_path) + ".race.log")

        def worker(idx, call):
            own_storage = Storage(db_path)
            own_logger = SafeLogger(race_log)
            own_service = DeviceAuthService(
                own_storage, service.clock, service.codes, own_logger)
            barrier.wait()
            try:
                outcomes[idx] = {"ok": True,
                                 "result": getattr(own_service, call["op"])(**call["args"])}
            except DeviceAuthError as exc:
                outcomes[idx] = {"ok": False, "error": exc.to_dict()}
            finally:
                own_logger.close()
                own_storage.close()

        threads = [threading.Thread(target=worker, args=(i, c))
                   for i, c in enumerate(calls)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # 用独立连接重读最终终态，避免跨线程复用主连接
        checker = Storage(db_path)
        try:
            row = checker.get_grant_by_user_hash(
                sha256_hex(normalize_user_code(calls[0]["args"]["user_code"]))
            )
            final_status = row["status"]
        finally:
            checker.close()
        return {
            "outcomes": outcomes,
            "final_status": final_status,
            "terminal": final_status in ("approved", "cancelled", "denied",
                                         "expired", "consumed"),
        }


def run_spec(input_path: str) -> dict:
    with open(input_path, "r", encoding="utf-8") as fp:
        spec = json.load(fp)
    return ScenarioRunner(input_path, spec).run()
