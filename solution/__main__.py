"""命令行入口：python -m solution --input cases.json --output result.json。"""

import argparse
import json
import os
import sys

from .runner import run_spec


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="本地设备授权服务脚本执行器（自定义协议，非完整 OAuth 兼容）"
    )
    parser.add_argument("--input", required=True, help="cases.json 路径")
    parser.add_argument("--output", required=True, help="结果 JSON 输出路径")
    args = parser.parse_args(argv)

    input_path = os.path.abspath(args.input)
    output_path = os.path.abspath(args.output)
    report = run_spec(input_path)
    report["input"] = input_path

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fp:
        json.dump(report, fp, ensure_ascii=False, indent=2, sort_keys=True)
        fp.write("\n")

    print(f"用例 {report['passed_cases']}/{report['total_cases']} 通过，"
          f"结果已写入 {output_path}")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
