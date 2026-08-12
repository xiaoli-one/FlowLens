import argparse
import os
import subprocess
import sys
from shutil import which

from pass_scan.terminal import bold, cyan, green, yellow


APP_NAME = "FlowLens"
APP_VERSION = "0.1.0"
APP_TAGLINE = "Passive traffic scanner | flow-triggered, proof-driven"

FLOWLENS_BANNER = r"""
    ________              __
   / ____/ /___ _      __/ /   ___  ____  _____
  / /_  / / __ \ | /| / / /   / _ \/ __ \/ ___/
 / __/ / / /_/ / |/ |/ / /___/  __/ / / (__  )
/_/   /_/\____/|__/|__/_____/\___/_/ /_/____/
"""


# 命令行名称保持简短，内部始终使用扫描器的插件名称。
SCAN_PLUGIN_ALIASES = {
    "sqli": "sql_injection",
    "sql_injection": "sql_injection",
    "fp": "fingerprint",
    "fingerprint": "fingerprint",
    "xss": "xss",
    "rce": "command_injection",
    "command_injection": "command_injection",
    "lfi": "path_traversal",
    "path_traversal": "path_traversal",
    "ssrf": "ssrf",
    "xxe": "xxe",
    "ssti": "ssti",
    "redir": "redir",
    "sensitive": "sensitive_info",
    "sensitive_info": "sensitive_info",
    "oss": "object_storage",
    "object_storage": "object_storage",
    "upload": "file_upload",
    "file_upload": "file_upload",
    "jwt": "jwt",
    "logic": "logic_agent",
    "logic_agent": "logic_agent",
}

# --default 覆盖全部检测能力，包括逻辑漏洞 Agent。
DEFAULT_PLUGINS = (
    "sql_injection",
    "fingerprint",
    "xss",
    "command_injection",
    "path_traversal",
    "ssrf",
    "xxe",
    "ssti",
    "redir",
    "sensitive_info",
    "object_storage",
    "file_upload",
    "jwt",
    "logic_agent",
)


def split_scan_names(values):
    """Split comma-separated CLI values while also accepting space-separated names."""
    names = []
    for value in values or []:
        names.extend(
            name.strip().lower()
            for name in value.replace("，", ",").split(",")
            if name.strip()
        )
    return names


def resolve_plugins(parser, scan_values, exclude_values, use_default):
    """Resolve CLI scan names into a stable, de-duplicated plugin list."""
    requested_names = split_scan_names(None if use_default else scan_values)
    excluded_names = split_scan_names(exclude_values)
    invalid_names = sorted(
        {
            name
            for name in requested_names + excluded_names
            if name not in SCAN_PLUGIN_ALIASES
        }
    )
    if invalid_names:
        parser.error(
            "未知检测名称: "
            + ", ".join(invalid_names)
            + "。可用名称: "
            + ", ".join(SCAN_PLUGIN_ALIASES)
        )

    requested_plugins = DEFAULT_PLUGINS if use_default else (
        SCAN_PLUGIN_ALIASES[name] for name in requested_names
    )
    excluded_plugins = {
        SCAN_PLUGIN_ALIASES[name] for name in excluded_names
    }
    selected_plugins = []
    for plugin in requested_plugins:
        if plugin not in excluded_plugins and plugin not in selected_plugins:
            selected_plugins.append(plugin)

    if not selected_plugins:
        parser.error("--exclude 排除了全部已选检测，至少保留一个检测名称。")

    return selected_plugins


def find_mitmdump():
    # 优先使用当前 Python 环境里的 mitmdump。
    # 例如你用 /Users/agiuser/py3/bin/python run.py 启动时，
    # 这里会优先找到 /Users/agiuser/py3/bin/mitmdump。
    python_bin_dir = os.path.dirname(sys.executable)
    local_mitmdump = os.path.join(python_bin_dir, "mitmdump")
    if os.path.exists(local_mitmdump):
        return local_mitmdump

    return which("mitmdump") or "mitmdump"


def print_banner(args, enabled_label):
    print(cyan(FLOWLENS_BANNER), flush=True)
    print(
        bold(f"{APP_NAME} v{APP_VERSION}") + " - " + APP_TAGLINE,
        flush=True,
    )
    print(
        green(
            f"[FlowLens] Listen: {args.host}:{args.port} | "
            f"Log: {args.log_file} | "
            f"Report: {args.report_file}"
        ),
        flush=True,
    )
    print(
        green(
            f"[FlowLens] Plugins: {enabled_label} | "
            f"Full payload scan: {'on' if args.full_payload_scan else 'config'} | "
            f"Verify: {'on' if args.verify else 'off'}"
        ),
        flush=True,
    )
    print("", flush=True)


def build_parser():
    parser = argparse.ArgumentParser(
        prog=APP_NAME.lower(),
        description=f"{APP_NAME} - {APP_TAGLINE}",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Proxy listen host")
    parser.add_argument("--port", default="8081", help="Proxy listen port")
    parser.add_argument(
        "--log-file",
        default=os.path.join("logs", "flows.jsonl"),
        help="Where captured traffic will be written",
    )
    parser.add_argument(
        "--report-file",
        default="report.html",
        help="Where vulnerability HTML report will be written",
    )
    parser.add_argument(
        "--full-payload-scan",
        action="store_true",
        help="Use full tamper scanning and enable header injection checks",
    )
    parser.add_argument(
        "--verify-upstream-cert",
        dest="verify_upstream_cert",
        action="store_true",
        help="校验目标站 TLS 证书（默认忽略自签名/无效证书，避免自签名目标返回 502）",
    )
    scan_group = parser.add_mutually_exclusive_group(required=True)
    scan_group.add_argument(
        "--default",
        action="store_true",
        help="启用全部漏洞检测，包括逻辑漏洞 Agent",
    )
    scan_group.add_argument(
        "--scan",
        nargs="+",
        metavar="VULN",
        help=(
            "只启用指定检测，支持逗号或空格分隔；例如: "
            "--scan sqli,xss,rce 或 --scan sqli xss rce"
        ),
    )
    parser.add_argument(
        "--exclude",
        nargs="+",
        metavar="VULN",
        default=[],
        help="排除指定检测，支持逗号或空格分隔；与 --default 或 --scan 一起使用",
    )
    parser.add_argument(
        "--verify",
        dest="verify",
        action="store_true",
        help="启用 Agent 主动漏洞验证与非破坏性利用链生成（默认关闭）",
    )
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    addon_path = os.path.join(os.path.dirname(__file__), "pass_scan", "mitm_addon.py")
    log_dir = os.path.dirname(args.log_file)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)

    selected_plugins = resolve_plugins(
        parser,
        args.scan,
        args.exclude,
        args.default,
    )

    env = os.environ.copy()
    env["PASS_SCAN_LOG_FILE"] = args.log_file
    env["PASS_SCAN_REPORT_FILE"] = args.report_file
    if args.verify:
        env["PASS_SCAN_VERIFY"] = "1"
    if args.full_payload_scan:
        env["PASS_SCAN_FULL_PAYLOAD_SCAN"] = "1"
    env["PASS_SCAN_PLUGINS"] = ",".join(selected_plugins)
    enabled_label = " + ".join(selected_plugins)

    command = [
        find_mitmdump(),
        "--quiet",
        "--flow-detail",
        "0",
        "--listen-host",
        args.host,
        "--listen-port",
        str(args.port),
        "--mode",
        "regular",
        # 忽略上游（目标站）自签名/无效证书。否则目标用自签名证书时，mitmproxy 会校验失败并对
        # 浏览器返回 502 Bad Gateway（Certificate verify failed）。扫描器自身的主动探测也一律
        # 忽略证书（_create_unverified_context），这里和它保持一致。用 --verify-upstream-cert 可关闭。
    ]
    if not args.verify_upstream_cert:
        command.append("--ssl-insecure")
    command += [
        "-s",
        addon_path,
    ]

    print_banner(args, enabled_label)
    print(
        yellow(
            f"[FlowLens][状态] 代理监听: {args.host}:{args.port} | "
            f"流量日志: {args.log_file} | "
            f"报告: {args.report_file} | "
            f"启用检测: {enabled_label} | "
            f"全量扫描: {'开启' if args.full_payload_scan else '按配置'} | "
            f"主动验证: {'开启' if args.verify else '关闭'} | "
            "已发现漏洞: 0"
        ),
        flush=True,
    )

    try:
        subprocess.run(command, env=env, check=False)
    except KeyboardInterrupt:
        print(yellow("\n[FlowLens][状态] 已停止"), flush=True)
    except FileNotFoundError:
        print(yellow("[FlowLens][状态] mitmdump 未找到，请先安装依赖: python3 -m pip install -r requirements.txt"))
        sys.exit(1)


if __name__ == "__main__":
    main()
