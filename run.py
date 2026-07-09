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


def main():
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
    parser.add_argument(
        "--sqli",
        dest="sqli",
        action="store_true",
        help="只做 SQL 注入检测",
    )
    parser.add_argument(
        "--fp",
        dest="fingerprint",
        action="store_true",
        help="只做指纹识别",
    )
    parser.add_argument(
        "--xss",
        dest="xss",
        action="store_true",
        help="只做 XSS 检测",
    )
    parser.add_argument(
        "--rce",
        dest="rce",
        action="store_true",
        help="只做命令注入检测",
    )
    parser.add_argument(
        "--lfi",
        dest="lfi",
        action="store_true",
        help="只做目录遍历/任意文件读取检测",
    )
    parser.add_argument(
        "--ssrf",
        dest="ssrf",
        action="store_true",
        help="只做 SSRF 检测",
    )
    parser.add_argument(
        "--xxe",
        dest="xxe",
        action="store_true",
        help="只做 XXE 检测",
    )
    parser.add_argument(
        "--ssti",
        dest="ssti",
        action="store_true",
        help="只做 SSTI 检测",
    )
    parser.add_argument(
        "--redir",
        dest="redir",
        action="store_true",
        help="只做开放重定向/CRLF 响应头注入检测",
    )
    parser.add_argument(
        "--sensitive",
        dest="sensitive_info",
        action="store_true",
        help="只做敏感信息泄漏检测",
    )
    parser.add_argument(
        "--oss",
        dest="object_storage",
        action="store_true",
        help="只做 OSS/对象存储桶检测",
    )
    parser.add_argument(
        "--upload",
        dest="file_upload",
        action="store_true",
        help="只做文件上传漏洞检测",
    )
    parser.add_argument(
        "--jwt",
        dest="jwt",
        action="store_true",
        help="只做 JWT 漏洞检测",
    )
    parser.add_argument(
        "--logic",
        dest="logic_agent",
        action="store_true",
        help="启用 Agent 逻辑漏洞检测（默认关闭）",
    )
    parser.add_argument(
        "--only-logic",
        dest="only_logic_agent",
        action="store_true",
        help="只启用 Agent 逻辑漏洞检测，不运行其他检测插件",
    )
    parser.add_argument(
        "--verify",
        dest="verify",
        action="store_true",
        help="启用 Agent 主动漏洞验证与非破坏性利用链生成（默认关闭）",
    )
    args = parser.parse_args()

    addon_path = os.path.join(os.path.dirname(__file__), "pass_scan", "mitm_addon.py")
    log_dir = os.path.dirname(args.log_file)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)

    # 选择启用哪些检测插件。
    # 不指定任何检测参数 -> 全做（默认）。
    # 指定一个或多个 -> 只做指定的。
    selected_plugins = []
    if args.sqli:
        selected_plugins.append("sql_injection")
    if args.fingerprint:
        selected_plugins.append("fingerprint")
    if args.xss:
        selected_plugins.append("xss")
    if args.rce:
        selected_plugins.append("command_injection")
    if args.lfi:
        selected_plugins.append("path_traversal")
    if args.ssrf:
        selected_plugins.append("ssrf")
    if args.xxe:
        selected_plugins.append("xxe")
    if args.ssti:
        selected_plugins.append("ssti")
    if args.redir:
        selected_plugins.append("redir")
    if args.sensitive_info:
        selected_plugins.append("sensitive_info")
    if args.object_storage:
        selected_plugins.append("object_storage")
    if args.file_upload:
        selected_plugins.append("file_upload")
    if args.jwt:
        selected_plugins.append("jwt")
    if args.only_logic_agent:
        selected_plugins = ["logic_agent"]

    env = os.environ.copy()
    env["PASS_SCAN_LOG_FILE"] = args.log_file
    env["PASS_SCAN_REPORT_FILE"] = args.report_file
    if args.logic_agent and not args.only_logic_agent:
        env["PASS_SCAN_ENABLE_LOGIC"] = "1"
    if args.verify:
        env["PASS_SCAN_VERIFY"] = "1"
    if args.full_payload_scan:
        env["PASS_SCAN_FULL_PAYLOAD_SCAN"] = "1"
    if selected_plugins:
        env["PASS_SCAN_PLUGINS"] = ",".join(selected_plugins)
        label_plugins = list(selected_plugins)
        if args.logic_agent and not args.only_logic_agent:
            label_plugins.append("logic_agent")
        enabled_label = " + ".join(label_plugins)
    else:
        enabled_label = "全部 + logic_agent" if args.logic_agent else "全部"

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
