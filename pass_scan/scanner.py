import os

from pass_scan.config import load_config
from pass_scan.command_injection import CommandInjectionScanner
from pass_scan.dedup import Deduper
from pass_scan.file_upload import FileUploadScanner
from pass_scan.fingerprint import FingerprintScanner
from pass_scan.filters import host_from_flow, is_ignored_host
from pass_scan.jwt import JWTScanner
from pass_scan.object_storage import ObjectStorageScanner
from pass_scan.path_traversal import PathTraversalScanner
from pass_scan.redir import RedirScanner
from pass_scan.scan_context import build_scan_context
from pass_scan.scan_queue import ScanQueue
from pass_scan.sensitive_info import SensitiveInfoScanner
from pass_scan.sql_injection import SQLInjectionScanner
from pass_scan.ssrf import SSRFScanner
from pass_scan.ssti import SSTIScanner
from pass_scan.terminal import yellow
from pass_scan.xss import XSSScanner
from pass_scan.xxe import XXEScanner
from agent_pass_scan import LogicAgentScanner
from vuln_verify import VerificationQueue


class PassiveScanner:
    """漏洞扫描总调度器。

    这里的设计更接近 xray 这类被动扫描器：

    1. mitm_addon.py 把流量交给 PassiveScanner。
    2. PassiveScanner 先生成 ScanContext，统一解析请求和参数。
    3. 全局过滤静态资源、无意义响应。
    4. 每个插件先用 interested(context) 判断是否关心这条流量。
    5. 通过 dedup 做任务去重。
    6. 把任务放入 ScanQueue，由后台 worker 限速执行主动扫描。

    后面新增 XSS、SSRF、RCE 插件时，也按这个接口：

    - plugin.name
    - plugin.interested(context)
    - plugin.dedup_key(context)
    - plugin.check(context)
    """

    def __init__(self):
        self.config = load_config()
        scan_config = self.config.get("scan", {})
        report_config = self.config.get("report", {})
        plugin_config = self.config.get("plugins", {})
        self.ignored_hosts = scan_config.get("ignored_hosts", [])
        ttl = int(scan_config.get("dedup_ttl_seconds", 1800))
        self.deduper = Deduper(ttl)
        self.queue = ScanQueue(self.config)
        self.vuln_file = os.environ.get("PASS_SCAN_VULN_FILE") or os.path.join("logs", "vulns.jsonl")
        self.report_file = os.environ.get("PASS_SCAN_REPORT_FILE") or report_config.get("html_file")
        fingerprint_config = plugin_config.get("fingerprint", {})
        self.fingerprint_file = (
            os.environ.get("PASS_SCAN_FP_FILE")
            or fingerprint_config.get("output_file", os.path.join("logs", "fingerprints.jsonl"))
        )
        self.verification_queue = VerificationQueue(
            self.config,
            self.vuln_file,
            self.report_file,
            self.fingerprint_file,
        )
        self.plugins = self.load_plugins()

        for plugin in self.plugins:
            self.queue.register_plugin(plugin)
            plugin.waf_state = self.queue.waf_state
            plugin.on_finding = (
                lambda finding=None, plugin_name=plugin.name: self.handle_finding(
                    plugin_name,
                    finding,
                )
            )

    def handle_finding(self, plugin_name, finding=None):
        """插件发现结果后的统一回调：计数，并按需提交给主动验证队列。"""
        self.queue.record_finding(plugin_name)
        if finding:
            verify_finding = dict(finding)
            for key in list(verify_finding):
                if str(key).startswith("_pass_scan_"):
                    verify_finding.pop(key, None)
            self.verification_queue.enqueue(plugin_name, verify_finding)

    def load_plugins(self):
        """根据配置和命令行选择启用插件。

        插件启用优先级：
        1. 命令行（环境变量 PASS_SCAN_PLUGINS，由 run.py 的 --sqli/--fp 等参数设置）：
           只要设置了这个变量，就**只**启用其中列出的插件，覆盖 config.yaml。
           不设置（默认运行）则按 config.yaml 的 enabled 开关，两个插件都做。
        2. config.yaml 的 plugins.<name>.enabled。
        """
        plugin_config = self.config.get("plugins", {})
        report_config = self.config.get("report", {})
        scan_config = self.config.get("scan", {})
        plugins = []

        # 命令行指定的插件白名单（逗号分隔）。为空表示不限制，按配置走。
        selected = os.environ.get("PASS_SCAN_PLUGINS", "").strip()
        selected_set = {
            name.strip() for name in selected.split(",") if name.strip()
        }

        def plugin_enabled(name):
            if selected_set:
                # 命令行明确选择了插件：只做被选中的，忽略 config 的 enabled。
                return name in selected_set
            # 默认：按 config.yaml 开关，缺省都开。
            return plugin_config.get(name, {}).get("enabled", True)

        if plugin_enabled("sql_injection"):
            sql_config = dict(plugin_config.get("sql_injection", {}))
            sql_config["full_payload_scan"] = bool(
                scan_config.get("full_payload_scan", False)
            )
            plugins.append(
                SQLInjectionScanner(
                    config=sql_config,
                    report_file=os.environ.get("PASS_SCAN_REPORT_FILE")
                    or report_config.get("html_file"),
                )
            )

        if plugin_enabled("command_injection"):
            cmdi_config = dict(plugin_config.get("command_injection", {}))
            cmdi_config["full_payload_scan"] = bool(
                scan_config.get("full_payload_scan", False)
            )
            plugins.append(
                CommandInjectionScanner(
                    config=cmdi_config,
                    report_file=os.environ.get("PASS_SCAN_REPORT_FILE")
                    or report_config.get("html_file"),
                    vuln_file=os.environ.get("PASS_SCAN_VULN_FILE")
                    or os.path.join("logs", "vulns.jsonl"),
                )
            )

        if plugin_enabled("xss"):
            xss_config = dict(plugin_config.get("xss", {}))
            xss_config["full_payload_scan"] = bool(
                scan_config.get("full_payload_scan", False)
            )
            plugins.append(
                XSSScanner(
                    config=xss_config,
                    report_file=os.environ.get("PASS_SCAN_REPORT_FILE")
                    or report_config.get("html_file"),
                    vuln_file=os.environ.get("PASS_SCAN_VULN_FILE")
                    or os.path.join("logs", "vulns.jsonl"),
                )
            )

        if plugin_enabled("path_traversal"):
            pt_config = dict(plugin_config.get("path_traversal", {}))
            pt_config["full_payload_scan"] = bool(
                scan_config.get("full_payload_scan", False)
            )
            plugins.append(
                PathTraversalScanner(
                    config=pt_config,
                    report_file=os.environ.get("PASS_SCAN_REPORT_FILE")
                    or report_config.get("html_file"),
                    vuln_file=os.environ.get("PASS_SCAN_VULN_FILE")
                    or os.path.join("logs", "vulns.jsonl"),
                )
            )

        if plugin_enabled("ssrf"):
            ssrf_config = dict(plugin_config.get("ssrf", {}))
            ssrf_config["full_payload_scan"] = bool(
                scan_config.get("full_payload_scan", False)
            )
            plugins.append(
                SSRFScanner(
                    config=ssrf_config,
                    report_file=os.environ.get("PASS_SCAN_REPORT_FILE")
                    or report_config.get("html_file"),
                    vuln_file=os.environ.get("PASS_SCAN_VULN_FILE")
                    or os.path.join("logs", "vulns.jsonl"),
                )
            )

        if plugin_enabled("xxe"):
            xxe_config = dict(plugin_config.get("xxe", {}))
            xxe_config["full_payload_scan"] = bool(
                scan_config.get("full_payload_scan", False)
            )
            plugins.append(
                XXEScanner(
                    config=xxe_config,
                    report_file=os.environ.get("PASS_SCAN_REPORT_FILE")
                    or report_config.get("html_file"),
                    vuln_file=os.environ.get("PASS_SCAN_VULN_FILE")
                    or os.path.join("logs", "vulns.jsonl"),
                )
            )

        if plugin_enabled("ssti"):
            ssti_config = dict(plugin_config.get("ssti", {}))
            ssti_config["full_payload_scan"] = bool(
                scan_config.get("full_payload_scan", False)
            )
            plugins.append(
                SSTIScanner(
                    config=ssti_config,
                    report_file=os.environ.get("PASS_SCAN_REPORT_FILE")
                    or report_config.get("html_file"),
                    vuln_file=os.environ.get("PASS_SCAN_VULN_FILE")
                    or os.path.join("logs", "vulns.jsonl"),
                )
            )

        if plugin_enabled("redir"):
            redir_config = dict(plugin_config.get("redir", {}))
            redir_config["full_payload_scan"] = bool(
                scan_config.get("full_payload_scan", False)
            )
            plugins.append(
                RedirScanner(
                    config=redir_config,
                    report_file=os.environ.get("PASS_SCAN_REPORT_FILE")
                    or report_config.get("html_file"),
                    vuln_file=os.environ.get("PASS_SCAN_VULN_FILE")
                    or os.path.join("logs", "vulns.jsonl"),
                )
            )

        if plugin_enabled("sensitive_info"):
            si_config = dict(plugin_config.get("sensitive_info", {}))
            plugins.append(
                SensitiveInfoScanner(
                    config=si_config,
                    report_file=os.environ.get("PASS_SCAN_REPORT_FILE")
                    or report_config.get("html_file"),
                    vuln_file=os.environ.get("PASS_SCAN_VULN_FILE")
                    or os.path.join("logs", "vulns.jsonl"),
                )
            )

        if plugin_enabled("object_storage"):
            os_config = dict(plugin_config.get("object_storage", {}))
            plugins.append(
                ObjectStorageScanner(
                    config=os_config,
                    report_file=os.environ.get("PASS_SCAN_REPORT_FILE")
                    or report_config.get("html_file"),
                    vuln_file=os.environ.get("PASS_SCAN_VULN_FILE")
                    or os.path.join("logs", "vulns.jsonl"),
                )
            )

        if plugin_enabled("file_upload"):
            upload_config = dict(plugin_config.get("file_upload", {}))
            upload_config["full_payload_scan"] = bool(
                scan_config.get("full_payload_scan", False)
            )
            plugins.append(
                FileUploadScanner(
                    config=upload_config,
                    report_file=os.environ.get("PASS_SCAN_REPORT_FILE")
                    or report_config.get("html_file"),
                    vuln_file=os.environ.get("PASS_SCAN_VULN_FILE")
                    or os.path.join("logs", "vulns.jsonl"),
                )
            )

        if plugin_enabled("jwt"):
            jwt_config = dict(plugin_config.get("jwt", {}))
            plugins.append(
                JWTScanner(
                    config=jwt_config,
                    report_file=os.environ.get("PASS_SCAN_REPORT_FILE")
                    or report_config.get("html_file"),
                    vuln_file=os.environ.get("PASS_SCAN_VULN_FILE")
                    or os.path.join("logs", "vulns.jsonl"),
                )
            )

        logic_requested = (
            "logic_agent" in selected_set
            or os.environ.get("PASS_SCAN_ENABLE_LOGIC", "").strip().lower()
            in ("1", "true", "yes", "on")
        )
        if logic_requested:
            logic_config = dict(plugin_config.get("logic_agent", {}))
            plugins.append(
                LogicAgentScanner(
                    config=logic_config,
                    report_file=os.environ.get("PASS_SCAN_REPORT_FILE")
                    or report_config.get("html_file"),
                    vuln_file=os.environ.get("PASS_SCAN_VULN_FILE")
                    or os.path.join("logs", "vulns.jsonl"),
                    fingerprint_file=self.fingerprint_file,
                )
            )

        if plugin_enabled("fingerprint"):
            fp_config = dict(plugin_config.get("fingerprint", {}))
            plugins.append(
                FingerprintScanner(
                    config=fp_config,
                    output_file=os.environ.get("PASS_SCAN_FP_FILE")
                    or fp_config.get("output_file", "logs/fingerprints.jsonl"),
                    unknown_file=fp_config.get(
                        "unknown_file", "logs/fingerprints_unknown.jsonl"
                    ),
                    report_file=os.environ.get("PASS_SCAN_REPORT_FILE")
                    or report_config.get("html_file"),
                    vuln_file=os.environ.get("PASS_SCAN_VULN_FILE")
                    or os.path.join("logs", "vulns.jsonl"),
                )
            )

        return plugins

    def check(self, record, flow=None):
        """接收一条流量并提交扫描任务。

        这个函数只做轻量调度，不直接发送 payload。
        返回值是本次成功入队的插件名列表。
        """
        if flow is None:
            return []

        if self.should_ignore_flow(flow):
            return []

        context = build_scan_context(record, flow, self.config)

        scheduled = []
        for plugin in self.plugins:
            if hasattr(plugin, "observe"):
                try:
                    observed_tasks = plugin.observe(context)
                except Exception as error:
                    print(
                        yellow(f"[状态] 观察任务异常: {plugin.name}: {error}"),
                        flush=True,
                    )
                    observed_tasks = []

                for task_context in observed_tasks:
                    dedup_key = (plugin.name, plugin.dedup_key(task_context))
                    if self.deduper.seen_or_add(dedup_key):
                        continue

                    task_label = f"{task_context.method} {task_context.url}"
                    if hasattr(plugin, "task_label"):
                        try:
                            task_label = plugin.task_label(task_context)
                        except Exception:
                            pass

                    if not self.should_print_enqueue_log(plugin, task_context):
                        task_label = None

                    if self.queue.enqueue(plugin, task_context, label=task_label):
                        scheduled.append(plugin.name)

                if getattr(plugin, "observer_only", False):
                    continue

            if not plugin.interested(context):
                continue

            dedup_key = (plugin.name, plugin.dedup_key(context))
            if self.deduper.seen_or_add(dedup_key):
                continue

            task_label = f"{context.method} {context.url}"
            if hasattr(plugin, "task_label"):
                try:
                    task_label = plugin.task_label(context)
                except Exception:
                    pass

            if not self.should_print_enqueue_log(plugin, context):
                task_label = None

            if self.queue.enqueue(plugin, context, label=task_label):
                scheduled.append(plugin.name)

        return scheduled

    def should_print_enqueue_log(self, plugin, task_context):
        custom_should_log = getattr(plugin, "should_log_enqueue", None)
        if custom_should_log:
            try:
                return bool(custom_should_log(task_context))
            except Exception:
                return True

        if not hasattr(plugin, "enqueue_log_key"):
            return True
        try:
            log_key = plugin.enqueue_log_key(task_context)
        except Exception:
            return True
        return not self.deduper.seen_or_add(
            ("__enqueue_log__", plugin.name, log_key)
        )

    def should_ignore_flow(self, flow):
        """判断这条流量是否属于浏览器/系统后台流量。"""
        return is_ignored_host(host_from_flow(flow), self.ignored_hosts)
