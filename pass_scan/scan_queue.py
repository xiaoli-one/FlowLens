# 后台扫描队列。
#
# mitmproxy 的 response 回调里只负责快速入队。
# 真正主动发 payload 的工作由固定数量 worker 在后台执行。

import queue
import threading
import time

from pass_scan.runtime import WafBlockedTask, WafState
from pass_scan.terminal import green, purple, yellow


class ScanTask:
    def __init__(self, plugin, context):
        self.plugin = plugin
        self.context = context


class PluginQueueState:
    def __init__(self, plugin_name, worker_count, queue_size):
        self.plugin_name = plugin_name
        self.worker_count = worker_count
        self.tasks = queue.Queue(maxsize=queue_size)
        self.active_count = 0
        self.completed_count = 0
        self.scheduled_count = 0
        self.finding_count = 0
        self.last_status = None
        self.last_summary_completed = 0


class ScanQueue:
    def __init__(self, config):
        scan_config = config.get("scan", {})
        self.default_worker_count = int(scan_config.get("worker_count", 3))
        self.default_queue_size = int(scan_config.get("queue_size", 200))

        self.per_host_interval = float(scan_config.get("per_host_interval_seconds", 0.2))
        self.status_interval = float(scan_config.get("status_interval_seconds", 3))
        self.host_last_run = {}
        self.host_lock = threading.Lock()
        self.waf_state = WafState(
            scan_config.get("waf_backoff_seconds", 1800),
            scan_config.get("waf_max_block_attempts", 3),
        )

        self.plugin_states = {}
        self.plugin_lock = threading.Lock()
        self.count_lock = threading.Lock()

        if self.status_interval > 0:
            status_worker = threading.Thread(
                target=self.status_loop,
                name="pass-scan-status",
                daemon=True,
            )
            status_worker.start()

    def register_plugin(self, plugin):
        """为一个插件准备独立队列和 worker。"""
        return self.ensure_plugin_state(plugin.name, getattr(plugin, "config", {}))

    def ensure_plugin_state(self, plugin_name, plugin_config=None):
        with self.plugin_lock:
            state = self.plugin_states.get(plugin_name)
            if state:
                return state

            plugin_config = plugin_config or {}
            worker_count = int(plugin_config.get("worker_count", self.default_worker_count))
            queue_size = int(plugin_config.get("queue_size", self.default_queue_size))
            state = PluginQueueState(
                plugin_name,
                max(1, worker_count),
                max(1, queue_size),
            )
            self.plugin_states[plugin_name] = state

            for index in range(state.worker_count):
                worker = threading.Thread(
                    target=self.worker_loop,
                    args=(state,),
                    name=f"pass-scan-{plugin_name}-worker-{index + 1}",
                    daemon=True,
                )
                worker.start()

            return state

    def enqueue(self, plugin, context, label=None):
        """提交扫描任务。队列满时直接丢弃，保护代理主流程。"""
        state = self.register_plugin(plugin)
        try:
            if state.tasks.full():
                raise queue.Full
            if label:
                color = purple if plugin.name == "logic_agent" else yellow
                print(
                    color(
                        f"[入队] {plugin.name} 队列 -> {label} "
                        f"(队列剩余: {state.tasks.qsize() + 1})"
                    ),
                    flush=True,
                )
            state.tasks.put_nowait(ScanTask(plugin, context))
            with self.count_lock:
                state.scheduled_count += 1
            return True
        except queue.Full:
            print(
                yellow(f"[状态] {plugin.name} 队列已满，丢弃任务: {context.url}"),
                flush=True,
            )
            return False

    def waiting_count(self, plugin_name):
        state = self.ensure_plugin_state(plugin_name)
        return state.tasks.qsize()

    def record_finding(self, plugin_name=None):
        """记录当前运行期间发现的漏洞数量。"""
        plugin_name = plugin_name or "unknown"
        state = self.ensure_plugin_state(plugin_name)
        with self.count_lock:
            state.finding_count += 1

    def current_finding_count(self, plugin_name=None):
        """返回当前运行期间发现的漏洞数量。"""
        with self.plugin_lock:
            states = list(self.plugin_states.values())

        with self.count_lock:
            if plugin_name:
                for state in states:
                    if state.plugin_name == plugin_name:
                        return state.finding_count
                return 0
            return sum(state.finding_count for state in states)

    def worker_loop(self, state):
        while True:
            task = state.tasks.get()
            try:
                with self.count_lock:
                    state.active_count += 1
                self.wait_for_host_slot(task.context.host)
                task.plugin.check(task.context)
            except WafBlockedTask:
                pass
            except Exception as error:
                print(
                    yellow(f"[状态] 扫描任务异常: {task.plugin.name}: {error}"),
                    flush=True,
                )
            finally:
                with self.count_lock:
                    state.active_count -= 1
                    state.completed_count += 1
                state.tasks.task_done()

    def wait_for_host_slot(self, host):
        """同一个 host 的任务之间留一点间隔，避免瞬间打太猛。"""
        self.waf_state.wait_if_needed(host)

        with self.host_lock:
            now = time.time()
            last_run = self.host_last_run.get(host, 0)
            wait_seconds = self.per_host_interval - (now - last_run)
            if wait_seconds > 0:
                time.sleep(wait_seconds)
            self.host_last_run[host] = time.time()

    def status_loop(self):
        """定时显示每类漏洞自己的队列状态。"""

        while True:
            time.sleep(self.status_interval)

            with self.plugin_lock:
                states = list(self.plugin_states.values())

            for state in states:
                self.print_plugin_status(state)

    def finding_label(self, plugin_name):
        """不同插件的“发现数”叫法不同：指纹插件发现的是指纹，不是漏洞。"""
        if plugin_name == "fingerprint":
            return "已发现指纹"
        if plugin_name == "logic_agent":
            return "已发现逻辑漏洞"
        return "已发现漏洞"

    def print_plugin_status(self, state):
        with self.count_lock:
            active = state.active_count
            completed = state.completed_count
            scheduled = state.scheduled_count
            finding_count = state.finding_count

        waiting = state.tasks.qsize()
        status = (waiting, active, completed, scheduled, finding_count)
        label = self.finding_label(state.plugin_name)

        # 从忙碌回到空闲时，按插件类型输出一次总计；持续空闲时不刷屏。
        if waiting == 0 and active == 0:
            if completed > state.last_summary_completed:
                print(
                    green(
                        f"[完成] {state.plugin_name} 检测完成 | "
                        f"总入队: {scheduled} | "
                        f"总完成: {completed} | "
                        f"{label}: {finding_count}"
                    ),
                    flush=True,
                )
                state.last_summary_completed = completed
            state.last_status = status
            return

        # 运行中状态没变化时不重复输出。
        if status == state.last_status:
            return

        state.last_status = status
        color = purple if state.plugin_name == "logic_agent" else yellow
        print(
            color(
                f"[状态] {state.plugin_name} | "
                f"队列剩余: {waiting} | "
                f"正在检测: {active} | "
                f"已完成: {completed} | "
                f"已入队: {scheduled} | "
                f"{label}: {finding_count}"
            ),
            flush=True,
        )
