# XXE OOB（带外/Out-of-Band）关联管理器。
#
# 盲打 XXE（无回显）只能靠带外通道确认：在 XML 里塞一个指向唯一子域的外部实体 / 外部 DTD
# （<!DOCTYPE r SYSTEM "http://<host>/x.dtd">、<!ENTITY % p SYSTEM "http://<host>/"> 等），
# 解析器一旦去解析它（哪怕只做 DNS 解析）就会回连我们控制的 OOB 服务器；轮询到带对应 token
# 的交互，就能关联回具体注入点，判定 XXE 成立。OOB 命中即高置信（服务端解析器真的去外连了），
# 回连来源 IP 是目标服务器而非我们，天然证明是“服务端解析”发起，且完全不依赖响应是否回显。
#
# 这里对接 projectdiscovery 的免费公共 interactsh 服务（oast.pro 等），协议实现在
# tools/interactsh_client.py（各插件共享的底层协议客户端）。本模块只负责：注册会话、给注入点
# 发放唯一域名、后台轮询、把回连关联回注入点并回调上层生成漏洞结果。与 SSRF / 命令注入插件
# 各自持有独立会话，互不影响。
#
# 前提：目标必须能对外发起请求（DNS/HTTP 出站）。内网无出网环境 OOB 会静默，此时由“带内文件
# 读取”检测兜底（file:///etc/passwd 并在响应里找 signature），两者互补。

import threading
import time

from pass_scan.terminal import yellow


class OOBManager:
    """OOB 关联管理器。启用后对接 interactsh 公共服务，后台轮询回连。"""

    def __init__(self, config=None, on_interaction=None):
        self.config = config or {}
        self.on_interaction = on_interaction
        self.enabled = False

        self.client = None
        self.lock = threading.Lock()
        # token -> 注入点信息 dict
        self.pending = {}
        # 已上报的 (token, protocol)，避免同一回连重复报。
        self.reported = set()

        self.poll_interval = float(self.config.get("poll_interval", 15))
        self.timeout = int(self.config.get("timeout", 15))
        # 服务器：可配单个 server，或用默认公共服务器列表逐个尝试。
        configured = self.config.get("server")
        if configured:
            self.servers = [configured]
        else:
            self.servers = None  # 用客户端默认列表
        self.auth_token = self.config.get("token", "")

    def start(self):
        """按配置启动 OOB 会话。注册可能较慢（逐个尝试公共服务器），放到后台线程做，
        不阻塞代理启动。注册成功前 new_domain() 返回空，扫描器自动跳过带外分支。"""
        if not self.config.get("enabled", False):
            return False
        worker = threading.Thread(target=self._bootstrap, name="pass-scan-xxe-oob-init", daemon=True)
        worker.start()
        return True

    def _bootstrap(self):
        """后台：逐个尝试服务器注册；成功后进入轮询循环。"""
        # 延迟导入，避免未启用 OOB 时也依赖 cryptography / tools 包。
        try:
            from tools.interactsh_client import DEFAULT_SERVERS, InteractshClient
        except Exception as error:
            print(yellow(f"[XXE-OOB] 加载 interactsh 客户端失败，OOB 不可用: {error}"), flush=True)
            return

        servers = self.servers or list(DEFAULT_SERVERS)
        for server in servers:
            client = InteractshClient(server=server, token=self.auth_token, timeout=self.timeout)
            if client.register():
                self.client = client
                self.enabled = True
                print(yellow(f"[XXE-OOB] 已连接 interactsh 服务: {server}"), flush=True)
                self._poll_loop()
                return

        print(
            yellow("[XXE-OOB] 所有 interactsh 服务器注册失败，OOB 不可用（将只用带内文件读取检测）"),
            flush=True,
        )

    def new_domain(self, info=None):
        """给一个注入点发放唯一 OOB 域名。返回 (token, host)；未启用返回 (None, "")。"""
        if not self.enabled or not self.client:
            return None, ""
        token, host = self.client.new_domain()
        with self.lock:
            self.pending[token] = dict(info or {})
        return token, host

    def record(self, token, info):
        """补充/更新某 token 的注入点信息（发包后把请求包等写进去）。"""
        if not token:
            return
        with self.lock:
            if token in self.pending:
                self.pending[token].update(info or {})
            else:
                self.pending[token] = dict(info or {})

    def _poll_loop(self):
        """后台线程：定期轮询交互，命中已登记 token 就回调上层。"""
        while True:
            time.sleep(self.poll_interval)
            self.poll_once()

    def poll_once(self):
        """拉取一次交互并分发命中。返回本次新命中的数量。"""
        try:
            interactions = self.client.poll()
        except Exception:
            return 0

        hits = 0
        for interaction in interactions:
            token = self.client.token_of(interaction)
            if not token:
                continue
            protocol = interaction.get("protocol", "")
            with self.lock:
                info = self.pending.get(token)
                key = (token, protocol)
                if not info or key in self.reported:
                    continue
                self.reported.add(key)

            if self.on_interaction:
                try:
                    self.on_interaction(dict(info), interaction)
                    hits += 1
                except Exception as error:
                    print(yellow(f"[XXE-OOB] 处理回连异常: {error}"), flush=True)
        return hits
