# interactsh 客户端 —— 对接 projectdiscovery 的免费公共 OOB（带外）服务。
#
# interactsh 是业界标准的 OOB 平台，官方提供多个免费公共服务器（oast.pro、oast.fun…），
# 也可自建。命令注入盲打时，我们注入一条“向唯一子域发起 DNS/HTTP 请求”的命令，
# 目标一旦执行就会回连 interactsh 服务器，我们轮询即可确认漏洞。
#
# 这个文件只实现 interactsh 的协议（纯 Python，依赖 cryptography——它本就是 mitmproxy
# 的依赖，无需额外安装），不含任何检测逻辑。命令注入插件的 oob.py 会调用它。
#
# 协议流程：
#   1. 本地生成 RSA-2048 密钥对，生成 20 字符 correlation-id 和一个 secret(uuid)。
#   2. POST /register 上报公钥(PEM/SubjectPublicKeyInfo 的 base64)、secret、correlation-id。
#   3. 每个 payload 用一个新域名：correlation-id(20) + 随机 token(13) + "." + 服务器域名。
#      同一 correlation-id 下所有域名的交互都在一次 poll 里返回，用 token 区分是哪个 payload。
#   4. GET /poll?id=<correlation-id>&secret=<secret> 返回:
#        { "aes_key": <RSA-OAEP-SHA256 加密的 AES key，base64>,
#          "data":   [<AES-CTR 加密的交互 JSON，base64>, ...] }
#      用私钥解出 AES key，再解每条 data，得到 {protocol, unique-id/full-id, remote-address, ...}。
#
# 参考：https://github.com/projectdiscovery/interactsh

import base64
import json
import secrets
import ssl
import string
import uuid
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# 官方免费公共服务器。任选其一即可；某个不可用时可换下一个。
DEFAULT_SERVERS = (
    "oast.pro",
    "oast.live",
    "oast.site",
    "oast.online",
    "oast.fun",
    "oast.me",
)

CORRELATION_ID_LENGTH = 20
TOKEN_LENGTH = 13  # 20 + 13 = 33，interactsh 约定的完整标识长度


def _rand_label(length):
    """生成 DNS 安全的随机标签：首位字母，其余小写字母 + 数字。"""
    alphabet = string.ascii_lowercase + string.digits
    first = secrets.choice(string.ascii_lowercase)
    rest = "".join(secrets.choice(alphabet) for _ in range(length - 1))
    return first + rest


class InteractshClient:
    """interactsh 协议客户端（纯 Python）。"""

    def __init__(self, server="oast.pro", token="", timeout=15):
        self.server = server
        self.auth_token = token  # 自建服务器可能需要 Authorization；公共服务器留空。
        self.timeout = timeout
        self.correlation_id = _rand_label(CORRELATION_ID_LENGTH)
        self.secret = str(uuid.uuid4())
        self.private_key = None
        self.registered = False

        # 不走系统代理，避免 OOB 请求又绕回 mitmproxy 形成回环。
        # 公共服务器证书有效，但为兼容性统一用不校验的上下文（OOB 内容非机密）。
        ssl_context = ssl._create_unverified_context()
        self.opener = build_opener(ProxyHandler({}), HTTPSHandler(context=ssl_context))

    # ------------------------------------------------------------------
    # 注册 / 轮询
    # ------------------------------------------------------------------

    def register(self):
        """生成密钥并向服务器注册会话。成功返回 True。"""
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub_pem = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        payload = {
            "public-key": base64.b64encode(pub_pem).decode("ascii"),
            "secret-key": self.secret,
            "correlation-id": self.correlation_id,
        }
        request = Request(
            f"https://{self.server}/register",
            data=json.dumps(payload).encode("utf-8"),
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        if self.auth_token:
            request.add_header("Authorization", self.auth_token)

        try:
            self.opener.open(request, timeout=self.timeout).read()
            self.registered = True
            return True
        except Exception:
            self.registered = False
            return False

    def new_domain(self):
        """分配一个新的 OOB 域名。返回 (token, host)。

        token 是 13 字符随机标识，用于把回连关联回具体注入点。
        host 是完整域名，直接拼进 payload。
        """
        token = _rand_label(TOKEN_LENGTH)
        host = f"{self.correlation_id}{token}.{self.server}"
        return token, host

    def poll(self):
        """拉取并解密新的交互记录，返回交互 dict 列表。失败返回 []。"""
        if not self.registered or not self.private_key:
            return []

        url = f"https://{self.server}/poll?id={self.correlation_id}&secret={self.secret}"
        request = Request(url, method="GET")
        if self.auth_token:
            request.add_header("Authorization", self.auth_token)

        try:
            body = self.opener.open(request, timeout=self.timeout).read()
            obj = json.loads(body)
        except Exception:
            return []

        aes_key_b64 = obj.get("aes_key")
        data = obj.get("data") or []
        if not aes_key_b64 or not data:
            return []

        try:
            aes_key = self._decrypt_aes_key(base64.b64decode(aes_key_b64))
        except Exception:
            return []

        interactions = []
        for item in data:
            try:
                raw = base64.b64decode(item)
                plaintext = self._aes_ctr_decrypt(aes_key, raw)
                interactions.append(json.loads(plaintext))
            except Exception:
                continue
        return interactions

    def token_of(self, interaction):
        """从交互记录里提取 13 字符 token（去掉 correlation-id 前缀）。"""
        full_id = (
            interaction.get("full-id")
            or interaction.get("unique-id")
            or interaction.get("uniqueId")
            or ""
        )
        full_id = full_id.lower()
        if full_id.startswith(self.correlation_id):
            return full_id[len(self.correlation_id):][:TOKEN_LENGTH]
        return ""

    # ------------------------------------------------------------------
    # 解密
    # ------------------------------------------------------------------

    def _decrypt_aes_key(self, encrypted_key):
        """用 RSA 私钥（OAEP + SHA256）解出会话 AES key。"""
        return self.private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    def _aes_ctr_decrypt(self, key, raw):
        """AES-CTR 解密。前 16 字节是 IV，其余是密文。"""
        iv = raw[:16]
        ciphertext = raw[16:]
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    def _aes_cfb_decrypt(self, key, raw):
        """兼容旧内部调用名；interactsh 当前 poll 数据使用 AES-CTR。"""
        return self._aes_ctr_decrypt(key, raw)
