"""
p2p_connect.py - Простая P2P библиотека для чатов и мультиплеерных игр.
Зависимости: pip install aiortc pynacl

Пример использования (чат):
    from p2p_connect import P2PNode, MessageType
    async def main():
        node = P2PNode("Alice")
        node.on_message = lambda msg: print(f"{msg.sender}: {msg.data}")
        await node.start("offer")
        # или await node.start("answer")
    import asyncio
    asyncio.run(main())
"""

import asyncio
import json
import base64
import sys
from enum import Enum
from typing import Any, Callable, Optional
from aiortc import RTCPeerConnection, RTCSessionDescription, RTCConfiguration, RTCIceServer
from nacl import public, exceptions

# --- Конфигурация ---
STUN_SERVERS = ["stun:stun.l.google.com:19302"]
NONCE_SIZE = 24

# --- Типы данных ---
class MessageType(Enum):
    TEXT = "text"
    JSON = "json"
    BINARY = "binary"

class Message:
    """Класс для сообщений."""
    def __init__(self, data: Any, type: MessageType, sender: str, sender_pub: str):
        self.data = data
        self.type = type
        self.sender = sender
        self.sender_pub = sender_pub

    def to_dict(self) -> dict:
        data = self.data
        if self.type == MessageType.BINARY:
            data = base64.b64encode(self.data).decode('utf-8')
        return {
            "type": self.type.value,
            "sender": self.sender,
            "sender_pub": self.sender_pub,
            "data": data,
            "nonce": self.nonce if hasattr(self, "nonce") else None,
            "ciphertext": self.ciphertext if hasattr(self, "ciphertext") else None
        }

    @staticmethod
    def from_dict(data: dict) -> 'Message':
        msg_type = MessageType(data["type"])
        data_field = data["data"]
        if msg_type == MessageType.BINARY:
            data_field = base64.b64decode(data_field)
        msg = Message(data_field, msg_type, data["sender"], data["sender_pub"])
        if data.get("nonce") and data.get("ciphertext"):
            msg.nonce = data["nonce"]
            msg.ciphertext = data["ciphertext"]
        return msg

# --- Шифрование ---
class Crypto:
    @staticmethod
    def generate_keypair():
        sk = public.PrivateKey.generate()
        pk = sk.public_key
        return base64.b64encode(pk.encode()).decode('utf-8'), base64.b64encode(sk.encode()).decode('utf-8')

    @staticmethod
    def to_private(b64: str) -> public.PrivateKey:
        return public.PrivateKey(base64.b64decode(b64))

    @staticmethod
    def to_public(b64: str) -> public.PublicKey:
        return public.PublicKey(base64.b64decode(b64))

    @staticmethod
    def encrypt(sender_priv_b64: str, recipient_pub_b64: str, data: bytes) -> dict:
        sk = Crypto.to_private(sender_priv_b64)
        pk = Crypto.to_public(recipient_pub_b64)
        box = public.Box(sk, pk)
        full = box.encrypt(data)
        nonce = full[:NONCE_SIZE]
        ciphertext = full[NONCE_SIZE:]
        return {
            "nonce": base64.b64encode(nonce).decode('utf-8'),
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8')
        }

    @staticmethod
    def decrypt(recipient_priv_b64: str, sender_pub_b64: str, nonce_b64: str, ciphertext_b64: str) -> Optional[bytes]:
        sk = Crypto.to_private(recipient_priv_b64)
        pk = Crypto.to_public(sender_pub_b64)
        box = public.Box(sk, pk)
        try:
            return box.decrypt(base64.b64decode(nonce_b64) + base64.b64decode(ciphertext_b64))
        except exceptions.CryptoError:
            return None

# --- Основной класс P2P ---
class P2PNode:
    def __init__(self, nickname: str = "anon"):
        self.nickname = nickname
        self.pub_key, self.priv_key = Crypto.generate_keypair()
        self.remote_pub_key = None
        self.pc = None
        self.channel = None
        self.on_message: Callable[[Message], None] = lambda msg: None  # Callback для входящих сообщений
        self.running = False

    def set_remote_key(self, remote_pub_key: str):
        """Устанавливает публичный ключ партнёра."""
        self.remote_pub_key = remote_pub_key

    async def send(self, data: Any, msg_type: MessageType = MessageType.TEXT):
        """Отправляет сообщение."""
        if not self.channel or self.channel.readyState != "open":
            print("[ERROR] Канал не открыт!")
            return
        msg = Message(data, msg_type, self.nickname, self.pub_key)
        if self.remote_pub_key:
            data_bytes = data.encode('utf-8') if msg_type == MessageType.TEXT else \
                         json.dumps(data).encode('utf-8') if msg_type == MessageType.JSON else data
            enc = Crypto.encrypt(self.priv_key, self.remote_pub_key, data_bytes)
            msg.nonce = enc["nonce"]
            msg.ciphertext = enc["ciphertext"]
            msg.data = None  # Очищаем данные, так как они зашифрованы
        self.channel.send(json.dumps(msg.to_dict()))

    async def _input_loop(self):
        """Читает ввод с консоли для отправки текстовых сообщений."""
        loop = asyncio.get_event_loop()
        while self.running:
            try:
                text = await loop.run_in_executor(None, sys.stdin.readline)
                text = text.strip()
                if not text:
                    continue
                if text.lower() == "/exit":
                    await self.close()
                    break
                await self.send(text, MessageType.TEXT)
            except Exception as e:
                print(f"[ERROR] Ошибка ввода: {e}")
            await asyncio.sleep(0.1)

    async def _handle_message(self, raw_msg: str):
        """Обрабатывает входящее сообщение."""
        try:
            msg_dict = json.loads(raw_msg)
            msg = Message.from_dict(msg_dict)
            if hasattr(msg, "nonce") and hasattr(msg, "ciphertext") and self.remote_pub_key:
                decrypted = Crypto.decrypt(self.priv_key, msg.sender_pub, msg.nonce, msg.ciphertext)
                if decrypted is None:
                    print(f"[ERROR] Не удалось расшифровать сообщение от {msg.sender}")
                    return
                msg.data = decrypted.decode('utf-8') if msg.type == MessageType.TEXT else \
                           json.loads(decrypted) if msg.type == MessageType.JSON else decrypted
            self.on_message(msg)
        except Exception as e:
            print(f"[ERROR] Ошибка обработки сообщения: {e}")

    async def start(self, role: str):
        """Запускает P2P-соединение (offer или answer)."""
        if role not in ("offer", "answer"):
            raise ValueError("Роль должна быть 'offer' или 'answer'")
        self.running = True
        print(f"Твой публичный ключ: {self.pub_key}")
        if not self.remote_pub_key:
            self.remote_pub_key = input("Введи публичный ключ партнёра: ").strip() or self.pub_key

        config = RTCConfiguration([RTCIceServer(urls=STUN_SERVERS)])
        self.pc = RTCPeerConnection(configuration=config)

        if role == "offer":
            await self._run_offer()
        else:
            await self._run_answer()

    async def _run_offer(self):
        """Логика для роли offer."""
        self.channel = self.pc.createDataChannel("data")

        @self.channel.on("open")
        def on_open():
            print("[INFO] Канал открыт! Вводи сообщения или используй API. /exit для выхода.")
            asyncio.create_task(self._input_loop())

        @self.channel.on("message")
        def on_message(msg):
            asyncio.create_task(self._handle_message(msg))

        offer = await self.pc.createOffer()
        await self.pc.setLocalDescription(offer)
        print("\n=== Передай этот OFFER партнёру ===")
        print(json.dumps({"sdp": self.pc.localDescription.sdp, "type": self.pc.localDescription.type}))

        answer_json = input("\nВставь ANSWER JSON: ")
        try:
            ans = json.loads(answer_json)
            await self.pc.setRemoteDescription(RTCSessionDescription(sdp=ans["sdp"], type=ans["type"]))
            await asyncio.Future()  # Ожидаем события, не блокируя обработчики
        except Exception as e:
            print(f"[ERROR] Ошибка answer: {e}")
            await self.close()

    async def _run_answer(self):
        """Логика для роли answer."""
        @self.pc.on("datachannel")
        def on_datachannel(channel):
            self.channel = channel

           # @channel.on("open")
           # def on_open():
            print("[INFO] Канал открыт! Вводи сообщения или используй API. /exit для выхода.")
            asyncio.create_task(self._input_loop())

            @channel.on("message")
            def on_message(msg):
                asyncio.create_task(self._handle_message(msg))

        offer_json = input("\nВставь OFFER JSON: ")
        try:
            offer = json.loads(offer_json)
            await self.pc.setRemoteDescription(RTCSessionDescription(sdp=offer["sdp"], type=offer["type"]))
            answer = await self.pc.createAnswer()
            await self.pc.setLocalDescription(answer)
            print("\n=== Передай этот ANSWER партнёру ===")
            print(json.dumps({"sdp": self.pc.localDescription.sdp, "type": self.pc.localDescription.type}))
            await asyncio.Future()  # Вместо блокирующего sleep
        except Exception as e:
            print(f"[ERROR] Ошибка offer/answer: {e}")
            await self.close()

    async def close(self):
        """Закрывает соединение."""
        self.running = False
        if self.channel:
            try:
                await self.channel.close()
            except:
                pass
        if self.pc:
            await self.pc.close()

# --- Пример использования ---
if __name__ == "__main__":
    async def demo():
        nick = input("Введи ник: ").strip() or "anon"
        node = P2PNode(nick)
        node.on_message = lambda msg: print(f"{msg.sender}: {msg.data}")
        role = input("Роль (offer/answer): ").strip().lower()
        await node.start(role)
    asyncio.run(demo())