import base64
import ipaddress
import os
import socket
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import BinaryIO, ClassVar
from urllib.parse import unquote


class Protocol(Enum):
    IMAP = "imap"
    POP3 = "pop3"
    SMTP = "smtp"


class Status(Enum):
    OK = "OK"
    INVALID = "Invalid login or password"
    LIMITED = "Too many failed attempts, try again later"
    UNAVAILABLE = "Temporary server problem, try again later"


@dataclass(frozen=True)
class Backend:
    host: str
    port: int

    @classmethod
    def from_env(cls, name: str, host: str, port: int) -> "Backend":
        return cls(os.environ.get(f"{name}_HOST", host), int(os.environ.get(f"{name}_PORT", port)))


@dataclass(frozen=True)
class Request:
    protocol: Protocol
    user: str
    password: str
    attempt: int
    client: ipaddress.IPv4Address | ipaddress.IPv6Address

    @classmethod
    def from_headers(cls, headers) -> "Request":
        return cls(
            Protocol(headers.get("Auth-Protocol", "")),
            unquote(headers.get("Auth-User", "")),
            unquote(headers.get("Auth-Pass", "")),
            int(headers.get("Auth-Login-Attempt", 1)),
            ipaddress.ip_address(headers.get("Client-IP", "")),
        )


@dataclass(frozen=True)
class Verifier:
    host: str
    port: int
    timeout: float
    version: ClassVar[tuple[int, int]] = (1, 2)
    limit: ClassVar[int] = 16384

    @classmethod
    def from_env(cls) -> "Verifier":
        return cls(
            os.environ.get("VERIFY_HOST", "127.0.0.1"),
            int(os.environ.get("VERIFY_PORT", 12345)),
            float(os.environ.get("VERIFY_TIMEOUT", 30)),
        )

    def verify(self, request: Request) -> Status:
        if not request.user or not request.password or "\0" in request.user or "\0" in request.password:
            return Status.INVALID
        response = base64.b64encode(b"\0" + request.user.encode() + b"\0" + request.password.encode()).decode()
        try:
            with socket.create_connection((self.host, self.port), timeout=self.timeout) as connection, connection.makefile("rwb") as stream:
                stream.write(f"VERSION\t{self.version[0]}\t{self.version[1]}\nCPID\t{os.getpid()}\n".encode())
                stream.flush()
                if not self.handshake(stream):
                    return Status.UNAVAILABLE
                stream.write(f"AUTH\t1\tPLAIN\tservice={request.protocol.value}\tsecured\trip={request.client}\tresp={response}\n".encode())
                stream.flush()
                return self.result(self.read(stream))
        except OSError:
            return Status.UNAVAILABLE

    def read(self, stream: BinaryIO) -> list[str] | None:
        line = stream.readline(self.limit + 1)
        if not line.endswith(b"\n"):
            return None
        return line[:-1].decode(errors="replace").split("\t")

    def handshake(self, stream: BinaryIO) -> bool:
        version = False
        plain = False
        while (fields := self.read(stream)) is not None:
            if fields[0] == "VERSION":
                version = len(fields) >= 2 and fields[1] == str(self.version[0])
            elif fields[0] == "MECH":
                plain = plain or (len(fields) >= 2 and fields[1] == "PLAIN")
            elif fields[0] == "DONE":
                return version and plain
        return False

    def result(self, fields: list[str] | None) -> Status:
        if fields is None or len(fields) < 2 or fields[1] != "1":
            return Status.UNAVAILABLE
        if fields[0] == "OK":
            return Status.OK
        if fields[0] == "FAIL":
            return Status.UNAVAILABLE if "code=temp_fail" in fields[2:] else Status.INVALID
        return Status.UNAVAILABLE


@dataclass
class Client:
    start: float
    failures: int = 0
    active: int = 0


@dataclass
class Limiter:
    failures: int
    window: float
    concurrency: int
    ipv4_prefix: int
    ipv6_prefix: int
    clients: dict[ipaddress.IPv4Network | ipaddress.IPv6Network, Client] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)

    @classmethod
    def from_env(cls) -> "Limiter":
        return cls(
            int(os.environ.get("LIMIT_FAILURES", 10)),
            float(os.environ.get("LIMIT_WINDOW", 600)),
            int(os.environ.get("LIMIT_CONCURRENCY", 4)),
            int(os.environ.get("LIMIT_IPV4_PREFIX", 32)),
            int(os.environ.get("LIMIT_IPV6_PREFIX", 64)),
        )

    def network(self, address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
        return ipaddress.ip_network((address, self.ipv4_prefix if address.version == 4 else self.ipv6_prefix), strict=False)

    def acquire(self, address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        network = self.network(address)
        now = time.monotonic()
        with self.lock:
            self.expire(now)
            client = self.clients.get(network)
            if client is None or now - client.start >= self.window:
                client = Client(now, active=client.active if client is not None else 0)
                self.clients.pop(network, None)
                self.clients[network] = client
            if client.failures >= self.failures or client.active >= self.concurrency:
                return False
            client.active += 1
            return True

    def release(self, address: ipaddress.IPv4Address | ipaddress.IPv6Address, status: Status) -> None:
        with self.lock:
            client = self.clients[self.network(address)]
            client.active -= 1
            if status is Status.INVALID:
                client.failures += 1

    def expire(self, now: float) -> None:
        while self.clients:
            network, client = next(iter(self.clients.items()))
            if client.active or now - client.start < self.window:
                return
            del self.clients[network]


@dataclass(frozen=True)
class Response:
    status: Status
    backend: Backend | None = None
    wait: int | None = None
    error_code: str | None = None

    def headers(self) -> list[tuple[str, str]]:
        headers = [("Auth-Status", self.status.value)]
        if self.backend is not None:
            headers.append(("Auth-Server", self.backend.host))
            headers.append(("Auth-Port", str(self.backend.port)))
        if self.wait is not None:
            headers.append(("Auth-Wait", str(self.wait)))
        if self.error_code is not None:
            headers.append(("Auth-Error-Code", self.error_code))
        return headers


@dataclass(frozen=True)
class Service:
    verifier: Verifier
    limiter: Limiter
    backends: dict[Protocol, Backend]
    max_attempts: int
    wait: int

    @classmethod
    def from_env(cls) -> "Service":
        return cls(
            Verifier.from_env(),
            Limiter.from_env(),
            {
                Protocol.IMAP: Backend.from_env("IMAP", "127.0.0.1", 10143),
                Protocol.POP3: Backend.from_env("POP3", "127.0.0.1", 10110),
                Protocol.SMTP: Backend.from_env("SMTP", "127.0.0.1", 10025),
            },
            int(os.environ.get("MAX_ATTEMPTS", 5)),
            int(os.environ.get("AUTH_WAIT", 3)),
        )

    def authenticate(self, request: Request) -> Response:
        backend = self.backends.get(request.protocol)
        if backend is None:
            return Response(Status.INVALID)
        if not self.limiter.acquire(request.client):
            return Response(Status.LIMITED, error_code=self.error_code(request.protocol, Status.LIMITED))
        status = Status.UNAVAILABLE
        try:
            status = self.verifier.verify(request)
        finally:
            self.limiter.release(request.client, status)
        if status is Status.OK:
            return Response(status, backend=backend)
        error_code = self.error_code(request.protocol, status)
        if request.attempt >= self.max_attempts:
            return Response(status, error_code=error_code)
        return Response(status, wait=self.wait, error_code=error_code)

    def error_code(self, protocol: Protocol, status: Status) -> str | None:
        if protocol is not Protocol.SMTP:
            return None
        match status:
            case Status.UNAVAILABLE:
                return "451 4.3.0"
            case Status.LIMITED:
                return "454 4.7.0"
            case _:
                return None


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    server_version = "mail-auth"
    sys_version = ""
    service = Service.from_env()

    def do_GET(self) -> None:
        try:
            response = self.service.authenticate(Request.from_headers(self.headers))
        except (KeyError, ValueError):
            response = Response(Status.INVALID)
        self.send_response(200)
        for name, value in response.headers():
            self.send_header(name, value)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, format: str, *args) -> None:
        pass


class Server(ThreadingHTTPServer):
    daemon_threads = True

    @classmethod
    def from_env(cls) -> "Server":
        host = os.environ.get("LISTEN_HOST", "127.0.0.1")
        port = int(os.environ.get("LISTEN_PORT", 10080))
        return cls((host, port), Handler)


if __name__ == "__main__":
    Server.from_env().serve_forever()
