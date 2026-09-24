import imaplib
import os
from dataclasses import dataclass
from enum import Enum
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote


class Protocol(Enum):
    IMAP = "imap"
    POP3 = "pop3"
    SMTP = "smtp"


class Status(Enum):
    OK = "OK"
    INVALID = "Invalid login or password"
    UNAVAILABLE = "Temporary server problem, try again later"


@dataclass(frozen=True)
class Backend:
    host: str
    port: int

    @classmethod
    def from_env(cls, name: str, host: str, port: int) -> "Backend":
        return cls(os.environ.get(f"{name}_HOST", host), int(os.environ.get(f"{name}_PORT", port)))


@dataclass(frozen=True)
class Verifier:
    host: str
    port: int
    timeout: float

    @classmethod
    def from_env(cls) -> "Verifier":
        return cls(
            os.environ.get("VERIFY_HOST", "127.0.0.1"),
            int(os.environ.get("VERIFY_PORT", 1143)),
            float(os.environ.get("VERIFY_TIMEOUT", 10)),
        )

    def verify(self, user: str, password: str) -> Status:
        if not user or not password:
            return Status.INVALID
        try:
            connection = imaplib.IMAP4(self.host, self.port, timeout=self.timeout)
        except (OSError, imaplib.IMAP4.error):
            return Status.UNAVAILABLE
        try:
            connection.login(user, password)
        except imaplib.IMAP4.error:
            return Status.INVALID
        except OSError:
            return Status.UNAVAILABLE
        finally:
            try:
                connection.logout()
            except (OSError, imaplib.IMAP4.error):
                pass
        return Status.OK


@dataclass(frozen=True)
class Request:
    protocol: Protocol
    user: str
    password: str
    attempt: int

    @classmethod
    def from_headers(cls, headers) -> "Request":
        return cls(
            Protocol(headers.get("Auth-Protocol", "")),
            unquote(headers.get("Auth-User", "")),
            unquote(headers.get("Auth-Pass", "")),
            int(headers.get("Auth-Login-Attempt", 1)),
        )


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
    backends: dict[Protocol, Backend]
    max_attempts: int
    wait: int

    @classmethod
    def from_env(cls) -> "Service":
        return cls(
            Verifier.from_env(),
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
        status = self.verifier.verify(request.user, request.password)
        if status is Status.OK:
            return Response(status, backend=backend)
        error_code = self.error_code(request.protocol, status)
        if request.attempt >= self.max_attempts:
            return Response(status, error_code=error_code)
        return Response(status, wait=self.wait, error_code=error_code)

    def error_code(self, protocol: Protocol, status: Status) -> str | None:
        if protocol is not Protocol.SMTP:
            return None
        return "451 4.3.0" if status is Status.UNAVAILABLE else None


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
