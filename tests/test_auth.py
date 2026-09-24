import base64
import http.client
import importlib.util
import ipaddress
import re
import socket
import socketserver
import sys
import threading
from dataclasses import dataclass, field
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location("auth", Path(__file__).resolve().parent.parent / "auth" / "auth.py")
auth = importlib.util.module_from_spec(SPEC)
sys.modules["auth"] = auth
SPEC.loader.exec_module(auth)

CLIENT = ipaddress.ip_address("192.0.2.42")
HANDSHAKE = ["VERSION\t1\t3", "MECH\tPLAIN\tplaintext", "MECH\tLOGIN\tplaintext", "SPID\t1", "CUID\t1", "COOKIE\t" + "0" * 32, "DONE"]


@dataclass
class Dovecot:
    handshake: list[str] = field(default_factory=lambda: list(HANDSHAKE))
    reply: str = "OK\t{id}\tuser=user@example.org"
    received: list[list[str]] = field(default_factory=list)
    auth_before_done: bool = False


class DovecotHandler(socketserver.BaseRequestHandler):
    def setup(self) -> None:
        self.buffer = b""

    def line(self) -> list[str] | None:
        while b"\n" not in self.buffer:
            data = self.request.recv(4096)
            if not data:
                return None
            self.buffer += data
        line, _, self.buffer = self.buffer.partition(b"\n")
        return line.decode().split("\t")

    def handle(self) -> None:
        dovecot = self.server.dovecot
        self.request.settimeout(5)
        first = self.line()
        if first is None:
            return
        dovecot.received.append(first)
        if first[0] != "VERSION":
            return
        self.request.settimeout(0.2)
        try:
            while (fields := self.line()) is not None:
                dovecot.received.append(fields)
                if fields[0] == "AUTH":
                    dovecot.auth_before_done = True
        except TimeoutError:
            pass
        self.request.settimeout(5)
        self.request.sendall("".join(f"{line}\n" for line in dovecot.handshake).encode())
        while (fields := self.line()) is not None:
            dovecot.received.append(fields)
            if fields[0] == "AUTH":
                self.request.sendall(f"{dovecot.reply.format(id=fields[1])}\n".encode())
                return


class DovecotServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


@pytest.fixture
def dovecot():
    state = Dovecot()
    server = DovecotServer(("127.0.0.1", 0), DovecotHandler)
    server.dovecot = state
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield state, auth.Verifier("127.0.0.1", server.server_address[1], 5)
    server.shutdown()
    server.server_close()


def request(user="user@example.org", password="secret", protocol=auth.Protocol.IMAP, client=CLIENT, attempt=1):
    return auth.Request(protocol, user, password, attempt, client)


def command(state: Dovecot, name: str) -> list[str]:
    return next(fields for fields in state.received if fields[0] == name)


def parameters(fields: list[str]) -> dict[str, str | None]:
    return {key: value for key, _, value in (parameter.partition("=") for parameter in fields[3:])}


def test_client_starts_with_version_major_1(dovecot):
    state, verifier = dovecot
    verifier.verify(request())
    assert state.received[0][0] == "VERSION"
    assert state.received[0][1] == "1"
    assert state.received[0][2].isdigit()


def test_client_sends_cpid(dovecot):
    state, verifier = dovecot
    verifier.verify(request())
    assert int(command(state, "CPID")[1]) > 0


def test_client_waits_for_done_before_auth(dovecot):
    state, verifier = dovecot
    assert verifier.verify(request()) is auth.Status.OK
    assert not state.auth_before_done


def test_auth_command_uses_plain_with_32bit_id(dovecot):
    state, verifier = dovecot
    verifier.verify(request())
    fields = command(state, "AUTH")
    assert 0 < int(fields[1]) < 2 ** 32
    assert fields[2] == "PLAIN"


def test_auth_command_names_service(dovecot):
    state, verifier = dovecot
    for protocol in auth.Protocol:
        state.received.clear()
        verifier.verify(request(protocol=protocol))
        assert parameters(command(state, "AUTH"))["service"] == protocol.value


def test_auth_command_passes_ipv4_remote_ip(dovecot):
    state, verifier = dovecot
    verifier.verify(request())
    assert parameters(command(state, "AUTH"))["rip"] == "192.0.2.42"


def test_auth_command_passes_ipv6_remote_ip(dovecot):
    state, verifier = dovecot
    verifier.verify(request(client=ipaddress.ip_address("2001:db8::1")))
    assert ipaddress.ip_address(parameters(command(state, "AUTH"))["rip"]) == ipaddress.ip_address("2001:db8::1")


def test_auth_command_ends_with_initial_response(dovecot):
    state, verifier = dovecot
    verifier.verify(request())
    assert command(state, "AUTH")[-1].startswith("resp=")


def test_initial_response_is_plain_message_without_authzid(dovecot):
    state, verifier = dovecot
    verifier.verify(request())
    assert base64.b64decode(parameters(command(state, "AUTH"))["resp"], validate=True) == b"\0user@example.org\0secret"


def test_initial_response_encodes_utf8(dovecot):
    state, verifier = dovecot
    verifier.verify(request(user="ユーザー@example.org", password="パスワード"))
    assert base64.b64decode(parameters(command(state, "AUTH"))["resp"]) == "\0ユーザー@example.org\0パスワード".encode()


def test_credentials_with_tab_do_not_break_the_command(dovecot):
    state, verifier = dovecot
    verifier.verify(request(password="se\tcret\n"))
    fields = command(state, "AUTH")
    assert base64.b64decode(parameters(fields)["resp"]) == b"\0user@example.org\0se\tcret\n"


@pytest.mark.parametrize("user,password", [("us\0er@example.org", "secret"), ("user@example.org", "sec\0ret")])
def test_credentials_with_nul_are_never_sent(dovecot, user, password):
    state, verifier = dovecot
    assert verifier.verify(request(user=user, password=password)) is auth.Status.INVALID
    assert not any(fields[0] == "AUTH" for fields in state.received)


@pytest.mark.parametrize("user,password", [("", "secret"), ("user@example.org", "")])
def test_empty_credentials_are_invalid(dovecot, user, password):
    state, verifier = dovecot
    assert verifier.verify(request(user=user, password=password)) is auth.Status.INVALID
    assert not any(fields[0] == "AUTH" for fields in state.received)


def test_ok_is_accepted(dovecot):
    state, verifier = dovecot
    assert verifier.verify(request()) is auth.Status.OK


def test_fail_is_invalid(dovecot):
    state, verifier = dovecot
    state.reply = "FAIL\t{id}\tuser=user@example.org"
    assert verifier.verify(request()) is auth.Status.INVALID


def test_fail_with_temp_fail_is_unavailable(dovecot):
    state, verifier = dovecot
    state.reply = "FAIL\t{id}\tcode=temp_fail"
    assert verifier.verify(request()) is auth.Status.UNAVAILABLE


def test_continuation_is_not_accepted(dovecot):
    state, verifier = dovecot
    state.reply = "CONT\t{id}\t"
    assert verifier.verify(request()) is not auth.Status.OK


def test_reply_for_another_id_is_not_accepted(dovecot):
    state, verifier = dovecot
    state.reply = "OK\t2\tuser=user@example.org"
    assert verifier.verify(request()) is not auth.Status.OK


def test_unsupported_major_version_is_not_used(dovecot):
    state, verifier = dovecot
    state.handshake = ["VERSION\t2\t0"] + HANDSHAKE[1:]
    assert verifier.verify(request()) is auth.Status.UNAVAILABLE
    assert not any(fields[0] == "AUTH" for fields in state.received)


def test_server_without_plain_is_not_used(dovecot):
    state, verifier = dovecot
    state.handshake = [line for line in HANDSHAKE if not line.startswith("MECH\tPLAIN")]
    assert verifier.verify(request()) is auth.Status.UNAVAILABLE
    assert not any(fields[0] == "AUTH" for fields in state.received)


def test_unreachable_server_is_unavailable():
    with socket.socket() as placeholder:
        placeholder.bind(("127.0.0.1", 0))
        port = placeholder.getsockname()[1]
    assert auth.Verifier("127.0.0.1", port, 1).verify(request()) is auth.Status.UNAVAILABLE


@dataclass
class FakeVerifier:
    status: auth.Status = auth.Status.OK
    calls: int = 0
    gate: threading.Event | None = None

    def verify(self, request) -> auth.Status:
        self.calls += 1
        if self.gate is not None:
            self.gate.wait(5)
        return self.status


def service(verifier: FakeVerifier, failures=3, window=600.0, concurrency=2, max_attempts=5):
    return auth.Service(
        verifier,
        auth.Limiter(failures, window, concurrency, 32, 64),
        {
            auth.Protocol.IMAP: auth.Backend("127.0.0.1", 10143),
            auth.Protocol.POP3: auth.Backend("127.0.0.1", 10110),
            auth.Protocol.SMTP: auth.Backend("127.0.0.1", 10025),
        },
        max_attempts,
        3,
    )


def headers(response) -> dict[str, str]:
    return dict(response.headers())


def test_success_names_backend():
    result = headers(service(FakeVerifier()).authenticate(request()))
    assert result["Auth-Status"] == "OK"
    assert result["Auth-Server"] == "127.0.0.1"
    assert result["Auth-Port"] == "10143"


@pytest.mark.parametrize("protocol,port", [(auth.Protocol.IMAP, "10143"), (auth.Protocol.SMTP, "10025")])
def test_success_uses_backend_of_protocol(protocol, port):
    assert headers(service(FakeVerifier()).authenticate(request(protocol=protocol)))["Auth-Port"] == port


def test_failure_is_not_ok_and_names_no_backend():
    result = headers(service(FakeVerifier(auth.Status.INVALID)).authenticate(request()))
    assert result["Auth-Status"] != "OK"
    assert "Auth-Server" not in result
    assert "Auth-Port" not in result


def test_failure_allows_retry_until_last_attempt():
    target = service(FakeVerifier(auth.Status.INVALID), failures=100, max_attempts=5)
    assert "Auth-Wait" in headers(target.authenticate(request(attempt=1)))
    assert "Auth-Wait" in headers(target.authenticate(request(attempt=4)))
    assert "Auth-Wait" not in headers(target.authenticate(request(attempt=5)))


def test_smtp_errors_use_rfc_3463_codes():
    for status in (auth.Status.INVALID, auth.Status.UNAVAILABLE, auth.Status.LIMITED):
        code = headers(service(FakeVerifier(status), failures=0 if status is auth.Status.LIMITED else 3).authenticate(request(protocol=auth.Protocol.SMTP))).get("Auth-Error-Code")
        if code is None:
            continue
        match = re.fullmatch(r"([245])\d\d ([245])\.\d{1,3}\.\d{1,3}", code)
        assert match is not None
        assert match.group(1) == match.group(2)


def test_temporary_smtp_errors_are_transient():
    code = headers(service(FakeVerifier(auth.Status.UNAVAILABLE)).authenticate(request(protocol=auth.Protocol.SMTP)))["Auth-Error-Code"]
    assert code.startswith("4")


def test_imap_errors_have_no_smtp_code():
    result = headers(service(FakeVerifier(auth.Status.UNAVAILABLE)).authenticate(request()))
    assert "Auth-Error-Code" not in result


def test_client_is_limited_after_failures():
    verifier = FakeVerifier(auth.Status.INVALID)
    target = service(verifier, failures=3)
    for _ in range(3):
        target.authenticate(request())
    result = headers(target.authenticate(request()))
    assert verifier.calls == 3
    assert result["Auth-Status"] != "OK"
    assert "Auth-Wait" not in result


def test_limited_smtp_client_gets_transient_code():
    target = service(FakeVerifier(auth.Status.INVALID), failures=1)
    target.authenticate(request(protocol=auth.Protocol.SMTP))
    assert headers(target.authenticate(request(protocol=auth.Protocol.SMTP)))["Auth-Error-Code"].startswith("4")


def test_correct_password_is_refused_while_limited():
    verifier = FakeVerifier(auth.Status.INVALID)
    target = service(verifier, failures=2)
    target.authenticate(request())
    target.authenticate(request())
    verifier.status = auth.Status.OK
    assert headers(target.authenticate(request()))["Auth-Status"] != "OK"


def test_successes_do_not_count_as_failures():
    verifier = FakeVerifier(auth.Status.OK)
    target = service(verifier, failures=2)
    for _ in range(10):
        assert headers(target.authenticate(request()))["Auth-Status"] == "OK"


def test_unavailable_does_not_count_as_failure():
    verifier = FakeVerifier(auth.Status.UNAVAILABLE)
    target = service(verifier, failures=2)
    for _ in range(5):
        target.authenticate(request())
    assert verifier.calls == 5


def test_other_clients_are_not_limited():
    verifier = FakeVerifier(auth.Status.INVALID)
    target = service(verifier, failures=1)
    target.authenticate(request())
    verifier.status = auth.Status.OK
    assert headers(target.authenticate(request(client=ipaddress.ip_address("192.0.2.43"))))["Auth-Status"] == "OK"


def test_ipv6_clients_are_limited_per_64():
    verifier = FakeVerifier(auth.Status.INVALID)
    target = service(verifier, failures=1)
    target.authenticate(request(client=ipaddress.ip_address("2001:db8:0:1::1")))
    verifier.status = auth.Status.OK
    assert headers(target.authenticate(request(client=ipaddress.ip_address("2001:db8:0:1::2"))))["Auth-Status"] != "OK"
    assert headers(target.authenticate(request(client=ipaddress.ip_address("2001:db8:0:2::1"))))["Auth-Status"] == "OK"


def test_limit_expires_after_window(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(auth.time, "monotonic", lambda: now[0])
    verifier = FakeVerifier(auth.Status.INVALID)
    target = service(verifier, failures=1, window=60)
    target.authenticate(request())
    verifier.status = auth.Status.OK
    now[0] += 59
    assert headers(target.authenticate(request()))["Auth-Status"] != "OK"
    now[0] += 1
    assert headers(target.authenticate(request()))["Auth-Status"] == "OK"


def test_expired_clients_are_forgotten(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(auth.time, "monotonic", lambda: now[0])
    target = service(FakeVerifier(auth.Status.INVALID), failures=5, window=60)
    for index in range(100):
        target.authenticate(request(client=ipaddress.ip_address(f"198.51.100.{index}")))
    now[0] += 60
    target.authenticate(request())
    assert len(target.limiter.clients) == 1


def test_concurrent_verifications_are_limited_per_client():
    gate = threading.Event()
    verifier = FakeVerifier(auth.Status.OK, gate=gate)
    target = service(verifier, concurrency=2)
    threads = [threading.Thread(target=target.authenticate, args=(request(),)) for _ in range(2)]
    for thread in threads:
        thread.start()
    while verifier.calls < 2:
        pass
    try:
        assert headers(target.authenticate(request()))["Auth-Status"] != "OK"
        assert verifier.calls == 2
        assert headers(target.authenticate(request(client=ipaddress.ip_address("192.0.2.43"))))["Auth-Status"] == "OK"
    finally:
        gate.set()
        for thread in threads:
            thread.join()
    assert headers(target.authenticate(request()))["Auth-Status"] == "OK"


@pytest.fixture
def server(monkeypatch):
    verifier = FakeVerifier()
    monkeypatch.setattr(auth.Handler, "service", service(verifier))
    instance = auth.Server(("127.0.0.1", 0), auth.Handler)
    thread = threading.Thread(target=instance.serve_forever, daemon=True)
    thread.start()
    yield instance.server_address[1], verifier
    instance.shutdown()
    instance.server_close()


def fetch(port: int, extra: dict[str, str]) -> http.client.HTTPResponse:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    base = {"Auth-Method": "plain", "Auth-User": "user%40example.org", "Auth-Pass": "secret", "Auth-Protocol": "imap", "Auth-Login-Attempt": "1", "Client-IP": "192.0.2.42"}
    connection.request("GET", "/auth", headers={**base, **extra})
    response = connection.getresponse()
    response.read()
    connection.close()
    return response


def test_http_success(server):
    port, verifier = server
    response = fetch(port, {})
    assert response.status == 200
    assert response.getheader("Auth-Status") == "OK"
    assert response.getheader("Auth-Server") == "127.0.0.1"
    assert response.getheader("Auth-Port") == "10143"


def test_http_decodes_url_encoded_credentials(server, monkeypatch):
    port, verifier = server
    seen = []
    monkeypatch.setattr(verifier, "verify", lambda request: seen.append(request) or auth.Status.OK)
    fetch(port, {"Auth-User": "user%40example.org", "Auth-Pass": "p%25ss%20word"})
    assert seen[0].user == "user@example.org"
    assert seen[0].password == "p%ss word"
    assert seen[0].client == CLIENT


@pytest.mark.parametrize("extra", [{"Client-IP": ""}, {"Client-IP": "not-an-address"}, {"Auth-Protocol": "unknown"}])
def test_http_malformed_request_is_refused(server, extra):
    port, verifier = server
    response = fetch(port, extra)
    assert response.status == 200
    assert response.getheader("Auth-Status") not in (None, "OK")
    assert verifier.calls == 0
