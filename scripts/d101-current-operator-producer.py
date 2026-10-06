#!/usr/bin/env python3
"""Issuer-only private transport; absent independent installation always denies."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
import http.client
import json
import os
import re
import select
import signal
import ssl
import subprocess
import sys
import time
from typing import Protocol
from urllib.parse import parse_qsl, urlencode, urlsplit

MAX_JWT_BYTES = 65536
READY_SECONDS = 30
TOKEN_SECONDS = 2
LAUNCHER = "/etc/opensamguk/d101/native-helper/host-session-launcher"
PUBLIC_REASONS = frozenset({
    "DEADLINE_EXCEEDED", "BOUNDED_CLOCK_UNAVAILABLE", "CLOCK_ALREADY_IN_USE",
    "OIDC_RESPONSE_INVALID", "OIDC_ENDPOINT_MISMATCH", "INSTALLED_REQUEST_INVALID",
    "OIDC_REQUEST_CREDENTIAL_UNAVAILABLE", "OIDC_RESPONSE_REJECTED", "OIDC_RESPONSE_OVERSIZE",
    "JWT_FRAMING_INVALID", "READY_TIMEOUT", "READY_DENIED", "JWT_TRANSFER_TIMEOUT",
    "JWT_TRANSFER_REJECTED", "NATIVE_ISSUANCE_NOT_CONFIRMED", "OPERATION_SELECTOR_INVALID",
    "WORKFLOW_EVENT_REJECTED", "INDEPENDENT_INSTALLED_SUPPLIER_UNAVAILABLE",
})


class Hold(Exception):
    """Only fixed reason codes may cross the public output boundary."""


@dataclass(frozen=True)
class RequestData:
    # These are data, not authority. Only an independently authenticated native
    # supplier can authorize this request, reserve the operation and confirm it.
    request_endpoint: str
    audience: str
    operation_cutoff_monotonic: float


class InstalledSupplier(Protocol):
    def reserve_authorized_operation(self, operation_id: str) -> RequestData:
        """Authenticate installation/pins/scope and durable pre-READY custody."""

    def confirm_retained_originals(self, operation_id: str) -> None:
        """Verify native retained originals; child exit/readiness is insufficient."""


def _fixed_independent_supplier() -> InstalledSupplier | None:
    # No actual endpoint/policy/key/native custody supplier has been installed.
    # Never substitute env, request URI, workflow input, JWT or a JSON shape.
    # Wiring an actual supplier requires a separately reviewed source change.
    return None


def _remaining(deadline: float) -> float:
    left = deadline - time.monotonic()
    if left <= 0:
        raise Hold("DEADLINE_EXCEEDED")
    return left


@contextmanager
def _bounded_call(deadline: float):
    # The runner uses Linux and the main thread. One alarm covers connection,
    # response reads and transport together; chunks never restart the budget.
    if not hasattr(signal, "setitimer"):
        raise Hold("BOUNDED_CLOCK_UNAVAILABLE")
    if signal.getitimer(signal.ITIMER_REAL) != (0.0, 0.0):
        raise Hold("CLOCK_ALREADY_IN_USE")
    previous = signal.getsignal(signal.SIGALRM)

    def expired(_signum, _frame):
        raise Hold("DEADLINE_EXCEEDED")

    signal.signal(signal.SIGALRM, expired)
    try:
        signal.setitimer(signal.ITIMER_REAL, _remaining(deadline))
        yield
        _remaining(deadline)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Hold("OIDC_RESPONSE_INVALID")
        result[key] = value
    return result


def _request_exact_token(data: RequestData, deadline: float) -> bytes:
    # Environment URL only corroborates the independently supplied exact URL.
    # It never selects an endpoint or grants authority.
    if os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL") != data.request_endpoint:
        raise Hold("OIDC_ENDPOINT_MISMATCH")
    parts = urlsplit(data.request_endpoint)
    if (parts.scheme != "https" or not parts.hostname or parts.username is not None or
            parts.password is not None or parts.fragment or parts.port not in (None, 443) or
            any(char.isspace() for char in data.request_endpoint) or
            not data.audience or any(key == "audience" for key, _ in parse_qsl(parts.query))):
        raise Hold("INSTALLED_REQUEST_INVALID")
    credential = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if not credential or "\r" in credential or "\n" in credential:
        raise Hold("OIDC_REQUEST_CREDENTIAL_UNAVAILABLE")
    query = parts.query + ("&" if parts.query else "") + urlencode({"audience": data.audience})
    target = (parts.path or "/") + "?" + query
    connection = http.client.HTTPSConnection(parts.hostname, 443,
        timeout=_remaining(deadline), context=ssl.create_default_context())
    try:
        # Direct connection: environment proxies and redirects are not used.
        connection.request("GET", target, headers={"Authorization": "Bearer " + credential,
                                                   "Accept": "application/json"})
        response = connection.getresponse()
        if response.status != 200 or response.getheader("Content-Type", "").split(";", 1)[0] != "application/json":
            raise Hold("OIDC_RESPONSE_REJECTED")
        raw = response.read(MAX_JWT_BYTES + 1)
        _remaining(deadline)
        if len(raw) > MAX_JWT_BYTES:
            raise Hold("OIDC_RESPONSE_OVERSIZE")
        value = json.loads(raw, object_pairs_hook=_unique_object)
        if not isinstance(value, dict) or set(value) != {"value"} or not isinstance(value["value"], str):
            raise Hold("OIDC_RESPONSE_INVALID")
        token = value["value"].encode("ascii")
        if not token or len(token) > MAX_JWT_BYTES or not re.fullmatch(rb"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", token):
            raise Hold("JWT_FRAMING_INVALID")
        # Framing is not authentication; actual Verify/JTI/scope is host-owned.
        return token
    finally:
        connection.close()


def _read_ready(child: subprocess.Popen, deadline: float) -> float:
    readable, _, _ = select.select([child.stdout], [], [], _remaining(deadline))
    if not readable:
        raise Hold("READY_TIMEOUT")
    ready = os.read(child.stdout.fileno(), 1)
    observed = time.monotonic()
    _remaining(deadline)
    if ready != b"R":
        raise Hold("READY_DENIED")
    return observed


def _write_exact_and_eof(child: subprocess.Popen, token: bytes, deadline: float) -> None:
    fd = child.stdin.fileno()
    os.set_blocking(fd, False)
    view = memoryview(token)
    while view:
        _, writable, _ = select.select([], [fd], [], _remaining(deadline))
        if not writable:
            raise Hold("JWT_TRANSFER_TIMEOUT")
        try:
            count = os.write(fd, view)
        except BlockingIOError:
            continue
        if count <= 0:
            raise Hold("JWT_TRANSFER_REJECTED")
        view = view[count:]
    child.stdin.close()  # No LF, wrapper, second token or retry.
    _remaining(deadline)


def _issuer_only_once(operation_id: str, supplier: InstalledSupplier) -> None:
    data = supplier.reserve_authorized_operation(operation_id)
    _remaining(data.operation_cutoff_monotonic)
    # The host validates the installed source/native scope, takes root privilege
    # before its first FD9/flock and owns the keeper's entire lifetime. Neither
    # this process nor a pipe/PID/UID observation authenticates that lifetime.
    child = subprocess.Popen(["sudo", "-n", "--", LAUNCHER, "--issuer-only",
                              "--operation-id", operation_id], stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}, close_fds=True)
    try:
        observed_ready = _read_ready(child, min(time.monotonic() + READY_SECONDS,
                                               data.operation_cutoff_monotonic))
        # Host: authoritative R-success-write -> exact JWT + EOF total 2s.
        # Producer: observed-R local 2s, including HTTPS and transfer. These
        # clocks are distinct. A delayed/denied host yields same-op HOLD.
        deadline = min(observed_ready + TOKEN_SECONDS, data.operation_cutoff_monotonic)
        with _bounded_call(deadline):
            token = _request_exact_token(data, deadline)
            _write_exact_and_eof(child, token, deadline)
        # Host must authenticate JWT, atomically claim authenticated issuer/JTI
        # after Verify and complete native issuance/retention. No body may follow
        # R on stdout. A successful exit alone is never an issuance receipt.
        readable, _, _ = select.select([child.stdout], [], [],
                                      _remaining(data.operation_cutoff_monotonic))
        if not readable:
            raise Hold("NATIVE_ISSUANCE_NOT_CONFIRMED")
        extra = os.read(child.stdout.fileno(), 1)
        if extra or child.wait(timeout=_remaining(data.operation_cutoff_monotonic)) != 0:
            raise Hold("NATIVE_ISSUANCE_NOT_CONFIRMED")
        supplier.confirm_retained_originals(operation_id)
    finally:
        if not child.stdin.closed:
            child.stdin.close()
        child.stdout.close()
        # No kill/release/reissue here: timeout/unknown belongs to the native
        # same-operation HOLD protocol and its custody, never an automatic retry.


class _Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise Hold("OPERATION_SELECTOR_INVALID")


def main(argv: list[str] | None = None) -> int:
    try:
        parser = _Parser(add_help=False)
        parser.add_argument("--operation-id", required=True)
        operation_id = parser.parse_args(argv).operation_id
        if re.fullmatch(r"[a-f0-9]{32}", operation_id) is None:
            raise Hold("OPERATION_SELECTOR_INVALID")
        if os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch" or os.environ.get("GITHUB_RUN_ATTEMPT") != "1":
            raise Hold("WORKFLOW_EVENT_REJECTED")
        supplier = _fixed_independent_supplier()
        if supplier is None:
            raise Hold("INDEPENDENT_INSTALLED_SUPPLIER_UNAVAILABLE")
        _issuer_only_once(operation_id, supplier)
        print("TECHNICAL_ORIGINALS_CONFIRMED")
        return 0
    except Hold as failure:
        reason = str(failure)
        print("HOLD:" + (reason if reason in PUBLIC_REASONS else "ISSUER_ONLY_UNAVAILABLE"))
    except Exception:
        print("HOLD:ISSUER_ONLY_UNAVAILABLE")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
