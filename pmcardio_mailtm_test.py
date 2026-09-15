#!/usr/bin/env python3
"""Bounded Mail.tm test-account onboarding for the PMcardio integration.

This module is intentionally test-only. It creates one generated Mail.tm
mailbox per explicit test run, reads the PMcardio Cognito confirmation code,
and returns the resulting PMcardio refresh session to the caller without
printing or persisting the Mail.tm password or token.
"""

from __future__ import annotations

import json
import re
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

from pmcardio_api_test import (
    CognitoTokenSet,
    PMCardioError,
    cognito_confirm_sign_up,
    cognito_password_sign_in,
    cognito_sign_up,
)


MAIL_TM_BASE_URL = "https://api.mail.tm"
VERIFICATION_CODE_PATTERNS = (
    re.compile(
        r"(?:verification|confirmation|confirm|security|code|رمز)[^\d]{0,80}(\d{6})",
        re.IGNORECASE,
    ),
    re.compile(r"\b(\d{6})\b"),
)


class MailTmError(RuntimeError):
    """A Mail.tm API or test-onboarding failure."""


@dataclass(frozen=True)
class MailTmMailbox:
    address: str
    password: str
    token: str


class MailTmClient:
    def __init__(self, token: str | None = None, *, timeout: float = 20.0) -> None:
        self.token = token
        self.timeout = timeout

    def _request_json(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, Any] | None = None,
        authenticated: bool = False,
    ) -> Any:
        body = (
            json.dumps(payload).encode("utf-8")
            if payload is not None
            else None
        )
        headers = {"Accept": "application/json"}
        if payload is not None:
            headers["Content-Type"] = "application/json"
        if authenticated:
            if not self.token:
                raise MailTmError("Mail.tm authentication token is missing.")
            headers["Authorization"] = f"Bearer {self.token}"
        request = urllib.request.Request(
            f"{MAIL_TM_BASE_URL}{path}",
            data=body,
            headers=headers,
            method=method,
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:400]
            raise MailTmError(
                f"Mail.tm {method} {path} returned HTTP {exc.code}: {detail}"
            ) from exc
        except urllib.error.URLError as exc:
            raise MailTmError(f"Mail.tm request failed: {exc.reason}") from exc
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise MailTmError("Mail.tm returned invalid JSON.") from exc

    def active_domains(self) -> list[str]:
        last_member_count = 0
        for attempt in range(3):
            payload = self._request_json("GET", "/domains?page=1")
            if isinstance(payload, dict):
                members = payload.get("hydra:member")
            elif isinstance(payload, list):
                members = payload
            else:
                members = None
            if isinstance(members, list):
                last_member_count = len(members)
                domains = [
                    str(item["domain"])
                    for item in members
                    if isinstance(item, dict)
                    and item.get("isActive", True) is not False
                    and isinstance(item.get("domain"), str)
                    and item["domain"].strip()
                ]
                if domains:
                    return domains
            if attempt < 2:
                time.sleep(2)
        raise MailTmError(
            f"Mail.tm returned no active domains after retries "
            f"(domain records: {last_member_count})."
        )

    def create_account(self, address: str, password: str) -> None:
        self._request_json(
            "POST",
            "/accounts",
            payload={"address": address, "password": password},
        )

    def issue_token(self, address: str, password: str) -> str:
        payload = self._request_json(
            "POST",
            "/token",
            payload={"address": address, "password": password},
        )
        token = payload.get("token") if isinstance(payload, dict) else None
        if not isinstance(token, str) or not token:
            raise MailTmError("Mail.tm did not return a token.")
        return token

    def list_messages(self) -> list[dict[str, Any]]:
        payload = self._request_json(
            "GET",
            "/messages?page=1",
            authenticated=True,
        )
        if isinstance(payload, dict):
            members = payload.get("hydra:member")
        elif isinstance(payload, list):
            members = payload
        else:
            members = None
        return [item for item in members if isinstance(item, dict)] if isinstance(members, list) else []

    def get_message(self, message_id: str) -> dict[str, Any]:
        payload = self._request_json(
            "GET",
            f"/messages/{urllib.parse.quote(message_id, safe='')}",
            authenticated=True,
        )
        if not isinstance(payload, dict):
            raise MailTmError("Mail.tm returned an invalid message.")
        return payload

    def wait_for_code(self, *, timeout: float = 180.0, poll_interval: float = 3.0) -> str:
        deadline = time.monotonic() + timeout
        checked: set[str] = set()
        while time.monotonic() < deadline:
            for summary in self.list_messages():
                message_id = summary.get("id")
                if not isinstance(message_id, str) or message_id in checked:
                    continue
                checked.add(message_id)
                message = self.get_message(message_id)
                text_parts = [
                    message.get("subject"),
                    message.get("intro"),
                    message.get("text"),
                ]
                html = message.get("html")
                if isinstance(html, list):
                    text_parts.extend(html)
                elif isinstance(html, str):
                    text_parts.append(html)
                content = "\n".join(
                    str(part) for part in text_parts if isinstance(part, str)
                )
                for pattern in VERIFICATION_CODE_PATTERNS:
                    match = pattern.search(content)
                    if match:
                        return match.group(1)
            time.sleep(max(1.0, poll_interval))
        raise MailTmError("Timed out waiting for the PMcardio email verification code.")


def create_verified_pmcardio_test_account(
    *,
    mailbox_timeout: float = 180.0,
) -> tuple[str, CognitoTokenSet]:
    """Create exactly one test mailbox and one verified PMcardio session."""

    bootstrap = MailTmClient()
    domain = bootstrap.active_domains()[0]
    # Mail.tm validates the local part more strictly than a normal email
    # provider; keep it short and alphanumeric so every active domain accepts it.
    address = f"pmcardio{secrets.token_hex(6)}@{domain}"
    password = f"Pmcardio-{secrets.token_urlsafe(18)}9"
    bootstrap.create_account(address, password)
    mailbox = MailTmMailbox(
        address=address,
        password=password,
        token=bootstrap.issue_token(address, password),
    )
    inbox = MailTmClient(mailbox.token)

    try:
        signup = cognito_sign_up(mailbox.address, mailbox.password)
        if not signup.get("UserConfirmed"):
            code = inbox.wait_for_code(timeout=mailbox_timeout)
            cognito_confirm_sign_up(mailbox.address, code)
        tokens = cognito_password_sign_in(mailbox.address, mailbox.password)
    except PMCardioError:
        raise
    except (MailTmError, OSError, ValueError) as exc:
        raise MailTmError(f"Test account onboarding failed: {exc}") from exc

    if not tokens.refresh_token:
        raise MailTmError("PMcardio did not return a refresh session for the test account.")
    return mailbox.address, tokens