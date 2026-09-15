#!/usr/bin/env python3
"""Production Telegram bot for the real PMcardio ECG workflow.

The bot uses Telegram only for message transport. ECG processing uses the
verified APK-compatible PMcardio API and its authenticated AI report flow.

Authentication:
    python3 pmcardio_api_test.py login
    # or configure PMCARDIO_TOKEN through secure secrets

Required Telegram secret:
    TELEGRAM_BOT_TOKEN

Run a credential check:
    python3 pmcardio_telegram_bot.py --check

Run the bot:
    python3 pmcardio_telegram_bot.py
"""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from typing import Any

from pmcardio_api_test import (
    cognito_confirm_sign_up,
    cognito_password_sign_in,
    cognito_resend_sign_up_code,
    cognito_sign_up,
    CognitoTokenSet,
    PMCardioClient,
    PMCardioError,
    refresh_cognito_tokens,
)
from pmcardio_mailtm_test import (
    MailTmError,
    create_verified_pmcardio_test_account,
)


class TelegramError(RuntimeError):
    """A Telegram Bot API failure without exposing the bot token."""


class HealthHandler(BaseHTTPRequestHandler):
    """Small production health endpoint for the always-running bot process."""

    def do_GET(self) -> None:
        if self.path not in {"/", "/api/healthz"}:
            self.send_error(404)
            return
        body = b'{"status":"ok","service":"pmcardio-telegram-bot"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: Any) -> None:
        return


def start_health_server() -> ThreadingHTTPServer | None:
    configured_port = os.environ.get("PORT")
    if not configured_port:
        return None
    try:
        port = int(configured_port)
    except ValueError as exc:
        raise RuntimeError("PORT must be an integer when configured.") from exc
    server = ThreadingHTTPServer(("0.0.0.0", port), HealthHandler)
    Thread(target=server.serve_forever, name="pmcardio-health", daemon=True).start()
    return server


class TelegramSessionStore:
    """Store only per-chat refresh tokens and the latest report ID."""

    def __init__(self, path: str | Path | None = None) -> None:
        configured = os.environ.get("PMCARDIO_TELEGRAM_SESSION_FILE")
        self.path = Path(
            path
            or configured
            or Path.home() / ".config" / "pmcardio" / "telegram-sessions.json"
        )

    def _load(self) -> dict[str, dict[str, str]]:
        if not self.path.is_file():
            return {}
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PMCardioError(f"Unable to read Telegram session file: {exc}") from exc
        if not isinstance(payload, dict):
            raise PMCardioError("Telegram session file has an invalid format.")
        return {
            str(chat_id): value
            for chat_id, value in payload.items()
            if isinstance(value, dict)
        }

    def _save(self, payload: dict[str, dict[str, str]]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(f"{self.path.suffix}.tmp-{os.getpid()}")
        temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        os.chmod(temporary, 0o600)
        os.replace(temporary, self.path)
        os.chmod(self.path, 0o600)

    def get(self, chat_id: int | str) -> dict[str, str] | None:
        return self._load().get(str(chat_id))

    def save_auth(self, chat_id: int | str, email: str, refresh_token: str) -> None:
        if not refresh_token:
            raise PMCardioError("PMcardio did not return a refresh token.")
        payload = self._load()
        current = payload.get(str(chat_id), {})
        payload[str(chat_id)] = {
            "email": email,
            "refresh_token": refresh_token,
            **({"client_device_id": current["client_device_id"]} if current.get("client_device_id") else {}),
            **({"onboarded": current["onboarded"]} if current.get("onboarded") else {}),
            **({"last_report_id": current["last_report_id"]} if current.get("last_report_id") else {}),
        }
        self._save(payload)

    def update_refresh_token(self, chat_id: int | str, refresh_token: str) -> None:
        payload = self._load()
        entry = payload.get(str(chat_id))
        if not entry:
            raise PMCardioError("Telegram chat has no saved PMcardio account.")
        entry["refresh_token"] = refresh_token
        self._save(payload)

    def save_report(self, chat_id: int | str, report_id: str) -> None:
        payload = self._load()
        entry = payload.setdefault(str(chat_id), {})
        entry["last_report_id"] = report_id
        self._save(payload)

    def mark_onboarded(self, chat_id: int | str, client_device_id: str) -> None:
        payload = self._load()
        entry = payload.get(str(chat_id))
        if not entry:
            raise PMCardioError("Telegram chat has no saved PMcardio account.")
        entry["onboarded"] = "1"
        entry["client_device_id"] = client_device_id
        self._save(payload)

    def clear(self, chat_id: int | str) -> None:
        payload = self._load()
        payload.pop(str(chat_id), None)
        self._save(payload)


class TelegramBot:
    def __init__(self, token: str, *, timeout: float = 35.0) -> None:
        if not token or ":" not in token:
            raise ValueError("TELEGRAM_BOT_TOKEN is missing or malformed.")
        self.token = token
        self.timeout = timeout
        self.api_url = f"https://api.telegram.org/bot{token}"
        self.file_url = f"https://api.telegram.org/file/bot{token}"

    def call(self, method: str, params: dict[str, Any] | None = None) -> Any:
        encoded = urllib.parse.urlencode(params or {}).encode("utf-8")
        request = urllib.request.Request(
            f"{self.api_url}/{method}",
            data=encoded,
            headers={"Accept": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code == 401:
                raise TelegramError("Telegram rejected the bot token.") from exc
            raise TelegramError(f"Telegram HTTP error {exc.code}.") from exc
        except (urllib.error.URLError, json.JSONDecodeError) as exc:
            raise TelegramError(f"Telegram request failed: {exc}") from exc

        if not isinstance(payload, dict) or not payload.get("ok"):
            detail = payload.get("description", "unknown Telegram API error")
            raise TelegramError(str(detail))
        return payload.get("result")

    def get_me(self) -> dict[str, Any]:
        result = self.call("getMe")
        return result if isinstance(result, dict) else {}

    def delete_webhook(self) -> None:
        self.call("deleteWebhook", {"drop_pending_updates": "false"})

    def get_updates(self, offset: int | None) -> list[dict[str, Any]]:
        params: dict[str, Any] = {"timeout": 25}
        if offset is not None:
            params["offset"] = offset
        result = self.call("getUpdates", params)
        return result if isinstance(result, list) else []

    def send_message(
        self,
        chat_id: int | str,
        text: str,
        *,
        parse_mode: str | None = None,
    ) -> None:
        for start in range(0, len(text), 4000):
            params: dict[str, Any] = {
                "chat_id": chat_id,
                "text": text[start : start + 4000],
            }
            if parse_mode:
                params["parse_mode"] = parse_mode
            self.call(
                "sendMessage",
                params,
            )

    def delete_message(self, chat_id: int | str, message_id: int) -> None:
        try:
            self.call(
                "deleteMessage",
                {"chat_id": chat_id, "message_id": message_id},
            )
        except TelegramError:
            # Deletion is a privacy improvement, not a requirement for the
            # authentication flow. Telegram may deny it in some chat types.
            return

    def send_document(
        self,
        chat_id: int | str,
        document: Path,
        *,
        caption: str | None = None,
        content_type: str = "application/pdf",
    ) -> None:
        boundary = f"----TelegramDocument{os.urandom(12).hex()}"
        chunks = [
            f"--{boundary}\r\n".encode(),
            b'Content-Disposition: form-data; name="chat_id"\r\n\r\n',
            str(chat_id).encode(),
            b"\r\n",
            f"--{boundary}\r\n".encode(),
            (
                f'Content-Disposition: form-data; name="document"; '
                f'filename="{document.name}"\r\n'
            ).encode(),
            f"Content-Type: {content_type}\r\n\r\n".encode(),
            document.read_bytes(),
            b"\r\n",
        ]
        if caption:
            chunks.extend(
                [
                    f"--{boundary}\r\n".encode(),
                    b'Content-Disposition: form-data; name="caption"\r\n\r\n',
                    caption.encode("utf-8"),
                    b"\r\n",
                ]
            )
        chunks.append(f"--{boundary}--\r\n".encode())
        request = urllib.request.Request(
            f"{self.api_url}/sendDocument",
            data=b"".join(chunks),
            headers={
                "Accept": "application/json",
                "Content-Type": f"multipart/form-data; boundary={boundary}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise TelegramError(f"Telegram document upload failed with HTTP {exc.code}.") from exc
        except (urllib.error.URLError, json.JSONDecodeError) as exc:
            raise TelegramError(f"Telegram document upload failed: {exc}") from exc
        if not isinstance(payload, dict) or not payload.get("ok"):
            detail = payload.get("description", "unknown Telegram API error")
            raise TelegramError(str(detail))

    def get_file_path(self, file_id: str) -> str:
        result = self.call("getFile", {"file_id": file_id})
        if not isinstance(result, dict) or not isinstance(result.get("file_path"), str):
            raise TelegramError("Telegram did not return a downloadable file path.")
        return result["file_path"]

    def download_file(self, file_path: str, target: Path) -> None:
        request = urllib.request.Request(
            f"{self.file_url}/{file_path}",
            headers={"Accept": "application/octet-stream"},
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                target.write_bytes(response.read())
        except urllib.error.HTTPError as exc:
            raise TelegramError(f"Telegram file download failed with HTTP {exc.code}.") from exc
        except urllib.error.URLError as exc:
            raise TelegramError(f"Telegram file download failed: {exc.reason}") from exc


def bot_from_environment() -> TelegramBot:
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    if not token:
        raise SystemExit(
            "TELEGRAM_BOT_TOKEN is not configured. Add it through secure secrets."
        )
    return TelegramBot(token)


def configured_chat_ids(environment_name: str) -> set[str]:
    raw = os.environ.get(environment_name, "")
    return {
        value.strip()
        for value in raw.split(",")
        if value.strip() and re.fullmatch(r"-?\d+", value.strip())
    }


def chat_is_allowed(chat_id: int | str) -> bool:
    allowed = configured_chat_ids("PMCARDIO_ALLOWED_CHAT_IDS")
    return str(chat_id) in allowed


def markdown_v2_link(label: str, url: str) -> str:
    """Create a Telegram MarkdownV2 inline link for a presigned URL."""

    safe_url = url.replace("\\", "\\\\").replace(")", "\\)")
    return f"[{label}]({safe_url})"


EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def client_for_chat(
    chat_id: int | str,
    store: TelegramSessionStore,
    active_tokens: dict[str, Any],
    *,
    require_onboarding: bool = True,
) -> PMCardioClient:
    key = str(chat_id)
    token_set = active_tokens.get(key)
    if (
        not isinstance(token_set, CognitoTokenSet)
        or token_set.expires_at is not None
        and token_set.expires_at <= time.time() + 60
    ):
        entry = store.get(chat_id)
        if not entry or not entry.get("refresh_token"):
            raise PMCardioError(
                "هذا الحساب غير مسجل. استخدم /signup email password أو /login email password."
            )
        if require_onboarding and entry.get("onboarded") != "1":
            raise PMCardioError(
                "حساب PMcardio يحتاج إعدادًا أوليًا قبل رفع ECG. "
                "استخدم /onboard الاسم_الأول الاسم_الأخير المهنة المؤسسة."
            )
        token_set = refresh_cognito_tokens(entry["refresh_token"])
        if token_set.refresh_token:
            store.update_refresh_token(chat_id, token_set.refresh_token)
        active_tokens[key] = token_set

    def refresh_for_request() -> str:
        entry = store.get(chat_id)
        if not entry or not entry.get("refresh_token"):
            raise PMCardioError("انتهت جلسة PMcardio. سجّل الدخول مرة أخرى.")
        refreshed = refresh_cognito_tokens(entry["refresh_token"])
        if refreshed.refresh_token:
            store.update_refresh_token(chat_id, refreshed.refresh_token)
        active_tokens[key] = refreshed
        return refreshed.access_token

    return PMCardioClient(
        token_set.access_token,
        refresh_access_token=refresh_for_request,
    )


def remember_token(
    chat_id: int | str,
    email: str,
    token_set: Any,
    store: TelegramSessionStore,
    active_tokens: dict[str, Any],
) -> None:
    if not token_set.refresh_token:
        raise PMCardioError("PMcardio did not return a refresh session for this account.")
    store.save_auth(chat_id, email, token_set.refresh_token)
    active_tokens[str(chat_id)] = token_set


def parse_command(text: str) -> tuple[str, list[str]]:
    parts = text.strip().split()
    if not parts:
        return "", []
    return parts[0].lower(), parts[1:]


def validate_signup_credentials(args: list[str]) -> tuple[str, str]:
    if len(args) != 2:
        raise ValueError("استخدم: /signup email@example.com Password123")
    email, password = args
    if not EMAIL_PATTERN.match(email):
        raise ValueError("أرسل بريدًا إلكترونيًا صحيحًا.")
    if (
        len(password) < 8
        or not re.search(r"[A-Z]", password)
        or not re.search(r"[a-z]", password)
        or not re.search(r"\d", password)
    ):
        raise ValueError("كلمة المرور يجب أن تكون 8 أحرف على الأقل وتحتوي حرفًا كبيرًا ورقمًا.")
    return email, password


def validate_onboarding_args(args: list[str]) -> tuple[str, str, str, str, str]:
    """Parse the real onboarding data required by the APK API.

    PMcardio requires country, given name, family name, and occupation.
    Institution is accepted when available but is optional upstream.
    """

    if len(args) not in (3, 4, 5):
        raise ValueError(
            "استخدم: /onboard FirstName LastName Occupation [Institution] "
            "أو أضف رمز الدولة أولًا: /onboard LB FirstName LastName Occupation [Institution]"
        )
    if len(args) in (3, 4):
        country = os.environ.get("PMCARDIO_COUNTRY", "LB")
        given_name, family_name, occupation = args[:3]
        institution = args[3] if len(args) == 4 else ""
    else:
        country, given_name, family_name, occupation, institution = args
    country = country.strip().upper()
    if len(country) != 2 or not country.isalpha():
        raise ValueError("رمز الدولة يجب أن يكون حرفين مثل LB.")
    if not all(value.strip() for value in (given_name, family_name, occupation)):
        raise ValueError("الاسم الأول والاسم الأخير والمهنة مطلوبة.")
    return country, given_name, family_name, occupation, institution


def parse_sse_text(payload: str) -> str:
    """Extract human-readable content from PMcardio's JSON/SSE chat response."""

    candidates: list[str] = []
    for line in payload.splitlines():
        if not line.startswith("data:"):
            continue
        raw = line[5:].strip()
        if not raw or raw == "[DONE]":
            continue
        try:
            value = json.loads(raw)
        except json.JSONDecodeError:
            candidates.append(raw)
            continue
        if isinstance(value, dict):
            for key in ("content", "text", "message", "answer"):
                if isinstance(value.get(key), str):
                    candidates.append(value[key])
                    break
        elif isinstance(value, str):
            candidates.append(value)
    if candidates:
        return "".join(candidates).strip()
    try:
        value = json.loads(payload)
    except json.JSONDecodeError:
        return payload.strip()
    if isinstance(value, dict):
        for key in ("content", "text", "message", "answer"):
            if isinstance(value.get(key), str):
                return value[key]
    return payload.strip()


def update_image(update: dict[str, Any]) -> tuple[str, str] | None:
    message = update.get("message")
    if not isinstance(message, dict):
        return None
    photos = message.get("photo")
    if isinstance(photos, list) and photos:
        largest = photos[-1]
        if isinstance(largest, dict) and isinstance(largest.get("file_id"), str):
            return largest["file_id"], "ecg.jpg"
    document = message.get("document")
    if isinstance(document, dict) and isinstance(document.get("file_id"), str):
        mime_type = str(document.get("mime_type", ""))
        file_name = str(document.get("file_name", "ecg.jpg"))
        if mime_type.startswith("image/") or Path(file_name).suffix.lower() in {
            ".jpg",
            ".jpeg",
            ".png",
            ".webp",
        }:
            return document["file_id"], file_name
    return None


def chat_id_from_update(update: dict[str, Any]) -> int | str | None:
    message = update.get("message")
    chat = message.get("chat") if isinstance(message, dict) else None
    if isinstance(chat, dict):
        return chat.get("id")
    return None


def is_private_chat(update: dict[str, Any]) -> bool:
    message = update.get("message")
    chat = message.get("chat") if isinstance(message, dict) else None
    return isinstance(chat, dict) and chat.get("type") == "private"


def mailtm_test_enabled(chat_id: int | str) -> bool:
    if os.environ.get("PMCARDIO_MAILTM_TEST_MODE") != "1":
        return False
    allowed_chat_ids = configured_chat_ids("PMCARDIO_TEST_CHAT_ID")
    return str(chat_id) in allowed_chat_ids


def message_id_from_update(update: dict[str, Any]) -> int | None:
    message = update.get("message")
    value = message.get("message_id") if isinstance(message, dict) else None
    return value if isinstance(value, int) else None


def report_summary(result: dict[str, Any]) -> tuple[str, str]:
    report = result.get("report")
    if not isinstance(report, dict):
        return "The API returned a report without structured details.", "unknown"

    status = str(report.get("data_status") or report.get("status") or "unknown")
    analysis = report.get("ai_analysis")
    if isinstance(analysis, dict):
        summary = str(
            analysis.get("summary")
            or analysis.get("interpretation")
            or analysis.get("conclusion")
            or "The AI report is ready for review."
        )
        mode = str(analysis.get("mode") or "PMcardio AI")
        return summary, f"{status} · {mode}"

    return "The report is ready for review in PMcardio.", status


def handle_update(
    bot: TelegramBot,
    update: dict[str, Any],
    *,
    session_store: TelegramSessionStore,
    active_tokens: dict[str, Any],
    pending_signups: dict[str, tuple[str, str]],
) -> None:
    chat_id = chat_id_from_update(update)
    if chat_id is None:
        return
    message = update.get("message")
    text = str(message.get("text", "")).strip() if isinstance(message, dict) else ""
    command, args = parse_command(text)
    if not chat_is_allowed(chat_id):
        if is_private_chat(update) and command in {"/start", "/help", "/chat-id"}:
            bot.send_message(
                chat_id,
                "هذا البوت مقيّد بقائمة سماح.\n"
                f"رقم هذه المحادثة هو: {chat_id}\n"
                "أرسل هذا الرقم إلى مسؤول البوت لإضافته، ثم أعد إرسال /start.",
            )
        return
    if command in {"/start", "/help"}:
        bot.send_message(
            chat_id,
            "هذا بوت PMcardio حقيقي.\n\n"
            "/signup email password — إنشاء حساب PMcardio وتأكيد البريد\n"
            "/test-signup — إنشاء حساب اختبار واحد عبر Mail.tm (وضع الاختبار فقط)\n"
            "/chat-id — عرض رقم هذه المحادثة لتقييد وضع الاختبار\n"
            "/verify 123456 — تأكيد رمز البريد\n"
            "/login email password — تسجيل الدخول\n"
             "/onboard FirstName LastName Occupation [Institution] — إكمال إعداد الحساب الحقيقي\n"
            "/logout — حذف جلسة هذا الحساب من البوت\n"
            "بعد تسجيل الدخول أرسل صورة ECG بصيغة JPG أو PNG أو WebP.\n"
            "/chat سؤالك — محادثة حقيقية حول آخر تقرير\n"
            "/history — قراءة محادثة آخر تقرير\n\n"
            "لا ترسل كلمة المرور في مجموعة عامة، ولا تعِد استخدامها في خدمة أخرى.\n"
            "التقرير ليس تشخيصًا طبيًا.",
        )
        return

    if command == "/chat-id":
        if is_private_chat(update):
            bot.send_message(chat_id, f"رقم هذه المحادثة: {chat_id}")
        else:
            bot.send_message(chat_id, "استخدم /chat-id في محادثة خاصة مع البوت.")
        return

    if command == "/test-signup":
        if not is_private_chat(update):
            bot.send_message(chat_id, "وضع الاختبار يعمل فقط في محادثة خاصة مع البوت.")
            return
        if not mailtm_test_enabled(chat_id):
            bot.send_message(
                chat_id,
                "تسجيل Mail.tm غير مفعّل. فعّل PMCARDIO_MAILTM_TEST_MODE=1 "
                "لتجربة حساب اختبار واحد فقط.",
            )
            return
        if session_store.get(chat_id):
            bot.send_message(
                chat_id,
                "لدى هذه المحادثة جلسة PMcardio محفوظة بالفعل. استخدم /logout أولًا.",
            )
            return
        bot.send_message(
            chat_id,
            "جارٍ إنشاء صندوق اختبار واحد وانتظار رسالة تأكيد PMcardio...",
        )
        try:
            email, token_set = create_verified_pmcardio_test_account()
            remember_token(chat_id, email, token_set, session_store, active_tokens)
            bot.send_message(
                chat_id,
                "اكتمل حساب الاختبار وتسجيل الدخول تلقائيًا. "
                "قبل أول صورة، أكمل إعداد PMcardio الحقيقي عبر:\n"
                "/onboard FirstName LastName Occupation [Institution]\n"
                f"البريد الاختباري: {email}",
            )
        except (MailTmError, PMCardioError, OSError, ValueError) as exc:
            bot.send_message(chat_id, f"تعذر إنشاء حساب الاختبار: {exc}")
        return

    if command == "/signup":
        if not is_private_chat(update):
            bot.send_message(chat_id, "لأمان الحساب، استخدم /signup في محادثة خاصة مع البوت.")
            return
        try:
            email, password = validate_signup_credentials(args)
            result = cognito_sign_up(email, password)
            if result.get("UserConfirmed"):
                token_set = cognito_password_sign_in(email, password)
                remember_token(
                    chat_id,
                    email,
                    token_set,
                    session_store,
                    active_tokens,
                )
                bot.send_message(
                    chat_id,
                    "تم إنشاء حساب PMcardio وتسجيل الدخول. "
                    "أكمل إعداد الحساب الحقيقي أولًا عبر:\n"
                    "/onboard FirstName LastName Occupation [Institution]",
                )
            else:
                pending_signups[str(chat_id)] = (email, password)
                bot.send_message(
                    chat_id,
                    "تم إنشاء الحساب. أرسل رمز التأكيد الذي وصلك على البريد عبر:\n"
                    "/verify 123456",
                )
            if message_id_from_update(update) is not None:
                bot.delete_message(chat_id, message_id_from_update(update) or 0)
        except (PMCardioError, ValueError) as exc:
            bot.send_message(chat_id, f"تعذر إنشاء الحساب: {exc}")
        return

    if command == "/onboard":
        if not is_private_chat(update):
            bot.send_message(chat_id, "لأمان الحساب، استخدم /onboard في محادثة خاصة مع البوت.")
            return
        try:
            country, given_name, family_name, occupation, institution = (
                validate_onboarding_args(args)
            )
            client = client_for_chat(
                chat_id,
                session_store,
                active_tokens,
                require_onboarding=False,
            )
            bot.send_message(chat_id, "جارٍ إرسال بيانات onboarding الحقيقية إلى PMcardio...")
            client_device_id = (
                session_store.get(chat_id) or {}
            ).get("client_device_id") or str(uuid.uuid4())
            client.onboard_user(
                country=country,
                given_name=given_name,
                family_name=family_name,
                occupation=occupation,
                institution_name=institution,
                client_device_id=client_device_id,
                preferred_language="en",
            )
            session_store.mark_onboarded(chat_id, client_device_id)
            bot.send_message(
                chat_id,
                "تم تجهيز حساب PMcardio الحقيقي بنجاح. "
                "أرسل صورة ECG الآن للتحليل والنتيجة من API التطبيق.",
            )
        except (PMCardioError, ValueError, OSError) as exc:
            bot.send_message(chat_id, f"فشل إعداد حساب PMcardio: {exc}")
        return

    if command == "/verify":
        if not is_private_chat(update):
            bot.send_message(chat_id, "لأمان الحساب، استخدم /verify في محادثة خاصة مع البوت.")
            return
        pending = pending_signups.get(str(chat_id))
        if not pending or len(args) != 1:
            bot.send_message(chat_id, "ابدأ بـ /signup ثم أرسل /verify 123456.")
            return
        email, password = pending
        try:
            cognito_confirm_sign_up(email, args[0])
            token_set = cognito_password_sign_in(email, password)
            remember_token(chat_id, email, token_set, session_store, active_tokens)
            pending_signups.pop(str(chat_id), None)
            bot.send_message(
                chat_id,
                "تم تأكيد البريد وتسجيل الدخول إلى PMcardio. "
                "أكمل إعداد الحساب الحقيقي أولًا عبر:\n"
                "/onboard FirstName LastName Occupation [Institution]",
            )
        except PMCardioError as exc:
            bot.send_message(chat_id, f"تعذر تأكيد الحساب: {exc}")
        return

    if command == "/resend":
        if not is_private_chat(update):
            bot.send_message(chat_id, "لأمان الحساب، استخدم /resend في محادثة خاصة مع البوت.")
            return
        pending = pending_signups.get(str(chat_id))
        if not pending:
            bot.send_message(chat_id, "لا يوجد تسجيل معلق لهذا الحساب.")
            return
        try:
            cognito_resend_sign_up_code(pending[0])
            bot.send_message(chat_id, "تم إرسال رمز تأكيد جديد.")
        except PMCardioError as exc:
            bot.send_message(chat_id, f"تعذر إعادة إرسال الرمز: {exc}")
        return

    if command == "/login":
        if not is_private_chat(update):
            bot.send_message(chat_id, "لأمان الحساب، استخدم /login في محادثة خاصة مع البوت.")
            return
        try:
            email, password = validate_signup_credentials(args)
            token_set = cognito_password_sign_in(email, password)
            remember_token(chat_id, email, token_set, session_store, active_tokens)
            bot.send_message(
                chat_id,
                "تم تسجيل الدخول إلى حساب PMcardio. "
                "إذا كان هذا الحساب جديدًا، أكمل الإعداد عبر:\n"
                "/onboard FirstName LastName Occupation [Institution]",
            )
            if message_id_from_update(update) is not None:
                bot.delete_message(chat_id, message_id_from_update(update) or 0)
        except (PMCardioError, ValueError) as exc:
            bot.send_message(chat_id, f"تعذر تسجيل الدخول: {exc}")
        return

    if command == "/logout":
        if not is_private_chat(update):
            bot.send_message(chat_id, "لأمان الحساب، استخدم /logout في محادثة خاصة مع البوت.")
            return
        active_tokens.pop(str(chat_id), None)
        pending_signups.pop(str(chat_id), None)
        session_store.clear(chat_id)
        bot.send_message(chat_id, "تم حذف جلسة PMcardio المحفوظة لهذا الحساب.")
        return

    if command in {"/chat", "/history"}:
        entry = session_store.get(chat_id)
        report_id = entry.get("last_report_id") if entry else None
        if not report_id:
            bot.send_message(chat_id, "أرسل صورة ECG أولًا لإنشاء تقرير.")
            return
        try:
            client = client_for_chat(chat_id, session_store, active_tokens)
            if command == "/history":
                response = json.dumps(
                    client.get_chat(report_id),
                    ensure_ascii=False,
                    indent=2,
                    default=str,
                )
            else:
                if not args:
                    bot.send_message(chat_id, "استخدم: /chat اشرح لي نتيجة التقرير")
                    return
                response = parse_sse_text(client.send_chat(report_id, " ".join(args)))
            bot.send_message(chat_id, response or "لم يرجع PMcardio ردًا نصيًا.")
        except (PMCardioError, ValueError) as exc:
            bot.send_message(chat_id, f"تعذر الوصول إلى محادثة PMcardio: {exc}")
        return

    image = update_image(update)
    if image is None:
        bot.send_message(chat_id, "أرسل صورة ECG أو استخدم /help.")
        return

    file_id, file_name = image
    try:
        client = client_for_chat(chat_id, session_store, active_tokens)
        bot.send_message(chat_id, "تم استلام الصورة. جارٍ رفع ECG إلى PMcardio وتحليلها...")
        with tempfile.TemporaryDirectory(prefix="pmcardio-telegram-") as directory:
            source = Path(directory) / Path(file_name).name
            if source.suffix.lower() not in {".jpg", ".jpeg", ".png", ".webp"}:
                source = source.with_suffix(".jpg")
            pdf_path = Path(directory) / "pmcardio-report.pdf"
            report_json_path = Path(directory) / "pmcardio-report.json"
            bot.download_file(bot.get_file_path(file_id), source)
            result = client.process_report([source])
            report_id = result["report_id"]
            session_store.save_report(chat_id, report_id)
            report_json_path.write_text(
                json.dumps(result, ensure_ascii=False, indent=2, default=str),
                encoding="utf-8",
            )
            pdf_error: str | None = None
            pdf_url: str | None = None
            for _ in range(12):
                try:
                    pdf_status = client.get_report_pdf_status(report_id)
                    candidate_url = (
                        pdf_status.get("pdf_report_url")
                        if isinstance(pdf_status, dict)
                        else None
                    )
                    if isinstance(candidate_url, str) and candidate_url:
                        pdf_url = candidate_url
                    client.download_report_pdf(report_id, pdf_path)
                    break
                except PMCardioError as exc:
                    pdf_error = str(exc)
                    time.sleep(2.5)

            summary, status = report_summary(result)
            message = (
                "اكتمل تحليل PMcardio الحقيقي.\n\n"
                f"الحالة: {status}\n"
                f"التحليل: {summary}\n\n"
                "يمكنك طرح سؤال عن التقرير باستخدام /chat.\n"
                "تنبيه: هذا التقرير ليس تشخيصًا طبيًا."
            )
            bot.send_message(chat_id, message)
            bot.send_document(
                chat_id,
                report_json_path,
                caption="كامل رد PMcardio بصيغة JSON",
                content_type="application/json",
            )
            if pdf_url:
                bot.send_message(
                    chat_id,
                    markdown_v2_link("فتح تقرير PDF", pdf_url),
                    parse_mode="MarkdownV2",
                )
            if pdf_path.is_file():
                bot.send_document(chat_id, pdf_path, caption="تقرير PMcardio PDF")
            elif pdf_error:
                bot.send_message(
                    chat_id,
                    "تقرير PDF غير جاهز حاليًا. أعد المحاولة بعد اكتمال تجهيز التقرير.",
                )
    except (PMCardioError, OSError, ValueError) as exc:
        bot.send_message(chat_id, f"فشل تنفيذ تحليل PMcardio الحقيقي: {exc}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Validate Telegram and PMcardio credentials, then exit.",
    )
    parser.add_argument(
        "--session-file",
        help="Per-Telegram-chat session file; defaults to ~/.config/pmcardio/telegram-sessions.json.",
    )
    args = parser.parse_args()

    bot = bot_from_environment()
    if args.check:
        info = bot.get_me()
        print(
            json.dumps(
                {
                    "telegram_authorized": True,
                    "bot_username": info.get("username"),
                    "can_read_messages": info.get("can_read_all_group_messages"),
                    "telegram_session_file": str(
                        TelegramSessionStore(args.session_file).path
                    ),
                    "pmcardio_authentication": "per-chat Cognito refresh sessions",
                    "email_verification": "PMcardio Cognito email delivery",
                },
                indent=2,
            )
        )
        return

    health_server = start_health_server()
    bot.delete_webhook()
    print("PMcardio Telegram bot is running in realtime long-polling mode.")
    offset: int | None = None
    session_store = TelegramSessionStore(args.session_file)
    active_tokens: dict[str, Any] = {}
    pending_signups: dict[str, tuple[str, str]] = {}
    stopping = False

    def request_stop(_signum: int, _frame: Any) -> None:
        nonlocal stopping
        stopping = True
        print("PMcardio Telegram bot is stopping.")

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)

    while not stopping:
        try:
            for update in bot.get_updates(offset):
                if stopping:
                    break
                update_id = update.get("update_id")
                if isinstance(update_id, int):
                    offset = update_id + 1
                try:
                    handle_update(
                        bot,
                        update,
                        session_store=session_store,
                        active_tokens=active_tokens,
                        pending_signups=pending_signups,
                    )
                except (OSError, TelegramError, PMCardioError, ValueError, RuntimeError) as exc:
                    chat_id = chat_id_from_update(update)
                    if chat_id is not None:
                        bot.send_message(
                            chat_id,
                            f"تعذر تنفيذ طلب PMcardio: {exc}",
                        )
        except TelegramError as exc:
            print(f"Telegram polling error: {exc}")
            time.sleep(5)

    if health_server is not None:
        health_server.shutdown()
    print("PMcardio Telegram bot stopped cleanly.")


if __name__ == "__main__":
    main()