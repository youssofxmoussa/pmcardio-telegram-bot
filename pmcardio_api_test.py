#!/usr/bin/env python3
"""Single-file PMcardio APK contract client and offline test.

Default usage never contacts PMcardio and never reads PMCARDIO_TOKEN:

    python pmcardio_api_test.py test
    python pmcardio_api_test.py describe
    python pmcardio_api_test.py stress 10000
    python pmcardio_api_test.py offline-workflow path/to/ecg.jpg
    python pmcardio_api_test.py login
    python pmcardio_api_test.py auth-workflow path/to/ecg.jpg

Live usage is explicit and requires an already-authorized token or a saved
Cognito refresh session:

    PMCARDIO_TOKEN='...' python pmcardio_api_test.py live-list
    PMCARDIO_TOKEN='...' python pmcardio_api_test.py live-workflow ecg-1.jpg

After one legitimate Hosted UI login, the `login` command saves only the
refresh token in a permission-restricted local session file. Future live
commands refresh the short-lived access token automatically.

This file contains endpoints confirmed in the PMcardio Individuals 3.14.0
APK and the captured PMcardio report-chat web flow.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import mimetypes
import os
import secrets
import re
import tempfile
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
import uuid
import webbrowser
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable


BASE_URL = "https://individuals.pmcardio.com"
API_PREFIX = "/api/"
COGNITO_DOMAIN = "https://login.individuals.pmcardio.com"
COGNITO_IDP_URL = "https://cognito-idp.eu-west-1.amazonaws.com/"
COGNITO_CLIENT_ID = "1po7kp4qg2ll9rte4gba3q07eu"
COGNITO_REDIRECT_URI = "pmind://callback/"
COGNITO_SCOPES = (
    "email openid profile aws.cognito.signin.user.admin"
)
ACS_MODULE_VERSION = "V4_0"
APK_USER_AGENT = (
    "PMcardioIndividuals/3.14.0 "
    "(Android; 11; TECNO MOBILE LIMITED TECNO KG5k) Build/461557953"
)
ECG_LAYOUTS = {
    "single_page",
    "3x2_standard",
    "6x1_standard",
    "3x1_standard",
    "3x2_cabrera",
    "6x1_cabrera",
    "3x1_cabrera",
}
PAPER_SPEEDS = {25.0, 50.0}
VOLTAGE_GAINS = {5.0, 10.0}
IMAGE_TYPES = {
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
    ".webp": "image/webp",
}


class PMCardioError(RuntimeError):
    """A local validation error or an upstream request failure."""


def create_pkce_pair() -> tuple[str, str]:
    """Return a PKCE verifier and S256 challenge for Cognito Hosted UI."""

    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()
    ).rstrip(b"=").decode("ascii")
    return verifier, challenge


def cognito_authorize_url(state: str, code_challenge: str) -> str:
    query = urllib.parse.urlencode(
        {
            "client_id": COGNITO_CLIENT_ID,
            "response_type": "code",
            "scope": COGNITO_SCOPES,
            "redirect_uri": COGNITO_REDIRECT_URI,
            "state": state,
            "code_challenge_method": "S256",
            "code_challenge": code_challenge,
        }
    )
    return f"{COGNITO_DOMAIN}/oauth2/authorize?{query}"


@dataclass(frozen=True)
class CognitoTokenSet:
    """Tokens returned by Cognito without exposing them in command output."""

    access_token: str
    refresh_token: str | None
    expires_at: float | None


def _cognito_token_request(form_values: dict[str, str]) -> CognitoTokenSet:
    form = urllib.parse.urlencode(form_values).encode("utf-8")
    request = urllib.request.Request(
        f"{COGNITO_DOMAIN}/oauth2/token",
        data=form,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=45.0) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:500]
        raise PMCardioError(
            f"Cognito token exchange returned HTTP {exc.code}: {detail}"
        ) from exc
    except (urllib.error.URLError, json.JSONDecodeError) as exc:
        raise PMCardioError(f"Cognito token exchange failed: {exc}") from exc

    access_token = payload.get("access_token")
    if not isinstance(access_token, str) or not access_token:
        raise PMCardioError("Cognito response did not contain an access token.")
    expires_in = payload.get("expires_in")
    expires_at = (
        time.time() + float(expires_in)
        if isinstance(expires_in, (int, float, str)) and str(expires_in)
        else None
    )
    refresh_token = payload.get("refresh_token")
    return CognitoTokenSet(
        access_token=access_token,
        refresh_token=refresh_token if isinstance(refresh_token, str) else None,
        expires_at=expires_at,
    )


def _cognito_idp_request(target: str, payload: dict[str, Any]) -> dict[str, Any]:
    request = urllib.request.Request(
        COGNITO_IDP_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Accept": "application/json",
            "Content-Type": "application/x-amz-json-1.1",
            "X-Amz-Target": f"AWSCognitoIdentityProviderService.{target}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=45.0) as response:
            decoded = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:500]
        try:
            error_payload = json.loads(detail)
        except json.JSONDecodeError:
            error_payload = {}
        error_code = str(error_payload.get("__type", "")).rsplit("#", 1)[-1]
        message = error_payload.get("message") or detail
        raise PMCardioError(
            f"Cognito {target} failed ({error_code or exc.code}): {message}"
        ) from exc
    except (urllib.error.URLError, json.JSONDecodeError) as exc:
        raise PMCardioError(f"Cognito {target} request failed: {exc}") from exc
    if not isinstance(decoded, dict):
        raise PMCardioError(f"Cognito {target} returned an invalid response.")
    return decoded


def cognito_sign_up(email: str, password: str) -> dict[str, Any]:
    """Create a PMcardio Cognito account without persisting the password."""

    return _cognito_idp_request(
        "SignUp",
        {
            "ClientId": COGNITO_CLIENT_ID,
            "Username": email,
            "Password": password,
            "UserAttributes": [{"Name": "email", "Value": email}],
        },
    )


def cognito_confirm_sign_up(email: str, confirmation_code: str) -> dict[str, Any]:
    return _cognito_idp_request(
        "ConfirmSignUp",
        {
            "ClientId": COGNITO_CLIENT_ID,
            "Username": email,
            "ConfirmationCode": confirmation_code,
        },
    )


def cognito_resend_sign_up_code(email: str) -> dict[str, Any]:
    return _cognito_idp_request(
        "ResendConfirmationCode",
        {
            "ClientId": COGNITO_CLIENT_ID,
            "Username": email,
        },
    )


def cognito_password_sign_in(email: str, password: str) -> CognitoTokenSet:
    response = _cognito_idp_request(
        "InitiateAuth",
        {
            "AuthFlow": "USER_PASSWORD_AUTH",
            "ClientId": COGNITO_CLIENT_ID,
            "AuthParameters": {
                "USERNAME": email,
                "PASSWORD": password,
            },
        },
    )
    if response.get("ChallengeName"):
        raise PMCardioError(
            f"Cognito requires unsupported challenge {response['ChallengeName']}."
        )
    result = response.get("AuthenticationResult")
    if not isinstance(result, dict) or not result.get("AccessToken"):
        raise PMCardioError("Cognito sign-in did not return an access token.")
    return CognitoTokenSet(
        access_token=str(result["AccessToken"]),
        refresh_token=(
            str(result["RefreshToken"]) if result.get("RefreshToken") else None
        ),
        expires_at=(
            time.time() + float(result["ExpiresIn"])
            if result.get("ExpiresIn")
            else None
        ),
    )


def exchange_cognito_code_tokens(
    callback_url: str, verifier: str, state: str
) -> CognitoTokenSet:
    parsed = urllib.parse.urlparse(callback_url)
    values = urllib.parse.parse_qs(parsed.query)
    returned_state = values.get("state", [None])[0]
    if returned_state != state:
        raise PMCardioError("Cognito callback state did not match.")
    if values.get("error"):
        detail = values.get("error_description", values["error"])[0]
        raise PMCardioError(f"Cognito login failed: {detail}")
    code = values.get("code", [None])[0]
    if not code:
        raise PMCardioError("Cognito callback did not contain an authorization code.")

    return _cognito_token_request(
        {
            "grant_type": "authorization_code",
            "client_id": COGNITO_CLIENT_ID,
            "code": code,
            "redirect_uri": COGNITO_REDIRECT_URI,
            "code_verifier": verifier,
        }
    )


def exchange_cognito_code(callback_url: str, verifier: str, state: str) -> str:
    """Backward-compatible access-token-only wrapper."""

    return exchange_cognito_code_tokens(callback_url, verifier, state).access_token


def refresh_cognito_tokens(refresh_token: str) -> CognitoTokenSet:
    if not refresh_token.strip():
        raise PMCardioError("Cognito refresh token is empty.")
    token_set = _cognito_token_request(
        {
            "grant_type": "refresh_token",
            "client_id": COGNITO_CLIENT_ID,
            "refresh_token": refresh_token,
        }
    )
    return CognitoTokenSet(
        access_token=token_set.access_token,
        refresh_token=token_set.refresh_token or refresh_token,
        expires_at=token_set.expires_at,
    )


class CognitoSessionStore:
    """Persist only a refresh token outside the project workspace."""

    def __init__(self, path: str | Path | None = None) -> None:
        configured = os.environ.get("PMCARDIO_SESSION_FILE")
        self.path = Path(path or configured or Path.home() / ".config" / "pmcardio" / "session.json")

    def load_refresh_token(self) -> str | None:
        env_token = os.environ.get("PMCARDIO_REFRESH_TOKEN")
        if env_token:
            return env_token
        if not self.path.is_file():
            return None
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PMCardioError(
                f"Unable to read Cognito session file {self.path}: {exc}"
            ) from exc
        refresh_token = payload.get("refresh_token") if isinstance(payload, dict) else None
        if not isinstance(refresh_token, str) or not refresh_token:
            raise PMCardioError(f"Cognito session file {self.path} has no refresh token.")
        return refresh_token

    def save_refresh_token(self, refresh_token: str) -> None:
        if not refresh_token:
            raise PMCardioError(
                "Cognito did not return a refresh token; automatic login is unavailable "
                "for this client configuration."
            )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(f"{self.path.suffix}.tmp-{os.getpid()}")
        temporary.write_text(
            json.dumps(
                {
                    "provider": "pmcardio-cognito",
                    "client_id": COGNITO_CLIENT_ID,
                    "refresh_token": refresh_token,
                }
            )
            + "\n",
            encoding="utf-8",
        )
        os.chmod(temporary, 0o600)
        os.replace(temporary, self.path)
        os.chmod(self.path, 0o600)


def automated_access_token(session_file: str | Path | None = None) -> str:
    """Refresh a saved Cognito session, falling back to PMCARDIO_TOKEN."""

    store = CognitoSessionStore(session_file)
    refresh_token = store.load_refresh_token()
    if refresh_token:
        try:
            return refresh_cognito_tokens(refresh_token).access_token
        except PMCardioError as exc:
            raise PMCardioError(
                "Saved Cognito session could not be refreshed. Run `login` again."
            ) from exc

    token = os.environ.get("PMCARDIO_TOKEN")
    if not token:
        raise PMCardioError(
            "No authorized PMcardio session found. Run `python3 pmcardio_api_test.py login` "
            "once, or configure PMCARDIO_TOKEN."
        )
    return token


@dataclass(frozen=True)
class HTTPResponse:
    status: int
    headers: dict[str, str]
    body: bytes


Transport = Callable[
    [str, str, dict[str, str], bytes | None, float],
    HTTPResponse,
]


def multipart_body(
    fields: Iterable[tuple[str, str]],
    images: Iterable[tuple[str, str, bytes]],
    rotations: Iterable[int] = (),
) -> tuple[bytes, str]:
    """Build the repeated-field multipart body used by the Android client."""

    boundary = f"----PMCardioAPKContract{uuid.uuid4().hex}"
    chunks: list[bytes] = []

    def add_field(name: str, value: str) -> None:
        chunks.extend(
            [
                f"--{boundary}\r\n".encode(),
                f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode(),
                value.encode(),
                b"\r\n",
            ]
        )

    def add_file(name: str, file_name: str, content_type: str, data: bytes) -> None:
        chunks.extend(
            [
                f"--{boundary}\r\n".encode(),
                (
                    f'Content-Disposition: form-data; name="{name}"; '
                    f'filename="{file_name}"\r\n'
                ).encode(),
                f"Content-Type: {content_type}\r\n\r\n".encode(),
                data,
                b"\r\n",
            ]
        )

    ordered_fields = list(fields)
    # Retrofit receives the parameters in this order: ecg_layout, images,
    # paper_speed, voltage_gain, acs_module_version, rotations.
    for name, value in ordered_fields:
        if name == "ecg_layout":
            add_field(name, value)
    for file_name, content_type, data in images:
        add_file("images", file_name, content_type, data)
    for name, value in ordered_fields:
        if name != "ecg_layout":
            add_field(name, value)
    for rotation in rotations:
        add_field("rotations", str(rotation))

    chunks.append(f"--{boundary}--\r\n".encode())
    return b"".join(chunks), f"multipart/form-data; boundary={boundary}"


def json_body(response: HTTPResponse) -> Any:
    try:
        return json.loads(response.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PMCardioError(
            f"Expected JSON but received {response.body[:300]!r}"
        ) from exc


class PMCardioClient:
    """The verified APK API surface.

    Pass transport=fake_transport for offline testing. In live mode, a missing
    token is rejected before any network request is attempted.
    """

    def __init__(
        self,
        token: str | None = None,
        *,
        base_url: str = BASE_URL,
        timeout: float = 45.0,
        transport: Transport | None = None,
        refresh_access_token: Callable[[], str] | None = None,
    ) -> None:
        if token and token.lower().startswith("bearer "):
            raise ValueError("Pass only the token, without the 'Bearer ' prefix.")
        self.token = token
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.transport = transport or self._urllib_transport
        self.offline_transport = transport is not None
        self.refresh_access_token = refresh_access_token

    def _headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        headers = {
            "Accept": "application/json",
            "User-Agent": APK_USER_AGENT,
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        headers.update(extra or {})
        return headers

    @staticmethod
    def _urllib_transport(
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes | None,
        timeout: float,
    ) -> HTTPResponse:
        request = urllib.request.Request(
            url,
            data=body,
            headers=headers,
            method=method,
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return HTTPResponse(
                    response.status,
                    dict(response.headers.items()),
                    response.read(),
                )
        except urllib.error.HTTPError as exc:
            return HTTPResponse(
                exc.code,
                dict(exc.headers.items()),
                exc.read(),
            )
        except urllib.error.URLError as exc:
            raise PMCardioError(f"Request failed: {exc.reason}") from exc

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
        expected: tuple[int, ...] = (200,),
        absolute_url: bool = False,
    ) -> HTTPResponse:
        if not self.offline_transport and not self.token and not absolute_url:
            raise PMCardioError(
                "Live PMcardio calls are disabled without PMCARDIO_TOKEN. "
                "Use `python pmcardio_api_test.py test` for offline tests."
            )
        url = path if absolute_url else f"{self.base_url}{path}"
        if params:
            url += "?" + urllib.parse.urlencode(params)
        refreshed = False
        while True:
            request_headers = self._headers(headers)
            if absolute_url:
                # S3 presigned URLs already carry their own authentication in
                # the query string. Sending the PMcardio Bearer token too
                # makes S3 reject the request with "Only one auth mechanism".
                request_headers.pop("Authorization", None)
            response = self.transport(
                method,
                url,
                request_headers,
                body,
                self.timeout,
            )
            if (
                response.status == 401
                and not refreshed
                and self.refresh_access_token is not None
                and not self.offline_transport
            ):
                new_token = self.refresh_access_token()
                if not new_token:
                    raise PMCardioError(
                        "PMcardio authentication expired and refresh returned no token."
                    )
                self.token = new_token
                refreshed = True
                continue
            break
        if response.status not in expected:
            raise PMCardioError(
                f"{method} {url} returned unexpected HTTP {response.status}: "
                f"{response.body[:500]!r}"
            )
        return response

    def _json_request(self, method: str, path: str, **kwargs: Any) -> Any:
        response = self._request(method, path, **kwargs)
        return None if not response.body else json_body(response)

    @staticmethod
    def _quote(value: str) -> str:
        return urllib.parse.quote(value, safe="")

    @staticmethod
    def _validate_upload_options(
        ecg_layout: str,
        paper_speed: float,
        voltage_gain: float,
        acs_module_version: str,
    ) -> None:
        if ecg_layout not in ECG_LAYOUTS:
            raise ValueError(f"Unsupported ECG layout: {ecg_layout}")
        if float(paper_speed) not in PAPER_SPEEDS:
            raise ValueError("paper_speed must be 25.0 or 50.0")
        if float(voltage_gain) not in VOLTAGE_GAINS:
            raise ValueError("voltage_gain must be 5.0 or 10.0")
        if acs_module_version != ACS_MODULE_VERSION:
            raise ValueError("acs_module_version must be V4_0")

    def upload_reports(
        self,
        image_paths: Iterable[str | Path],
        *,
        ecg_layout: str = "single_page",
        paper_speed: float = 25.0,
        voltage_gain: float = 10.0,
        acs_module_version: str = ACS_MODULE_VERSION,
        rotations: Iterable[int] = (),
    ) -> Any:
        paths = [Path(path) for path in image_paths]
        if not paths:
            raise ValueError("At least one ECG image is required.")
        if len(paths) > 10:
            raise ValueError("The APK upload contract allows at most 10 images.")
        self._validate_upload_options(
            ecg_layout, paper_speed, voltage_gain, acs_module_version
        )
        images: list[tuple[str, str, bytes]] = []
        for path in paths:
            if not path.is_file():
                raise FileNotFoundError(path)
            content_type = IMAGE_TYPES.get(path.suffix.lower())
            if not content_type:
                raise ValueError(f"Unsupported ECG image type: {path.suffix}")
            images.append((path.name, content_type, path.read_bytes()))

        body, content_type = multipart_body(
            [
                ("ecg_layout", ecg_layout),
                ("paper_speed", str(float(paper_speed))),
                ("voltage_gain", str(float(voltage_gain))),
                ("acs_module_version", acs_module_version),
            ],
            images,
            rotations,
        )
        return self._json_request(
            "POST",
            f"{API_PREFIX}v1/reports",
            body=body,
            headers={"Content-Type": content_type},
            expected=(200, 201, 202),
        )

    def upload_report(self, image_path: str | Path, **options: Any) -> Any:
        return self.upload_reports([image_path], **options)

    def list_reports(self, *, size: int = 20, number: int = 1) -> Any:
        return self._json_request(
            "GET",
            f"{API_PREFIX}v1/reports",
            params={"size": size, "number": number},
        )

    def get_report(self, report_id: str) -> Any:
        return self._json_request(
            "GET",
            f"{API_PREFIX}v1/reports/{self._quote(report_id)}",
        )

    def wait_for_report(
        self,
        report_id: str,
        *,
        poll_interval: float = 5.0,
        max_wait: float = 300.0,
    ) -> Any:
        """Poll the APK report endpoint until the AI result is available."""

        deadline = time.monotonic() + max_wait
        last_payload: Any = None
        while time.monotonic() < deadline:
            last_payload = self.get_report(report_id)
            if not isinstance(last_payload, dict):
                return last_payload
            status = str(
                last_payload.get("data_status")
                or last_payload.get("status")
                or last_payload.get("state")
                or ""
            ).lower()
            if status in {"failed", "error", "rejected"}:
                raise PMCardioError(f"Report processing failed: {last_payload}")
            if status not in {
                "pending",
                "processing",
                "created",
                "queued",
                "in_progress",
            }:
                return last_payload
            time.sleep(max(0.1, poll_interval))
        raise PMCardioError(
            f"Report {report_id} was not ready within {max_wait:.0f} seconds. "
            f"Last response: {json.dumps(last_payload, default=str)[:500]}"
        )

    def get_report_pdf_status(self, report_id: str) -> Any:
        return self._json_request(
            "GET",
            f"{API_PREFIX}v1/reports/{self._quote(report_id)}/pdf",
        )

    def download_report_pdf(self, report_id: str, output_path: str | Path) -> Path:
        status = self.get_report_pdf_status(report_id)
        url = status.get("pdf_report_url") if isinstance(status, dict) else None
        if not url:
            state = status.get("data_status", "not ready") if isinstance(status, dict) else "not ready"
            raise PMCardioError(f"PDF is {str(state).lower()}; no pdf_report_url was returned.")
        response = self._request(
            "GET",
            str(url),
            headers={"Accept": "application/pdf"},
            absolute_url=True,
        )
        target = Path(output_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(response.body)
        return target

    def submit_feedback(
        self, report_id: str, entity_type: str, payload: dict[str, Any]
    ) -> Any:
        return self._json_request(
            "POST",
            f"{API_PREFIX}v1/reports/{self._quote(report_id)}/{self._quote(entity_type)}/feedback",
            body=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            expected=(200, 201, 202, 204),
        )

    def update_acs_module(
        self, report_id: str, payload: dict[str, Any]
    ) -> Any:
        return self._json_request(
            "PUT",
            f"{API_PREFIX}v1/reports/{self._quote(report_id)}/acs_module",
            body=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            expected=(200, 201, 202),
        )

    def get_user(self) -> Any:
        return self._json_request("GET", f"{API_PREFIX}v1/users/me")

    def get_chat(self, report_id: str) -> Any:
        return self._json_request(
            "GET",
            f"{API_PREFIX}v1/reports/{self._quote(report_id)}/chat",
        )

    def send_chat(self, report_id: str, content: str) -> str:
        if not content.strip():
            raise ValueError("Chat content cannot be empty.")
        response = self._request(
            "POST",
            f"{API_PREFIX}v1/reports/{self._quote(report_id)}/chat",
            body=json.dumps(
                {
                    "content": content,
                    "client_message_id": str(uuid.uuid4()),
                }
            ).encode("utf-8"),
            headers={
                "Accept": "text/event-stream, application/json",
                "Content-Type": "application/json",
            },
            expected=(200, 201, 202),
        )
        return response.body.decode("utf-8", errors="replace")

    def patch_user(self, payload: dict[str, Any]) -> Any:
        return self._json_request(
            "PATCH",
            f"{API_PREFIX}v1/users/me",
            body=json.dumps(payload).encode(),
            headers={"Content-Type": "application/merge-patch+json"},
            expected=(200, 201, 202, 204),
        )

    def update_user(self, payload: dict[str, Any]) -> Any:
        return self._json_request(
            "PUT",
            f"{API_PREFIX}v1/users/me",
            body=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            expected=(200, 201, 202, 204),
        )

    def onboard_user(
        self,
        *,
        country: str,
        family_name: str,
        given_name: str,
        occupation: str,
        institution_name: str,
        client_device_id: str | None = None,
        preferred_language: str | None = "en",
    ) -> Any:
        """Complete the same required account setup used by the Android app."""

        values = {
            "country": country.strip().upper(),
            "family_name": family_name.strip(),
            "given_name": given_name.strip(),
            "occupation": occupation.strip(),
        }
        if not all(values.values()):
            raise ValueError(
                "country, family_name, given_name, and occupation are required."
            )
        if client_device_id:
            values["client_device_id"] = client_device_id.strip()
        if institution_name and institution_name.strip():
            values["institution_name"] = institution_name.strip()
        if preferred_language:
            values["preferred_language"] = preferred_language.strip().lower()
        return self.update_user(values)

    def get_app_rating(self) -> Any:
        return self._json_request("GET", f"{API_PREFIX}v1/users/me/app-rating")

    def put_app_rating(self, payload: dict[str, Any]) -> Any:
        return self._json_request(
            "PUT",
            f"{API_PREFIX}v1/users/me/app-rating",
            body=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            expected=(200, 202, 204),
        )

    def get_countries(self) -> Any:
        return self._json_request("GET", f"{API_PREFIX}v1/countries")

    def get_onboarding_institutions(
        self,
        *,
        search: str | None = None,
        country: str | None = None,
        limit: int | None = None,
    ) -> Any:
        params: dict[str, Any] = {}
        if search is not None:
            params["search"] = search
        if country is not None:
            params["country"] = country
        if limit is not None:
            params["limit"] = limit
        return self._json_request(
            "GET",
            f"{API_PREFIX}v1/onboarding/institutions",
            params=params,
        )

    def post_referral(self, payload: dict[str, Any]) -> Any:
        return self._json_request(
            "POST",
            f"{API_PREFIX}v1/users/me/referral",
            body=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            expected=(200, 201, 202, 204),
        )

    def claim_referral_reward(self) -> Any:
        return self._json_request(
            "POST",
            f"{API_PREFIX}v1/users/me/referral/reward",
            expected=(200, 201, 202, 204),
        )

    def accept_disclaimer(
        self, disclaimer_id: str, payload: dict[str, Any]
    ) -> Any:
        return self._json_request(
            "POST",
            f"{API_PREFIX}v1/users/me/disclaimer/{self._quote(disclaimer_id)}/accept",
            body=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            expected=(200, 201, 202, 204),
        )

    def sync_entitlements(self) -> Any:
        return self._json_request(
            "POST",
            f"{API_PREFIX}v1/users/me/entitlements/sync",
            expected=(200, 201, 202, 204),
        )

    def login_intercom(self) -> Any:
        return self._json_request(
            "POST",
            f"{API_PREFIX}v1/users/me/login-intercom",
            expected=(200, 201, 202),
        )

    def get_sample_report(self, output_path: str | Path) -> Path:
        response = self._request(
            "GET",
            f"{API_PREFIX}assets/sample_report.pdf",
            headers={"Accept": "application/pdf"},
        )
        target = Path(output_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(response.body)
        return target

    def process_report(
        self,
        image_paths: Iterable[str | Path],
        *,
        pdf_output: str | Path | None = None,
        **upload_options: Any,
    ) -> dict[str, Any]:
        upload = self.upload_reports(image_paths, **upload_options)
        report_id = extract_report_id(upload)
        result = {
            "report_id": report_id,
            "upload": upload,
            "report": self.wait_for_report(report_id),
        }
        if pdf_output:
            result["pdf_path"] = str(self.download_report_pdf(report_id, pdf_output))
        return result


def extract_report_id(payload: Any) -> str:
    if isinstance(payload, dict):
        for key in ("id", "report_id", "reportId"):
            if payload.get(key):
                return str(payload[key])
        if isinstance(payload.get("report"), dict):
            return extract_report_id(payload["report"])
    raise PMCardioError("Upload response did not contain report_id/reportId.")


class FakeTransport:
    """Offline transport that records every request and returns fixture data."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, str], bytes | None]] = []

    def __call__(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes | None,
        _timeout: float,
    ) -> HTTPResponse:
        self.calls.append((method, url, headers, body))
        path = urllib.parse.urlparse(url).path
        if path.endswith("/pdf") and method == "GET":
            return HTTPResponse(
                200,
                {"Content-Type": "application/json"},
                json.dumps(
                    {
                        "data_status": "READY",
                        "pdf_report_id": "pdf-1",
                        "pdf_report_url": "https://fake.invalid/report.pdf",
                    }
                ).encode(),
            )
        if path.endswith("/report.pdf"):
            return HTTPResponse(200, {"Content-Type": "application/pdf"}, b"%PDF-fake")
        if path.endswith("/reports") and method == "POST":
            return HTTPResponse(
                201,
                {"Content-Type": "application/json"},
                b'{"report_id":"report-1","report_name":"fixture"}',
            )
        if path.endswith("/reports") and method == "GET":
            return HTTPResponse(
                200,
                {"Content-Type": "application/json"},
                b'{"hasNext":false,"hasPrevious":false,"pageNumber":1,"reports":[],"total":0}',
            )
        if path.endswith("/reports/report-1"):
            return HTTPResponse(
                200,
                {"Content-Type": "application/json"},
                b'{"report_id":"report-1","data_status":"READY"}',
            )
        return HTTPResponse(200, {"Content-Type": "application/json"}, b"{}")


class OfflineContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.transport = FakeTransport()
        self.client = PMCardioClient(transport=self.transport)

    def test_no_token_is_used_in_offline_upload(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first.jpg"
            second = Path(directory) / "second.png"
            first.write_bytes(b"jpeg-fixture")
            second.write_bytes(b"png-fixture")
            result = self.client.upload_reports(
                [first, second],
                ecg_layout="3x2_cabrera",
                paper_speed=50.0,
                voltage_gain=5.0,
                rotations=[0, 90],
            )

        self.assertEqual(result["report_id"], "report-1")
        method, url, headers, body = self.transport.calls[0]
        self.assertEqual(method, "POST")
        self.assertEqual(url, f"{BASE_URL}/api/v1/reports")
        self.assertNotIn("Authorization", headers)
        self.assertIsNotNone(body)
        assert body is not None
        self.assertEqual(body.count(b'name="images"'), 2)
        self.assertEqual(body.count(b'name="rotations"'), 2)
        self.assertIn(b"3x2_cabrera", body)
        self.assertIn(b"50.0", body)
        self.assertIn(b"5.0", body)
        self.assertIn(b"V4_0", body)

    def test_verified_report_workflow_and_pdf_status(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "ecg.webp"
            image.write_bytes(b"webp-fixture")
            output = Path(directory) / "report.pdf"
            result = self.client.process_report([image], pdf_output=output)
            self.assertEqual(result["report_id"], "report-1")
            self.assertEqual(output.read_bytes(), b"%PDF-fake")

        paths = [urllib.parse.urlparse(call[1]).path for call in self.transport.calls]
        self.assertIn("/api/v1/reports/report-1", paths)
        self.assertIn("/api/v1/reports/report-1/pdf", paths)
        self.assertIn("/report.pdf", paths)

    def test_presigned_pdf_url_does_not_receive_bearer_auth(self) -> None:
        client = PMCardioClient(token="cognito-token", transport=self.transport)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.pdf"
            client.download_report_pdf("report-1", output)

        pdf_calls = [call for call in self.transport.calls if "/report.pdf" in call[1]]
        self.assertEqual(len(pdf_calls), 1)
        self.assertNotIn("Authorization", pdf_calls[0][2])

    def test_missing_token_blocks_live_transport(self) -> None:
        real_client = PMCardioClient(token=None)
        with self.assertRaisesRegex(PMCardioError, "PMCARDIO_TOKEN"):
            real_client.list_reports()

    def test_report_chat_contract(self) -> None:
        self.client.get_chat("report-1")
        self.client.send_chat("report-1", "Explain the findings.")
        chat_calls = [
            call for call in self.transport.calls if "/chat" in call[1]
        ]
        self.assertEqual(len(chat_calls), 2)
        self.assertEqual(chat_calls[0][0], "GET")
        self.assertEqual(chat_calls[1][0], "POST")
        self.assertIn(b"Explain the findings.", chat_calls[1][3] or b"")

    def test_extracted_enum_validation(self) -> None:
        with self.assertRaises(ValueError):
            self.client.upload_report("does-not-matter.jpg", ecg_layout="12_lead")
        with self.assertRaises(ValueError):
            self.client.upload_report("does-not-matter.jpg", paper_speed=100.0)


def print_description() -> None:
    endpoints = [
        "POST /api/v1/reports (multipart upload)",
        "GET  /api/v1/reports?size=<size>&number=<number>",
        "GET  /api/v1/reports/{report_id}",
        "GET  /api/v1/reports/{report_id}/pdf (JSON status + pdf_report_url)",
        "POST /api/v1/reports/{report_id}/{entity_type}/feedback",
        "PUT  /api/v1/reports/{report_id}/acs_module",
        "GET  /api/v1/users/me",
        "GET  /api/v1/reports/{report_id}/chat",
        "POST /api/v1/reports/{report_id}/chat",
        "PATCH /api/v1/users/me",
        "PUT  /api/v1/users/me",
        "GET  /api/v1/users/me/app-rating",
        "PUT  /api/v1/users/me/app-rating",
        "POST /api/v1/users/me/referral",
        "POST /api/v1/users/me/referral/reward",
        "POST /api/v1/users/me/disclaimer/{disclaimer_id}/accept",
        "POST /api/v1/users/me/entitlements/sync",
        "POST /api/v1/users/me/login-intercom",
        "GET  /api/v1/countries",
        "GET  /api/v1/onboarding/institutions",
        "GET  /api/assets/sample_report.pdf",
    ]
    print("Verified PMcardio APK endpoints:")
    print("\n".join(f"  {endpoint}" for endpoint in endpoints))
    print("\nOffline test mode does not read PMCARDIO_TOKEN or PMCARDIO_REFRESH_TOKEN and makes no network calls.")
    print("Run `python3 pmcardio_api_test.py login` once to enable automatic Cognito refresh for live commands.")
    print("Report chat follows the captured PMcardio web-platform request flow.")


def live_client(session_file: str | Path | None = None) -> PMCardioClient:
    try:
        token = automated_access_token(session_file)
    except PMCardioError as exc:
        raise SystemExit(f"Error: {exc}") from exc
    return PMCardioClient(token)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("test", help="Run offline APK contract tests; no token or network.")
    commands.add_parser("describe", help="Print the verified APK endpoint list.")
    stress = commands.add_parser(
        "stress",
        help="Run offline contract requests; no token or network.",
    )
    stress.add_argument(
        "count",
        type=int,
        help="Number of fake requests to execute.",
    )
    offline_workflow = commands.add_parser(
        "offline-workflow",
        help="Run one image through the offline API contract fixtures.",
    )
    offline_workflow.add_argument("images", nargs="+")
    login = commands.add_parser(
        "login",
        help="Complete the APK's Cognito login once and save a refresh session.",
    )
    login.add_argument(
        "--no-open",
        action="store_true",
        help="Print the Hosted UI URL without opening a browser.",
    )
    login.add_argument(
        "--session-file",
        help="Override the default session path outside the project workspace.",
    )
    listing = commands.add_parser("live-list", help="Live authenticated report list.")
    listing.add_argument("--size", type=int, default=20)
    listing.add_argument("--number", type=int, default=1)
    listing.add_argument("--session-file")
    workflow = commands.add_parser("live-workflow", help="Live upload, detail, and optional PDF workflow.")
    workflow.add_argument("images", nargs="+")
    workflow.add_argument("--pdf-out")
    workflow.add_argument("--session-file")
    auth_workflow = commands.add_parser(
        "auth-workflow",
        help="Sign in through the APK's Cognito Hosted UI, then run a live workflow.",
    )
    auth_workflow.add_argument("images", nargs="+")
    auth_workflow.add_argument("--pdf-out")
    auth_workflow.add_argument(
        "--no-open",
        action="store_true",
        help="Print the Hosted UI URL without opening a browser.",
    )

    args = parser.parse_args()
    if args.command == "test":
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(OfflineContractTests)
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        raise SystemExit(0 if result.wasSuccessful() else 1)
    if args.command == "describe":
        print_description()
        return
    if args.command == "stress":
        if args.count < 1:
            raise SystemExit("count must be at least 1")
        transport = FakeTransport()
        client = PMCardioClient(transport=transport)
        for _ in range(args.count):
            client.list_reports(size=20, number=1)
        print(
            json.dumps(
                {
                    "completed": args.count,
                    "transport": "local FakeTransport",
                    "network_requests": 0,
                    "token_used": False,
                },
                indent=2,
            )
        )
        return
    if args.command == "offline-workflow":
        transport = FakeTransport()
        client = PMCardioClient(transport=transport)
        result = client.process_report(args.images)
        print(
            json.dumps(
                {
                    "result": result,
                    "requests_simulated": len(transport.calls),
                    "network_requests": 0,
                    "token_used": False,
                },
                indent=2,
                default=str,
            )
        )
        return
    if args.command == "login":
        verifier, challenge = create_pkce_pair()
        state = secrets.token_urlsafe(32)
        url = cognito_authorize_url(state, challenge)
        print("Open this URL in a browser and complete the PMcardio sign-in:")
        print(url)
        if not args.no_open:
            webbrowser.open(url)
        print(
            "After sign-in, paste the complete pmind://callback/ URL here. "
            "The callback and tokens are used only locally."
        )
        callback_url = input("Callback URL: ").strip()
        token_set = exchange_cognito_code_tokens(callback_url, verifier, state)
        if not token_set.refresh_token:
            raise SystemExit(
                "Cognito did not issue a refresh token. Automatic login cannot be enabled "
                "for this client configuration."
            )
        store = CognitoSessionStore(args.session_file)
        store.save_refresh_token(token_set.refresh_token)
        print(f"Saved the Cognito refresh session to {store.path}.")
        print("Future live commands will refresh access tokens automatically.")
        return
    if args.command == "auth-workflow":
        verifier, challenge = create_pkce_pair()
        state = secrets.token_urlsafe(32)
        url = cognito_authorize_url(state, challenge)
        print("Open this URL in a browser and complete the PMcardio sign-in:")
        print(url)
        if not args.no_open:
            webbrowser.open(url)
        print(
            "After sign-in, paste the complete pmind://callback/ URL here. "
            "It is used only in this process and is not printed or saved."
        )
        callback_url = input("Callback URL: ").strip()
        access_token = exchange_cognito_code(callback_url, verifier, state)
        result = PMCardioClient(access_token).process_report(
            args.images,
            pdf_output=args.pdf_out,
        )
        print(json.dumps(result, indent=2, default=str))
        return

    client = live_client(getattr(args, "session_file", None))
    if args.command == "live-list":
        print(json.dumps(client.list_reports(size=args.size, number=args.number), indent=2))
    elif args.command == "live-workflow":
        result = client.process_report(args.images, pdf_output=args.pdf_out)
        print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()