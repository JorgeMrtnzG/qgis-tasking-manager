# -*- coding: utf-8 -*-
"""
Tasking Manager authentication helpers.

The Tasking Manager uses OSM OAuth2.  HOT production has the
``https://tasks.hotosm.org/authorized`` redirect registered with OSM, so
the plugin logs in through an embedded browser and intercepts that redirect
before the Tasking Manager frontend consumes the authorization code.
"""

from __future__ import annotations

import base64
import queue
import time
from urllib.parse import parse_qs, urlparse

import requests
from qgis.core import QgsSettings, QgsTask
from qgis.PyQt.QtCore import QUrl, QUrlQuery, pyqtSignal
from qgis.PyQt.QtWidgets import QDialog, QDialogButtonBox, QLabel, QVBoxLayout

try:
    from qgis.PyQt.QtWebEngineWidgets import QWebEnginePage, QWebEngineView

    _HAS_WEBENGINE = True
except ImportError:
    QWebEnginePage = None
    QWebEngineView = None
    _HAS_WEBENGINE = False

try:
    from qgis.PyQt.QtWebKitWidgets import QWebPage, QWebView

    _HAS_WEBKIT = True
except ImportError:
    QWebPage = None
    QWebView = None
    _HAS_WEBKIT = False


TM_API_BASE = "https://tasking-manager-production-api.hotosm.org/api/v2"
DEFAULT_REDIRECT_URI = "https://tasks.hotosm.org/authorized"
LOGIN_TIMEOUT_SECONDS = 300
REQUEST_TIMEOUT_SECONDS = 30

USERNAME_SETTINGS_KEY = "tasking_manager/auth/username"
TOKEN_SETTINGS_KEY = "tasking_manager/auth/token"


def normalize_token(token: str | None) -> str:
    """Return a bare Tasking Manager session token.

    The Tasking Manager profile page copies the token as ``Token <value>``.
    Users may also paste just the value, so both forms are accepted.
    """
    value = (token or "").strip()
    if value.lower().startswith("token "):
        value = value[6:].strip()
    return value


def encode_session_token(session_token: str) -> str:
    """Encode the Tasking Manager session token for the API header.

    The API expects ``Authorization: Token <base64(session_token)>``.
    """
    return base64.b64encode(session_token.encode("utf-8")).decode("ascii")


def parse_oauth_redirect(
    url: str, expected_redirect_uri: str
) -> tuple[str | None, str | None, str | None]:
    """Extract ``(code, state, error)`` from an OAuth redirect URL.

    Returns ``(None, None, None)`` when ``url`` is not the expected redirect
    URL, so the embedded browser can keep navigating through OSM's login
    pages.
    """
    parsed = urlparse(url)
    expected = urlparse(expected_redirect_uri)

    if (parsed.scheme, parsed.netloc) != (expected.scheme, expected.netloc):
        return None, None, None
    if parsed.path.rstrip("/") != expected.path.rstrip("/"):
        return None, None, None

    params = parse_qs(parsed.query)
    code = params.get("code", [None])[0]
    state = params.get("state", [None])[0]
    error = params.get("error_description", params.get("error", [None]))[0]
    return code, state, error


def _redirect_uri_from_auth_url(auth_url: str) -> str:
    query = QUrlQuery(QUrl(auth_url))
    return query.queryItemValue("redirect_uri", QUrl.FullyDecoded) or DEFAULT_REDIRECT_URI


class AuthStore:
    """Persist the Tasking Manager credentials in the QGIS user profile."""

    def __init__(self):
        self._settings = QgsSettings()

    @property
    def username(self) -> str:
        return self._settings.value(USERNAME_SETTINGS_KEY, "", type=str) or ""

    @property
    def token(self) -> str:
        return normalize_token(
            self._settings.value(TOKEN_SETTINGS_KEY, "", type=str) or ""
        )

    def save(self, username: str, token: str) -> None:
        self._settings.setValue(USERNAME_SETTINGS_KEY, username)
        self._settings.setValue(TOKEN_SETTINGS_KEY, normalize_token(token))
        self._settings.sync()

    def clear(self) -> None:
        self._settings.remove(USERNAME_SETTINGS_KEY)
        self._settings.remove(TOKEN_SETTINGS_KEY)
        self._settings.sync()


def _callback_error_message(response: requests.Response) -> str:
    try:
        payload = response.json()
    except ValueError:
        return (
            "Tasking Manager rejected the login "
            f"(HTTP {response.status_code})."
        )

    message = (
        payload.get("Error")
        or payload.get("detail")
        or payload.get("message")
    )
    if message:
        return f"Tasking Manager rejected the login: {message}"
    return f"Tasking Manager rejected the login (HTTP {response.status_code})."


class OsmAuthTask(QgsTask):
    """Background task that drives the OSM OAuth exchange."""

    auth_url_ready = pyqtSignal(str)
    succeeded = pyqtSignal(dict)
    failed = pyqtSignal(str)
    canceled = pyqtSignal()

    def __init__(self, api_base: str = TM_API_BASE):
        super().__init__("Tasking Manager OSM login", QgsTask.CanCancel)
        self._api_base = api_base.rstrip("/")
        self._messages: queue.Queue[tuple[str, str | None, str | None]] = queue.Queue()
        self._result: dict[str, str] | None = None
        self._error: str | None = None
        self._cancel_requested = False

    def provide_code(self, code: str, state: str) -> None:
        self._messages.put(("code", code, state))

    def provide_error(self, message: str) -> None:
        self._messages.put(("error", message, None))

    def request_cancel(self) -> None:
        self._cancel_requested = True
        self._messages.put(("cancel", None, None))
        super().cancel()

    def run(self) -> bool:
        try:
            response = requests.get(
                f"{self._api_base}/system/authentication/login/",
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
            response.raise_for_status()
            login_data = response.json()

            auth_url = login_data["auth_url"]
            expected_state = login_data["state"]
            self.auth_url_ready.emit(auth_url)

            deadline = time.monotonic() + LOGIN_TIMEOUT_SECONDS
            while True:
                if self.isCanceled() or self._cancel_requested:
                    self._cancel_requested = True
                    return False

                try:
                    kind, value, state = self._messages.get(timeout=0.5)
                    break
                except queue.Empty:
                    if time.monotonic() >= deadline:
                        self._error = "Login timed out. Please try again."
                        return False

            if kind == "cancel":
                self._cancel_requested = True
                return False
            if kind == "error":
                self._error = value or "OSM authorization failed."
                return False
            if not value:
                self._error = "No authorization code was received from OSM."
                return False
            if state != expected_state:
                self._error = "OAuth state mismatch. Please try logging in again."
                return False

            response = requests.get(
                f"{self._api_base}/system/authentication/callback/",
                params={"code": value},
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
            if response.status_code != 200:
                self._error = _callback_error_message(response)
                return False

            callback_data = response.json()
            self._result = {
                "username": callback_data.get("username", ""),
                "token": encode_session_token(callback_data["session_token"]),
                "picture": callback_data.get("picture") or "",
            }
            return True
        except Exception as exc:  # noqa: BLE001 - surfaced to the user
            self._error = f"Login failed: {exc}"
            return False

    def finished(self, result: bool) -> None:  # noqa: D401 - QgsTask API
        if result and self._result is not None:
            self.succeeded.emit(self._result)
        elif self._cancel_requested or self.isCanceled():
            self.canceled.emit()
        else:
            self.failed.emit(self._error or "Login failed.")


if _HAS_WEBENGINE:

    class _LoginPage(QWebEnginePage):
        auth_code = pyqtSignal(str, str)
        auth_error = pyqtSignal(str)

        def __init__(self, expected_redirect_uri: str, parent=None):
            super().__init__(parent)
            self._expected_redirect_uri = expected_redirect_uri

        def acceptNavigationRequest(self, url, nav_type, is_main_frame):  # noqa: N802
            if is_main_frame:
                code, state, error = parse_oauth_redirect(
                    url.toString(), self._expected_redirect_uri
                )
                if error:
                    self.auth_error.emit(error)
                    return False
                if code:
                    self.auth_code.emit(code, state or "")
                    return False
            return super().acceptNavigationRequest(url, nav_type, is_main_frame)

elif _HAS_WEBKIT:

    class _LoginPage(QWebPage):
        auth_code = pyqtSignal(str, str)
        auth_error = pyqtSignal(str)

        def __init__(self, expected_redirect_uri: str, parent=None):
            super().__init__(parent)
            self._expected_redirect_uri = expected_redirect_uri

        def acceptNavigationRequest(self, frame, request, nav_type):  # noqa: N802
            if frame is self.mainFrame():
                code, state, error = parse_oauth_redirect(
                    request.url().toString(), self._expected_redirect_uri
                )
                if error:
                    self.auth_error.emit(error)
                    return False
                if code:
                    self.auth_code.emit(code, state or "")
                    return False
            return super().acceptNavigationRequest(frame, request, nav_type)

else:

    class _LoginPage:  # type: ignore[no-redef]
        pass


class OsmLoginDialog(QDialog):
    """Small browser window used to complete the OSM authorization."""

    auth_code = pyqtSignal(str, str)
    auth_error = pyqtSignal(str)
    canceled = pyqtSignal()

    def __init__(self, auth_url: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle(self.tr("Login to Tasking Manager"))
        self.resize(900, 700)

        self._completed = False
        self._canceled_emitted = False
        self._expected_redirect_uri = _redirect_uri_from_auth_url(auth_url)
        self._view = None
        self._page = None

        layout = QVBoxLayout(self)
        layout.addWidget(
            QLabel(
                self.tr(
                    "Log in with your OpenStreetMap account and authorize "
                    "the Tasking Manager."
                ),
                self,
            )
        )

        if _HAS_WEBENGINE:
            self._view = QWebEngineView(self)
            self._page = _LoginPage(self._expected_redirect_uri, self._view)
            self._view.setPage(self._page)
            layout.addWidget(self._view, 1)
            self._view.load(QUrl(auth_url))
        elif _HAS_WEBKIT:
            self._view = QWebView(self)
            self._page = _LoginPage(self._expected_redirect_uri, self._view)
            self._view.setPage(self._page)
            layout.addWidget(self._view, 1)
            self._view.load(QUrl(auth_url))
        else:
            layout.addWidget(
                QLabel(
                    self.tr(
                        "The embedded browser is not available in this QGIS "
                        "installation, so Tasking Manager login cannot be "
                        "completed."
                    ),
                    self,
                ),
                1,
            )

        if self._page is not None:
            self._page.auth_code.connect(self._on_code)
            self._page.auth_error.connect(self._on_error)

        buttons = QDialogButtonBox(QDialogButtonBox.Cancel, self)
        buttons.rejected.connect(self._cancel)
        layout.addWidget(buttons)

    def _on_code(self, code: str, state: str) -> None:
        self._completed = True
        self.auth_code.emit(code, state)
        self.accept()

    def _on_error(self, message: str) -> None:
        self._completed = True
        self.auth_error.emit(message)
        self.reject()

    def _emit_canceled_once(self) -> None:
        if not self._completed and not self._canceled_emitted:
            self._canceled_emitted = True
            self.canceled.emit()

    def _cancel(self) -> None:
        self._emit_canceled_once()
        self.reject()

    def closeEvent(self, event):  # noqa: N802
        self._emit_canceled_once()
        super().closeEvent(event)
