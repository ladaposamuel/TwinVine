import sys
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit, QTextEdit, QPushButton, QCheckBox, QFrame, QMessageBox, QHBoxLayout
)
from PyQt6.QtCore import QObject, Qt, QThread, pyqtSignal
from PyQt6.QtGui import QPalette, QColor
import json
import subprocess
import threading
import httpx
import base64
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse
import urllib.parse
import xml.etree.ElementTree as ET
from pywidevine.cdm import Cdm
from pywidevine.device import Device
from pywidevine.pssh import PSSH
from base64 import b64encode
import codecs
from pathlib import Path
import os
import shutil
import shlex

WVD_PATH = "./WVDs/device.wvd"
WIDEVINE_SYSTEM_ID = 'EDEF8BA9-79D6-4ACE-A3C8-27DCD51D21ED'

# Browser "Copy as cURL" includes these, and replaying them breaks the client that sends them.
_DROPPED_CURL_HEADERS = {
    "accept-encoding",
    "authority",
    "connection",
    "content-length",
    "host",
    "if-match",
    "if-modified-since",
    "if-none-match",
    "if-range",
    "if-unmodified-since",
    "transfer-encoding",
}


def parse_mpd_input(text: str) -> tuple[str, list[tuple[str, str]]]:
    """Return a manifest URL and the request headers to replay.

    A plain URL is used unchanged and carries no headers. A cURL command copied from
    a browser yields its URL, ``-H`` headers, and ``-b`` / ``--cookie`` values.
    """
    raw = text.strip()
    if not raw:
        return "", []
    if not raw.lower().startswith("curl"):
        return raw, []

    normalized = re.sub(r"\\\s*\r?\n", " ", raw)
    normalized = re.sub(r"\^\s*\r?\n", " ", normalized)
    try:
        tokens = shlex.split(normalized, posix=True)
    except ValueError:
        return _curl_from_regex(normalized)

    url = ""
    headers: list[tuple[str, str]] = []
    cookies: list[str] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        lower = token.lower()
        name, _, attached = token.partition("=")
        flag = name.lower()

        if lower == "curl":
            index += 1
            continue

        def take_value(explicit: str | None = None) -> str | None:
            nonlocal index
            if explicit is not None:
                index += 1
                return explicit
            if index + 1 >= len(tokens):
                index += 1
                return None
            index += 2
            return tokens[index - 1]

        if flag in {"-h", "--header"}:
            header = take_value(attached or None)
            if header and ":" in header:
                header_name, header_value = header.split(":", 1)
                headers.append((header_name.strip(), header_value.strip()))
            continue
        if flag in {"-b", "--cookie"}:
            cookie = take_value(attached or None)
            if cookie and not cookie.startswith("@"):
                cookies.append(cookie)
            continue
        if flag in {"-a", "--user-agent"}:
            user_agent = take_value(attached or None)
            if user_agent:
                headers.append(("User-Agent", user_agent))
            continue
        if flag in {"-e", "--referer", "--referrer"}:
            referer = take_value(attached or None)
            if referer:
                headers.append(("Referer", referer))
            continue
        if flag == "--url":
            found = take_value(attached or None)
            if found:
                url = found
            continue
        if token.startswith("-"):
            index += 1
            continue
        if not url and token.startswith(("http://", "https://")):
            url = token
        index += 1

    return url, _normalize_request_headers(headers, cookies)


def _curl_from_regex(curl_command: str) -> tuple[str, list[tuple[str, str]]]:
    url_match = re.search(r"""(?:--url\s+|curl\s+)(['"])(https?://.*?)\1""", curl_command, re.IGNORECASE | re.DOTALL)
    if url_match:
        url = url_match.group(2)
    else:
        bare = re.search(r"https?://\S+", curl_command)
        url = bare.group(0).rstrip("'\"") if bare else ""

    headers: list[tuple[str, str]] = []
    for match in re.finditer(r"""(?:-H|--header)(?:\s+|=)(['"])([^'"]+?)\1""", curl_command, re.IGNORECASE):
        header = match.group(2)
        if ":" in header:
            header_name, header_value = header.split(":", 1)
            headers.append((header_name.strip(), header_value.strip()))

    cookies = [
        match.group(2)
        for match in re.finditer(r"""(?:-b|--cookie)(?:\s+|=)(['"])([^'"]+?)\1""", curl_command, re.IGNORECASE)
    ]
    return url, _normalize_request_headers(headers, cookies)


def _normalize_request_headers(
    headers: list[tuple[str, str]], cookies: list[str]
) -> list[tuple[str, str]]:
    kept: list[tuple[str, str]] = []
    cookie_values: list[str] = []
    for name, value in headers:
        cleaned_name = name.strip()
        cleaned_value = value.strip()
        if not cleaned_name or not cleaned_value or cleaned_name.startswith(":"):
            continue
        if cleaned_name.lower() in _DROPPED_CURL_HEADERS:
            continue
        if cleaned_name.lower() == "cookie":
            cookie_values.append(cleaned_value)
            continue
        kept.append((cleaned_name, cleaned_value))

    cookie_values.extend(cookie.strip() for cookie in cookies if cookie.strip())
    if cookie_values:
        kept.append(("Cookie", "; ".join(cookie_values)))
    return kept


def normalize_kid(value: str) -> str:
    """Return a UUID-shaped key ID, or an empty string when the value is not 16 bytes."""
    hex_only = re.sub(r"[^0-9a-fA-F]", "", value or "")
    if len(hex_only) != 32:
        return ""
    hex_only = hex_only.lower()
    return f"{hex_only[:8]}-{hex_only[8:12]}-{hex_only[12:16]}-{hex_only[16:20]}-{hex_only[20:]}"


def _read_varint(data: bytes, index: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while index < len(data):
        byte = data[index]
        index += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, index
        shift += 7
    return value, index


def _protobuf_key_ids(data: bytes) -> list[str]:
    """Read Widevine PSSH protobuf field 2, which stores each key ID."""
    found: list[str] = []
    index = 0
    while index < len(data):
        tag = data[index]
        index += 1
        field = tag >> 3
        wire = tag & 0x07
        if wire == 0:
            _, index = _read_varint(data, index)
        elif wire == 1:
            index += 8
        elif wire == 5:
            index += 4
        elif wire == 2:
            length, index = _read_varint(data, index)
            value = data[index:index + length]
            index += length
            if field == 2 and len(value) == 16:
                kid = normalize_kid(value.hex())
                if kid:
                    found.append(kid)
        else:
            break
    return found


def pssh_key_ids(pssh_b64: str) -> list[str]:
    """Return the key IDs stored in a Widevine PSSH box."""
    try:
        raw = base64.b64decode("".join(pssh_b64.split()))
    except Exception:
        return []
    if len(raw) < 32 or raw[4:8] != b"pssh":
        return _protobuf_key_ids(raw)
    version = raw[8]
    if version == 0:
        data_size = int.from_bytes(raw[28:32], "big")
        return _protobuf_key_ids(raw[32:32 + data_size])
    kid_count = int.from_bytes(raw[28:32], "big")
    found: list[str] = []
    position = 32
    for _ in range(kid_count):
        kid = normalize_kid(raw[position:position + 16].hex())
        if kid:
            found.append(kid)
        position += 16
    if position + 4 <= len(raw):
        data_size = int.from_bytes(raw[position:position + 4], "big")
        found.extend(_protobuf_key_ids(raw[position + 4:position + 4 + data_size]))
    return list(dict.fromkeys(found))


def synthetic_pssh(key_ids: list[str]) -> str:
    """Build a version-0 Widevine PSSH containing only these key IDs."""
    proto = b""
    for key_id in key_ids:
        proto += b"\x12\x10" + bytes.fromhex(normalize_kid(key_id).replace("-", ""))
    box_size = 32 + len(proto)
    box = box_size.to_bytes(4, "big")
    box += b"pssh" + b"\x00\x00\x00\x00"
    box += bytes.fromhex("edef8ba979d64acea3c827dcd51d21ed")
    box += len(proto).to_bytes(4, "big") + proto
    return base64.b64encode(box).decode()


def _decode_entitlement(value: str):
    text = value.strip()
    if text.lower().startswith("bearer "):
        text = text[7:].strip()
    for _ in range(3):
        try:
            decoded = base64.b64decode(text + "=" * (-len(text) % 4))
            text = decoded.decode("utf-8").strip()
        except Exception:
            break
        if text.startswith("{") or text.startswith("["):
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return text
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return text


def _ids_from_entitlement(value) -> list[str]:
    if isinstance(value, str):
        parsed = _decode_entitlement(value)
    else:
        parsed = value
    if not isinstance(parsed, dict):
        return []
    message = parsed.get("message") if isinstance(parsed.get("message"), dict) else parsed
    source = message.get("content_keys_source")
    inline = []
    if isinstance(source, dict):
        inline = source.get("inline") or []
    elif isinstance(source, list):
        inline = source
    found: list[str] = []
    if isinstance(inline, list):
        for item in inline:
            if isinstance(item, str):
                found.append(item)
            elif isinstance(item, dict):
                for key in ("id", "key_id", "keyId"):
                    if item.get(key):
                        found.append(str(item[key]))
                        break
    for key in ("content_key_ids", "key_ids", "kids"):
        values = message.get(key)
        if isinstance(values, list):
            found.extend(str(item) for item in values)
    return [kid for item in found if (kid := normalize_kid(item))]


def entitlement_key_ids(headers, body: str | None) -> list[str]:
    """Read content key IDs from an Axinom entitlement message, ignoring the communication key."""
    found: list[str] = []
    pairs = headers.items() if isinstance(headers, dict) else (headers or [])
    for name, value in pairs:
        if "axdrm" in str(name).lower() or "entitlement" in str(name).lower():
            found.extend(_ids_from_entitlement(str(value)))
    if isinstance(body, str) and ("content_keys_source" in body or "entitlement_message" in body):
        found.extend(_ids_from_entitlement(body))
    return list(dict.fromkeys(found))


def choose_pssh(psshs: list[str], manifest_kids: list[str], entitled_kids: list[str]) -> str | None:
    """Pick a PSSH whose key IDs are all allowed by the entitlement message."""
    entitled = set(entitled_kids)
    if entitled:
        for pssh in psshs:
            present = pssh_key_ids(pssh)
            if present and set(present) <= entitled:
                return "".join(pssh.split())
        allowed_in_manifest = [kid for kid in manifest_kids if kid in entitled]
        return synthetic_pssh(allowed_in_manifest or entitled_kids)
    if psshs:
        return "".join(psshs[0].split())
    if manifest_kids:
        return synthetic_pssh(manifest_kids[:1])
    return None


def _header_arguments(headers: list[tuple[str, str]]) -> list[str]:
    arguments: list[str] = []
    for name, value in headers:
        arguments.extend(["-H", f"{name}: {value}"])
    return arguments


HELLYES_PORT = 8765
_TOOLS_DIR = Path(__file__).resolve().parent / "tools"


def tool_path(name: str) -> str | None:
    """Find a downloader on PATH, then in the TwinVine tools folder."""
    found = shutil.which(name)
    if found:
        return found
    local = _TOOLS_DIR / name
    if local.is_file() and os.access(local, os.X_OK):
        return str(local)
    return None
_MAX_CAPTURE_BYTES = 20 * 1024 * 1024


def headers_to_curl(url: str, headers: list[tuple[str, str]]) -> str:
    """Build a cURL command HellYes can parse again from captured headers."""
    command = ["curl", "--url", url]
    for name, value in headers:
        command.extend(["-H", f"{name}: {value}"])
    return shlex.join(command)


def _pairs_from_capture(items) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    if not isinstance(items, list):
        return pairs
    for item in items:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "")).replace("\r", "").replace("\n", "").strip()
        value = str(item.get("value", "")).replace("\r", "").replace("\n", "").strip()
        if name and value:
            pairs.append((name, value))
    return _normalize_request_headers(pairs, [])


class _CaptureHub(QObject):
    received = pyqtSignal(object)


_capture_hub: _CaptureHub | None = None


def deliver_capture(payload: dict) -> None:
    if _capture_hub is not None:
        _capture_hub.received.emit(payload)


class _CaptureHandler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_GET(self):
        if urlparse(self.path).path != "/health":
            self.send_error(404)
            return
        self._json(200, {"ok": True, "port": HELLYES_PORT})

    def do_POST(self):
        if urlparse(self.path).path != "/capture":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0 or length > _MAX_CAPTURE_BYTES:
            self._json(413, {"ok": False, "error": "Capture is empty or too large."})
            return
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._json(400, {"ok": False, "error": "Capture was not valid JSON."})
            return
        if not isinstance(payload, dict):
            self._json(400, {"ok": False, "error": "Capture must be an object."})
            return
        deliver_capture(payload)
        self._json(200, {"ok": True})

    def log_message(self, fmt, *args):
        print(f"[HellYes] {fmt % args}")

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def _json(self, status: int, payload: dict):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self._cors()
        self.end_headers()
        self.wfile.write(body)

class DownloadThread(QThread):
    finished = pyqtSignal()
    error = pyqtSignal(str)

    def __init__(self, command):
        super().__init__()
        self.command = command

    def run(self):
        try:
            subprocess.run(self.command, check=True)
            self.finished.emit()
        except Exception as exc:
            self.error.emit(str(exc))

class AllHell3App(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("HellYes!")
        self.n_m3u8dl_re_argv = None
        self.dash_mpd_cli_argv = None
        self.captured_mpd_url = None
        self.captured_mpd_body = None
        self.captured_headers = None
        self.captured_license = None
        self._applying_capture = False
        self._license_edited = False
        self._capture_server = None
        layout = QVBoxLayout()

        self.mpd_url_label = QLabel("MPD URL or cURL")
        layout.addWidget(self.mpd_url_label)
        self.mpd_url_entry = QTextEdit()
        self.mpd_url_entry.setPlaceholderText("Paste a manifest URL or cURL, or send one from the HellYes Pair extension")
        self.mpd_url_entry.setMinimumHeight(72)
        self.mpd_url_entry.setMaximumHeight(120)
        self.mpd_url_entry.textChanged.connect(self._mpd_text_edited)
        layout.addWidget(self.mpd_url_entry)
        self.extension_status = QLabel()
        layout.addWidget(self.extension_status)

        self.curl_label = QLabel("cURL of License Request")
        layout.addWidget(self.curl_label)
        self.curl_text = QTextEdit()
        self.curl_text.textChanged.connect(self._license_text_edited)
        layout.addWidget(self.curl_text)

        highlighted_frame = QFrame()
        highlighted_layout = QVBoxLayout()
        highlighted_frame.setLayout(highlighted_layout)
        highlighted_frame.setStyleSheet("border: 1px solid red;")

        self.video_name_label = QLabel("Video Name")
        highlighted_layout.addWidget(self.video_name_label)
        self.video_name_entry = QLineEdit()
        highlighted_layout.addWidget(self.video_name_entry)

        self.fetch_keys_button = QPushButton("Get Keys")
        self.fetch_keys_button.clicked.connect(self.fetch_keys)
        highlighted_layout.addWidget(self.fetch_keys_button)

        self.download_button = QPushButton("Download Nm~RE")
        self.download_button.clicked.connect(self.download_video)
        highlighted_layout.addWidget(self.download_button)

        self.download_button2 = QPushButton("Download DASH")
        self.download_button2.clicked.connect(self.download_dash)
        highlighted_layout.addWidget(self.download_button2)

        layout.addWidget(highlighted_frame)

        self.keys_output = QTextEdit()
        layout.addWidget(self.keys_output)

        self.n_m3u8dl_re_label = QLabel("N_m3u8DL-RE command")
        layout.addWidget(self.n_m3u8dl_re_label)
        self.n_m3u8dl_re_output = QTextEdit()
        layout.addWidget(self.n_m3u8dl_re_output)

        self.dash_mpd_cli_label = QLabel("Dash-MPD-CLI command")
        layout.addWidget(self.dash_mpd_cli_label)
        self.dash_mpd_cli_output = QTextEdit()
        layout.addWidget(self.dash_mpd_cli_output)

        checkbox_layout = QHBoxLayout()
        self.dark_mode_checkbox = QCheckBox("Dark Mode")
        self.dark_mode_checkbox.setChecked(True)
        self.dark_mode_checkbox.stateChanged.connect(self.toggle_dark_mode)
        checkbox_layout.addWidget(self.dark_mode_checkbox)

        self.reset_button = QPushButton("Reset")
        self.reset_button.clicked.connect(self.reset_fields)
        checkbox_layout.addWidget(self.reset_button)

        layout.addLayout(checkbox_layout)

        self.setLayout(layout)
        self.toggle_dark_mode()
        self._start_capture_server()

    def reset_fields(self):
        self.captured_mpd_url = None
        self.captured_mpd_body = None
        self.captured_headers = None
        self.captured_license = None
        self._license_edited = False
        self.mpd_url_entry.clear()
        self.curl_text.clear()
        self.video_name_entry.clear()
        self.keys_output.clear()
        self.n_m3u8dl_re_output.clear()
        self.dash_mpd_cli_output.clear()

    def _mpd_text_edited(self):
        if self._applying_capture:
            return
        self.captured_mpd_url = None
        self.captured_mpd_body = None
        self.captured_headers = None

    def _license_text_edited(self):
        if self._applying_capture:
            return
        self._license_edited = True
        self.captured_license = None

    def _start_capture_server(self):
        global _capture_hub
        _capture_hub = _CaptureHub()
        _capture_hub.received.connect(self.apply_capture)
        try:
            class _ReuseServer(ThreadingHTTPServer):
                allow_reuse_address = True

            server = _ReuseServer(("127.0.0.1", HELLYES_PORT), _CaptureHandler)
        except OSError as exc:
            self.extension_status.setText(f"Extension port {HELLYES_PORT} is already in use ({exc}).")
            return
        self._capture_server = server
        thread = threading.Thread(target=server.serve_forever, name="hellyes-capture", daemon=True)
        thread.start()
        self.extension_status.setText(f"HellYes Pair: listening on 127.0.0.1:{HELLYES_PORT}")

    def closeEvent(self, event):
        server = self._capture_server
        self._capture_server = None
        if server is not None:
            server.shutdown()
            server.server_close()
        super().closeEvent(event)

    def apply_capture(self, payload: dict):
        mpd_url = str(payload.get("mpd_url") or "").strip()
        parsed = urlparse(mpd_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            self.extension_status.setText("The extension sent a capture without an http(s) manifest URL.")
            return

        mpd_body = payload.get("mpd_body")
        if not isinstance(mpd_body, str) or not mpd_body.strip():
            self.extension_status.setText("The extension did not include the manifest response.")
            return

        headers = _pairs_from_capture(payload.get("headers"))
        license_payload = payload.get("license") if isinstance(payload.get("license"), dict) else None
        license_headers = _pairs_from_capture((license_payload or {}).get("headers"))
        license_url = str((license_payload or {}).get("url") or "").strip()
        body_text = (license_payload or {}).get("body_text")
        if not isinstance(body_text, str):
            body_text = None

        self.captured_mpd_url = mpd_url
        self.captured_mpd_body = mpd_body
        self.captured_headers = headers
        self.captured_license = None
        if license_url:
            self.captured_license = {
                "url": license_url,
                "headers": license_headers,
                "body_text": body_text,
            }

        self._applying_capture = True
        try:
            self.mpd_url_entry.setPlainText(headers_to_curl(mpd_url, headers))
            if license_url:
                self.curl_text.setPlainText(headers_to_curl(license_url, license_headers))
                self._license_edited = False
            title = str(payload.get("title") or "").strip()
            if not title:
                title = re.sub(
                    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}-",
                    "",
                    Path(parsed.path).stem,
                    flags=re.IGNORECASE,
                )
            title = re.sub(r'[\\/:*?"<>|]+', " ", title).replace("_", " ").strip()[:120]
            if title:
                self.video_name_entry.setText(title)
        finally:
            self._applying_capture = False

        self.extension_status.setText("Received the manifest from HellYes Pair. Click Get Keys.")


    def toggle_dark_mode(self):
        if self.dark_mode_checkbox.isChecked():
            palette = QPalette()
            palette.setColor(QPalette.ColorRole.Window, QColor(53, 53, 53))
            palette.setColor(QPalette.ColorRole.WindowText, Qt.GlobalColor.white)
            palette.setColor(QPalette.ColorRole.Base, QColor(35, 35, 35))
            palette.setColor(QPalette.ColorRole.AlternateBase, QColor(53, 53, 53))
            palette.setColor(QPalette.ColorRole.ToolTipBase, Qt.GlobalColor.black)
            palette.setColor(QPalette.ColorRole.ToolTipText, Qt.GlobalColor.white)
            palette.setColor(QPalette.ColorRole.Text, Qt.GlobalColor.white)
            palette.setColor(QPalette.ColorRole.Button, QColor(53, 53, 53))
            palette.setColor(QPalette.ColorRole.ButtonText, Qt.GlobalColor.white)
            palette.setColor(QPalette.ColorRole.BrightText, Qt.GlobalColor.red)
            palette.setColor(QPalette.ColorRole.Link, QColor(42, 130, 218))
            palette.setColor(QPalette.ColorRole.Highlight, QColor(42, 130, 218))
            palette.setColor(QPalette.ColorRole.HighlightedText, Qt.GlobalColor.black)
            self.setPalette(palette)

            self.mpd_url_label.setStyleSheet("color: white;")
            self.extension_status.setStyleSheet("color: #f5c2e7;")
            self.curl_label.setStyleSheet("color: white;")
            self.video_name_label.setStyleSheet("color: white;")
            self.n_m3u8dl_re_label.setStyleSheet("color: white;")
            self.dash_mpd_cli_label.setStyleSheet("color: white;")
            self.dark_mode_checkbox.setStyleSheet("color: white;")
            self.fetch_keys_button.setStyleSheet("""color: white;
                                                background-color: #4e4e4e;
                                                border: 1px solid #6e6e6e;
                                                padding: 5px;""")
            self.download_button.setStyleSheet("""color: white;
                                                background-color: #4e4e4e;
                                                border: 1px solid #6e6e6e;
                                                padding: 5px;""")
            
            self.download_button2.setStyleSheet("""color: white;
                                                background-color: #4e4e4e;
                                                border: 1px solid #6e6e6e;
                                                padding: 5px;""")
            
            self.curl_text.setStyleSheet("""color: white; border: 1px solid red;
                                            background-color: #232323;""")
            self.mpd_url_entry.setStyleSheet("""color: white; border: 1px solid red;
                                            background-color: #232323;""")
            self.video_name_label.setStyleSheet("""
                                                color: white; border: None;""")
        else:
            self.setPalette(QApplication.palette())

            self.mpd_url_label.setStyleSheet("color: black;")
            self.extension_status.setStyleSheet("color: #8839a0;")
            self.curl_label.setStyleSheet("color: black;")
            self.video_name_label.setStyleSheet("color: black;")
            self.n_m3u8dl_re_label.setStyleSheet("color: black;")
            self.dash_mpd_cli_label.setStyleSheet("color: black;")
            self.dark_mode_checkbox.setStyleSheet("color: black;")
            self.fetch_keys_button.setStyleSheet("""color: black;
                                                background-color: #aeaeae;
                                                border: 1px solid #6e6e6e;
                                                padding: 5px;""")
            self.download_button.setStyleSheet("""color: black;
                                                background-color: #aeaeae;
                                                border: 1px solid #6e6e6e;
                                                padding: 5px;""")
            self.download_button2.setStyleSheet("""color: black;
                                                background-color: #aeaeae;
                                                border: 1px solid #6e6e6e;
                                                padding: 5px;""")
            
            self.curl_text.setStyleSheet("""color: black; border: 1px solid red;
                                            background-color: white;""")
            self.mpd_url_entry.setStyleSheet("""color: black; border: 1px solid red;
                                            background-color: white;""")
            self.video_name_label.setStyleSheet("""
                                                color: black; border: None;""")
    def fetch_mpd_content(self, mpd_url, headers):
        response = httpx.get(mpd_url, headers=dict(headers), follow_redirects=True)
        response.raise_for_status()
        return response.text

    def find_default_kid_with_regex(self, mpd_content):
        match = re.search(r'cenc:default_KID="([0-9A-Fa-f-]+)"', mpd_content)
        if match:
            return match.group(1)
        return None

    def _manifest_protection(self, mpd_content: str) -> tuple[list[str], list[str]]:
        psshs: list[str] = []
        kids: list[str] = []
        try:
            root = ET.fromstring(mpd_content)
        except ET.ParseError:
            kid = self.find_default_kid_with_regex(mpd_content)
            return [], [normalize_kid(kid)] if kid and normalize_kid(kid) else []

        for elem in root.iter():
            if not str(elem.tag).endswith("ContentProtection"):
                continue
            scheme = (elem.attrib.get("schemeIdUri") or "").upper()
            kid = elem.attrib.get("{urn:mpeg:cenc:2013}default_KID") or elem.attrib.get("cenc:default_KID")
            normalized = normalize_kid(kid or "")
            if normalized:
                kids.append(normalized)
            if scheme == f"URN:UUID:{WIDEVINE_SYSTEM_ID}":
                for child in list(elem):
                    if str(child.tag).endswith("pssh") and child.text and child.text.strip():
                        psshs.append("".join(child.text.split()))
        if not kids:
            kid = self.find_default_kid_with_regex(mpd_content)
            normalized = normalize_kid(kid or "")
            if normalized:
                kids.append(normalized)
        return list(dict.fromkeys(psshs)), list(dict.fromkeys(kids))

    def extract_or_generate_pssh(self, mpd_content, mpd_url, headers, entitled_kids=None):
        psshs, kids = self._manifest_protection(mpd_content)
        chosen = choose_pssh(psshs, kids, entitled_kids or [])
        if chosen:
            return chosen
        try:
            return self.get_pssh_from_mpd(mpd_url, headers)
        except Exception as exc:
            print(f"Error reading a PSSH from the manifest: {exc}")
            return None

        
    def get_pssh_from_mpd(self, mpd: str, headers):
        print("Extracting PSSH from MPD...")

        yt_dl = 'yt-dlp'
        init = 'init.m4f'

        files_to_delete = [init]

        for file_name in files_to_delete:
            if os.path.exists(file_name):
                os.remove(file_name)
                print(f"{file_name} file successfully deleted.")

        command = [
            yt_dl,
            "-q",
            "--no-warning",
            "--test",
            "--allow-u",
            "-f",
            "bestvideo[ext=mp4]/bestaudio[ext=m4a]/best",
            "-o",
            init,
        ]
        for name, value in headers:
            command.extend(["--add-header", f"{name}: {value}"])
        command.append(mpd)

        try:
            subprocess.run(command)
        except FileNotFoundError:
            print("yt-dlp not found. Trying installing it...")
            exit(0)

        pssh_list = self.extract_pssh_from_file('init.m4f')
        pssh = None
        for target_pssh in pssh_list:
            if 20 < len(target_pssh) < 220:
                pssh = target_pssh

        print(f'\n{pssh}\n')

        for file_name in files_to_delete:
            if os.path.exists(file_name):
                os.remove(file_name)
                print(f"{file_name} file successfully deleted.")
        return pssh
        
    

    def extract_pssh_from_file(self,file_path: str) -> list:
        print('Extracting PSSHs from init file:', file_path)
        return self.to_pssh(Path(file_path).read_bytes())
    
    def find_wv_pssh_offsets(self, raw: bytes) -> list:
        offsets = []
        offset = 0
        while True:
            offset = raw.find(b'pssh', offset)
            if offset == -1:
                break
            size = int.from_bytes(raw[offset-4:offset], byteorder='big')
            pssh_offset = offset - 4
            offsets.append(raw[pssh_offset:pssh_offset+size])
            offset += size
        return offsets
    
    def to_pssh(self, content: bytes) -> list:
        wv_offsets = self.find_wv_pssh_offsets(content)
        return [base64.b64encode(wv_offset).decode() for wv_offset in wv_offsets]
    
    

    def parse_curl(self, curl_command):
        url_match = re.search(r"curl\s+'(.*?)'", curl_command)
        url = url_match.group(1) if url_match else ""

        method_match = re.search(r"-X\s+(\w+)", curl_command)
        method = method_match.group(1) if method_match else "UNDEFINED"

        headers = {}
        headers_matches = re.findall(r"-H\s+'([^:]+):\s*(.*?)'", curl_command)
        for header in headers_matches:
            headers[header[0]] = header[1]

        data_match = re.search(r"--data(?:-raw)?\s+(?:(\$?')|(\$?{?))(.*?)'", curl_command, re.DOTALL)
        if data_match:
            raw_prefix = data_match.group(1)
            data = data_match.group(3)
            if raw_prefix and raw_prefix.startswith('$'):
                data = None
            else:
                data = data.replace('\\\\', '\\').replace('\\x', '\\\\x')
                try:
                    data = codecs.decode(data, 'unicode_escape')
                except Exception as e:
                    data = ""
        else:
            data = ""
        return url, method, headers, data

    def get_key(self, pssh, license_url, headers, data):
        device = Device.load(WVD_PATH)
        cdm = Cdm.from_device(device)
        session_id = cdm.open()

        challenge = cdm.get_license_challenge(session_id, PSSH(pssh))

        if data:
            if match := re.search(r'"(CAQ=.*?)"', data):
                challenge = data.replace(match.group(1), base64.b64encode(challenge).decode())
            elif match := re.search(r'"(CAES.*?)"', data):
                challenge = data.replace(match.group(1), base64.b64encode(challenge).decode())
            elif match := re.search(r'=(CAES.*?)(&.*)?$', data):
                b64challenge = base64.b64encode(challenge).decode()
                quoted = urllib.parse.quote_plus(b64challenge)
                challenge = data.replace(match.group(1), quoted)

        payload = challenge if data is None else challenge

        license_response = httpx.post(url=license_url, data=payload, headers=headers)
        try:
            license_response.raise_for_status()
        except httpx.HTTPStatusError as e:
            raise e

        license_content = license_response.content
        try:
            match = re.search(r'"(CAIS.*?)"', license_response.content.decode('utf-8'))
            if match:
                license_content = base64.b64decode(match.group(1))
        except:
            pass

        if isinstance(license_content, str):
            license_content = base64.b64decode(license_content)

        cdm.parse_license(session_id, license_content)

        keys = []
        for key in cdm.get_keys(session_id):
            if key.type == 'CONTENT':
                keys.append(f"--key {key.kid.hex}:{key.key.hex()}")

        cdm.close(session_id)
        return keys

    def fetch_keys(self):
        self.n_m3u8dl_re_argv = None
        self.dash_mpd_cli_argv = None
        mpd_url, mpd_headers = parse_mpd_input(self.mpd_url_entry.toPlainText())
        if self.captured_mpd_url and self.captured_mpd_url == mpd_url and self.captured_headers:
            mpd_headers = self.captured_headers
        if not mpd_url:
            QMessageBox.critical(self, "Error", "Paste an MPD URL or cURL, or send a manifest from HellYes Pair.")
            return

        try:
            if self.captured_mpd_url == mpd_url and self.captured_mpd_body:
                mpd_content = self.captured_mpd_body
            else:
                mpd_content = self.fetch_mpd_content(mpd_url, mpd_headers)

            if self.captured_license and not self._license_edited:
                license_url = self.captured_license["url"]
                headers = dict(self.captured_license["headers"])
                data = self.captured_license.get("body_text") or None
            else:
                curl_command = self.curl_text.toPlainText().strip()
                license_url, method, headers, data = self.parse_curl(curl_command)
            if not license_url:
                QMessageBox.critical(
                    self,
                    "Error",
                    "No license request yet. Play the video after loading HellYes Pair, or paste the license cURL.",
                )
                return

            entitled = entitlement_key_ids(headers, data if isinstance(data, str) else None)
            pssh = self.extract_or_generate_pssh(mpd_content, mpd_url, mpd_headers, entitled)
            if not pssh:
                QMessageBox.critical(self, "Error", "Failed to extract or generate PSSH\nAre you sure the video is Widevine encrypted?.")
                return
            try:
                keys = self.get_key(pssh, license_url, headers, data)
            except Exception as exc:
                if "not present in the entitlement message" in str(exc) and not entitled:
                    raise RuntimeError(
                        f"{exc}\n\nThe license request has no Axinom entitlement key IDs "
                        "(X-AxDRM-Message), so HellYes asked for a key from the manifest."
                    ) from exc
                raise
            self.keys_output.clear()
            self.keys_output.append("\n".join( keys))

            key_args = []
            for key in keys:
                flag, value = key.split(" ", 1)
                key_args.extend([flag, value])

            save_name = self.video_name_entry.text().strip() or "video"
            header_args = _header_arguments(mpd_headers)
            ffmpeg = tool_path("ffmpeg")
            muxer = "mkvmerge" if shutil.which("mkvmerge") else "ffmpeg"
            re_tool = tool_path("N_m3u8DL-RE") or "N_m3u8DL-RE"
            dash_tool = tool_path("dash-mpd-cli") or "dash-mpd-cli"
            self.n_m3u8dl_re_argv = [
                re_tool,
                mpd_url,
                *header_args,
                *key_args,
                "--save-name",
                save_name,
                "-mt",
                f"-M:format=mkv:muxer={muxer}",
            ]
            if ffmpeg and muxer == "ffmpeg":
                self.n_m3u8dl_re_argv.extend(["--ffmpeg-binary-path", ffmpeg])
            self.n_m3u8dl_re_output.setText(shlex.join(self.n_m3u8dl_re_argv))

            self.dash_mpd_cli_argv = [
                dash_tool,
                "--quality",
                "best",
                "--muxer-preference",
                f"mkv:{muxer}",
                *key_args,
                *header_args,
                "--write-subs",
                "--output",
                f"{save_name}.mkv",
                mpd_url,
            ]
            if ffmpeg:
                self.dash_mpd_cli_argv[1:1] = ["--ffmpeg-location", ffmpeg]
            self.dash_mpd_cli_output.setText(shlex.join(self.dash_mpd_cli_argv))

        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def _launch_download(self, argv, tool_name):
        resolved = tool_path(tool_name)
        if not resolved:
            QMessageBox.critical(self, "Error", f"{tool_name} was not found on PATH or in the TwinVine tools folder.")
            return None
        command = list(argv)
        command[0] = resolved
        return command

    def download_video(self):
        if not self.n_m3u8dl_re_argv:
            QMessageBox.critical(self, "Error", "Fetch keys before downloading.")
            return
        command = self._launch_download(self.n_m3u8dl_re_argv, "N_m3u8DL-RE")
        if not command:
            return
        try:
            self.thread = DownloadThread(command)
            self.thread.finished.connect(self.on_download_finished)
            self.thread.error.connect(self.on_download_error)
            self.thread.start()
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def download_dash(self):
        if not self.dash_mpd_cli_argv:
            QMessageBox.critical(self, "Error", "Fetch keys before downloading.")
            return
        command = self._launch_download(self.dash_mpd_cli_argv, "dash-mpd-cli")
        if not command:
            return
        try:
            self.thread = DownloadThread(command)
            self.thread.finished.connect(self.on_download_finished)
            self.thread.error.connect(self.on_download_error)
            self.thread.start()
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def on_download_finished(self):
        QMessageBox.information(self, "Success", "Download finished successfully.")

    def on_download_error(self, error_message):
        QMessageBox.critical(self, "Error", f"Download failed: {error_message}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = AllHell3App()
    window.show()
    sys.exit(app.exec())
