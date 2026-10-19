"""
Cyber-Shield monitoring agent.

Runs on each authorized laboratory computer (Windows). It:
  * registers the computer with the Cyber-Shield server using the enrollment key,
  * sends a heartbeat (IP address, connection type, OS) every few seconds,
  * watches the configured folders and reports file created/modified/deleted/moved
    events with each file's SHA-256 hash,
  * uploads a file for VirusTotal analysis only when an Admin requests it from the
    dashboard, and only if the file is inside a watched folder and unchanged.

Every request after registration is signed with HMAC-SHA256 using the secret the
server issued, so the secret itself never travels over the network again.

Usage:
    python cyber_shield_agent.py              run the agent
    python cyber_shield_agent.py --check      test connectivity to the server and exit
    python cyber_shield_agent.py --config C:\\path\\config.json
"""

from __future__ import annotations

import argparse
import fnmatch
import glob
import hashlib
import hmac
import ipaddress
import json
import logging
import logging.handlers
import os
import platform
import queue
import socket
import sys
import threading
import time
import uuid
from pathlib import Path
from urllib.parse import urlencode, urlparse

import requests

try:
    import psutil
except ImportError:  # psutil only improves connection detection
    psutil = None

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

AGENT_NAME = "Cyber-Shield Agent"
AGENT_VERSION = "4.0.0"
AGENT_DIR = Path(__file__).resolve().parent
STATE_FILE = AGENT_DIR / "state.json"
QUEUE_FILE = AGENT_DIR / "queue.json"
MAX_BATCH = 100
MAX_QUEUED_EVENTS = 5000

DEFAULT_CONFIG = {
    "server_url": "http://192.168.1.10:8080",
    "enrollment_key": "",
    "lab_location": "Computer Lab 1",
    "watch_paths": ["C:\\Users\\*\\Downloads", "C:\\Users\\*\\Desktop", "C:\\Users\\*\\Documents"],
    "include_extensions": [],
    "exclude_patterns": ["~$*", "*.tmp", "*.crdownload", "*.part", "*.partial", "desktop.ini", "thumbs.db", "*.lnk"],
    "max_hash_mb": 200,
    "connection_type": "auto",
    "verify_tls": True,
    "request_timeout_seconds": 20,
    "log_file": "logs/cyber_shield_agent.log",
}

# Default subnets handed out by phone hotspots (iPhone and many Android phones).
HOTSPOT_NETWORKS = [ipaddress.ip_network("172.20.10.0/28"), ipaddress.ip_network("192.168.43.0/24")]

log = logging.getLogger("cyber_shield_agent")


class AgentError(Exception):
    pass


class ReRegisterRequired(AgentError):
    pass


# ---------------------------------------------------------------------------
# Configuration and local state
# ---------------------------------------------------------------------------

def load_config(path: Path) -> dict:
    if not path.exists():
        raise AgentError(f"Config file not found: {path}. Copy config.example.json to config.json and edit it.")
    with path.open("r", encoding="utf-8") as handle:
        config = {**DEFAULT_CONFIG, **json.load(handle)}
    config["server_url"] = config["server_url"].rstrip("/")
    if not urlparse(config["server_url"]).scheme in ("http", "https"):
        raise AgentError("server_url must start with http:// or https://")
    if not config["enrollment_key"]:
        raise AgentError("enrollment_key is empty. Copy agent_enrollment_key from the server's config.local.php.")
    config["watch_paths"] = expand_watch_paths(config["watch_paths"])
    config["include_extensions"] = [e.lower().lstrip(".") for e in config["include_extensions"]]
    config["exclude_patterns"] = [p.lower() for p in config["exclude_patterns"]]
    return config


def expand_watch_paths(patterns: list) -> list:
    """Expands %VARIABLES% and wildcards such as C:\\Users\\*\\Downloads into existing folders."""
    paths = []
    for pattern in patterns:
        expanded = os.path.expandvars(os.path.expanduser(pattern))
        matches = glob.glob(expanded) if glob.has_magic(expanded) else [expanded]
        for match in matches:
            path = os.path.abspath(match)
            if path not in paths:
                paths.append(path)
    return paths


def read_json(path: Path, default):
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return default


def write_json(path: Path, data) -> None:
    temporary = path.with_suffix(".tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(data, handle)
    os.replace(temporary, path)


def setup_logging(config: dict) -> None:
    log_path = Path(config["log_file"])
    if not log_path.is_absolute():
        log_path = AGENT_DIR / log_path
    log_path.parent.mkdir(parents=True, exist_ok=True)
    formatter = logging.Formatter("%(asctime)s [Cyber-Shield Agent] [%(levelname)s] %(message)s")
    file_handler = logging.handlers.RotatingFileHandler(log_path, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8")
    file_handler.setFormatter(formatter)
    console = logging.StreamHandler()
    console.setFormatter(formatter)
    log.setLevel(logging.INFO)
    log.addHandler(file_handler)
    log.addHandler(console)


# ---------------------------------------------------------------------------
# Computer and network details
# ---------------------------------------------------------------------------

def local_ip_for(server_url: str) -> str:
    """Returns the local IP address Windows would use to reach the server."""
    host = urlparse(server_url).hostname or "8.8.8.8"
    port = urlparse(server_url).port or 80
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect((host, port))
        return probe.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        probe.close()


def interface_for_ip(ip: str):
    if psutil is None:
        return None, None
    for name, addresses in psutil.net_if_addrs().items():
        if any(address.family == socket.AF_INET and address.address == ip for address in addresses):
            mac = next((a.address for a in addresses if a.family == psutil.AF_LINK), None)
            return name, mac
    return None, None


def detect_connection_type(ip: str, interface_name: str | None, configured: str) -> str:
    if configured in ("ethernet", "wifi", "hotspot"):
        return configured
    try:
        if any(ipaddress.ip_address(ip) in network for network in HOTSPOT_NETWORKS):
            return "hotspot"
    except ValueError:
        pass
    name = (interface_name or "").lower()
    if any(word in name for word in ("wi-fi", "wifi", "wireless", "wlan")):
        return "wifi"
    if any(word in name for word in ("ethernet", "local area connection", "eth", "lan")):
        return "ethernet"
    return "unknown"


def os_version() -> str:
    if platform.system() == "Windows":
        release, version, _, _ = platform.win32_ver()
        edition = platform.win32_edition() if hasattr(platform, "win32_edition") else ""
        return f"Windows {release} {edition} ({version})".replace("  ", " ")
    return platform.platform()


def computer_details(config: dict) -> dict:
    ip = local_ip_for(config["server_url"])
    interface_name, mac = interface_for_ip(ip)
    if not mac:
        node = uuid.getnode()
        mac = ":".join(f"{(node >> shift) & 0xFF:02X}" for shift in range(40, -1, -8))
    return {
        "hostname": socket.gethostname(),
        "ip_address": ip,
        "mac_address": (mac or "").replace("-", ":").upper(),
        "os_version": os_version(),
        "agent_version": AGENT_VERSION,
        "connection_type": detect_connection_type(ip, interface_name, config["connection_type"]),
        "lab_location": config["lab_location"],
        "watched_paths": config["watch_paths"],
    }


# ---------------------------------------------------------------------------
# Server API client
# ---------------------------------------------------------------------------

class ServerClient:
    def __init__(self, config: dict):
        self.config = config
        self.session = requests.Session()
        self.session.headers["User-Agent"] = f"{AGENT_NAME}/{AGENT_VERSION}"
        verify = config["verify_tls"]
        if isinstance(verify, str) and not os.path.isabs(verify):
            verify = str(AGENT_DIR / verify)
        self.session.verify = verify
        if verify is False:
            log.warning("TLS certificate verification is disabled (verify_tls=false). Use only on a trusted lab LAN.")
        self.state = read_json(STATE_FILE, {})
        if not self.state.get("agent_uuid"):
            self.state["agent_uuid"] = str(uuid.uuid4())
            write_json(STATE_FILE, self.state)

    @property
    def registered(self) -> bool:
        return bool(self.state.get("agent_secret"))

    def url(self, query: str) -> str:
        return f"{self.config['server_url']}/agent_api.php?{query}"

    def register(self, details: dict) -> dict:
        response = self.session.post(
            self.url("action=register"),
            json={"agent_uuid": self.state["agent_uuid"], **details},
            headers={"X-CyberShield-Enrollment-Key": self.config["enrollment_key"]},
            timeout=self.config["request_timeout_seconds"],
        )
        data = self._parse(response)
        self.state["agent_secret"] = data["agent_secret"]
        self.state["computer_id"] = data["computer_id"]
        write_json(STATE_FILE, self.state)
        log.info("Registered with the Cyber-Shield server as computer #%s (%s).",
                 data["computer_id"], "authorized" if data["authorized"] else "waiting for Super Admin approval")
        return data

    def _signed_headers(self, query: str, body_hash: str) -> dict:
        timestamp = str(int(time.time()))
        payload = f"{self.state['agent_uuid']}\n{timestamp}\n{query}\n{body_hash}".encode()
        signature = hmac.new(self.state["agent_secret"].encode(), payload, hashlib.sha256).hexdigest()
        return {
            "X-CyberShield-Agent": self.state["agent_uuid"],
            "X-CyberShield-Timestamp": timestamp,
            "X-CyberShield-Signature": signature,
        }

    def call(self, action: str, body: dict) -> dict:
        query = urlencode({"action": action})
        raw = json.dumps(body).encode()
        headers = self._signed_headers(query, hashlib.sha256(raw).hexdigest())
        headers["Content-Type"] = "application/json"
        response = self.session.post(self.url(query), data=raw, headers=headers, timeout=self.config["request_timeout_seconds"])
        return self._parse(response)

    def upload(self, request_id: int, path: str, sha256: str) -> dict:
        query = urlencode({"action": "upload-file", "request_id": request_id})
        headers = self._signed_headers(query, sha256)
        with open(path, "rb") as handle:
            response = self.session.post(
                self.url(query), files={"file": (os.path.basename(path), handle, "application/octet-stream")},
                headers=headers, timeout=max(120, self.config["request_timeout_seconds"]),
            )
        return self._parse(response)

    @staticmethod
    def _parse(response: requests.Response) -> dict:
        try:
            data = response.json()
        except ValueError:
            raise AgentError(f"Server returned HTTP {response.status_code} without JSON. Is server_url correct?")
        if response.status_code == 401 and data.get("reregister"):
            raise ReRegisterRequired(data.get("message", "Registration is no longer valid."))
        if not response.ok or not data.get("ok"):
            error = AgentError(data.get("message") or f"HTTP {response.status_code}")
            error.status = response.status_code
            raise error
        return data


# ---------------------------------------------------------------------------
# File monitoring
# ---------------------------------------------------------------------------

def sha256_of(path: str, max_bytes: int):
    """Returns (size, sha256) once the file stops changing, or (size, None) if it cannot be hashed."""
    for _ in range(5):
        try:
            size = os.path.getsize(path)
            time.sleep(0.5)
            if os.path.getsize(path) != size:
                continue
            if size > max_bytes:
                return size, None
            digest = hashlib.sha256()
            with open(path, "rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
            return size, digest.hexdigest()
        except FileNotFoundError:
            return None, None
        except PermissionError:
            time.sleep(1)  # still being written by another program
        except OSError:
            return None, None
    try:
        return os.path.getsize(path), None
    except OSError:
        return None, None


class WatchHandler(FileSystemEventHandler):
    TYPES = {"created": "created", "modified": "modified", "deleted": "deleted", "moved": "moved"}

    def __init__(self, agent: "Agent"):
        self.agent = agent

    def on_any_event(self, event: FileSystemEvent) -> None:
        if event.is_directory or event.event_type not in self.TYPES:
            return
        path = getattr(event, "dest_path", None) if event.event_type == "moved" else event.src_path
        if path and self.agent.should_watch(path):
            self.agent.raw_events.put((self.TYPES[event.event_type], path, time.time()))


class Agent:
    def __init__(self, config: dict):
        self.config = config
        self.client = ServerClient(config)
        self.raw_events: "queue.Queue[tuple[str, str, float]]" = queue.Queue()
        self.pending = read_json(QUEUE_FILE, [])
        self.pending_lock = threading.Lock()
        self.stop_event = threading.Event()
        self.authorized = False
        self.heartbeat_seconds = 30
        self.max_upload_bytes = 32 * 1024 * 1024
        self.recent: dict[tuple[str, str], float] = {}

    # -- filtering ---------------------------------------------------------
    def should_watch(self, path: str) -> bool:
        name = os.path.basename(path).lower()
        if any(fnmatch.fnmatch(name, pattern) for pattern in self.config["exclude_patterns"]):
            return False
        extensions = self.config["include_extensions"]
        return not extensions or name.rsplit(".", 1)[-1] in extensions

    def inside_watch_paths(self, path: str) -> bool:
        real = os.path.normcase(os.path.realpath(path))
        for root in self.config["watch_paths"]:
            base = os.path.normcase(os.path.realpath(root))
            if real == base or real.startswith(base.rstrip("\\/") + os.sep):
                return True
        return False

    # -- threads -----------------------------------------------------------
    def process_events(self) -> None:
        """Hashes files and turns raw watchdog events into queued file events."""
        max_bytes = int(self.config["max_hash_mb"]) * 1024 * 1024
        while not self.stop_event.is_set():
            try:
                event_type, path, detected = self.raw_events.get(timeout=1)
            except queue.Empty:
                continue
            key = (event_type, path)
            now = time.time()
            if event_type == "modified" and now - max(self.recent.get(key, 0), self.recent.get(("created", path), 0)) < 3:
                continue  # Windows fires "modified" right after "created", and editors fire several per save
            self.recent[key] = now
            if len(self.recent) > 5000:
                self.recent.clear()
            size, digest = (None, None) if event_type == "deleted" else sha256_of(path, max_bytes)
            if event_type != "deleted" and size is None:
                continue  # file vanished before it could be read
            with self.pending_lock:
                self.pending.append({
                    "event_uid": str(uuid.uuid4()),
                    "event_type": event_type,
                    "file_path": path,
                    "file_size": size,
                    "sha256": digest,
                    "detected_at": int(detected),
                })
                if len(self.pending) > MAX_QUEUED_EVENTS:
                    dropped = len(self.pending) - MAX_QUEUED_EVENTS
                    self.pending = self.pending[dropped:]
                    log.warning("Offline queue full - dropped %d oldest events.", dropped)

    def send_events(self) -> None:
        while not self.stop_event.wait(5):
            if not self.authorized or not self.client.registered:
                self._save_queue()
                continue
            with self.pending_lock:
                batch = self.pending[:MAX_BATCH]
            if not batch:
                continue
            try:
                result = self.client.call("file-events", {"events": batch})
                with self.pending_lock:
                    self.pending = self.pending[len(batch):]
                log.info("Sent %d file events (%d accepted).", len(batch), result.get("accepted", 0))
            except ReRegisterRequired as error:
                log.warning("%s", error)
                self.client.state.pop("agent_secret", None)
            except (AgentError, requests.RequestException) as error:
                if getattr(error, "status", None) == 403:
                    self.authorized = False
                log.warning("Could not send file events (%s). They stay queued and will be retried.", error)
            self._save_queue()

    def _save_queue(self) -> None:
        with self.pending_lock:
            snapshot = list(self.pending)
        try:
            write_json(QUEUE_FILE, snapshot)
        except OSError as error:
            log.warning("Could not save offline queue: %s", error)

    def heartbeat_loop(self) -> None:
        delay = 0
        while not self.stop_event.wait(delay):
            try:
                details = computer_details(self.config)
                if not self.client.registered:
                    data = self.client.register(details)
                    self.authorized = data["authorized"]
                    self.heartbeat_seconds = data["heartbeat_seconds"]
                data = self.client.call("heartbeat", {
                    key: details[key] for key in ("ip_address", "connection_type", "agent_version", "os_version", "watched_paths")
                } | {"queued_events": len(self.pending)})
                if data["authorized"] != self.authorized:
                    log.info("Computer is %s.", "authorized by a Super Admin" if data["authorized"] else "NOT authorized - waiting for approval")
                self.authorized = data["authorized"]
                self.heartbeat_seconds = data["heartbeat_seconds"]
                self.max_upload_bytes = data.get("max_upload_bytes", self.max_upload_bytes)
                for request in data.get("upload_requests", []):
                    self.handle_upload(request)
                delay = self.heartbeat_seconds
            except ReRegisterRequired as error:
                log.warning("%s Registering again.", error)
                self.client.state.pop("agent_secret", None)
                delay = 5
            except (AgentError, requests.RequestException) as error:
                log.warning("Cannot reach the Cyber-Shield server at %s: %s", self.config["server_url"], error)
                delay = min(max(self.heartbeat_seconds, 10), 60)

    def handle_upload(self, request: dict) -> None:
        path = request["file_path"]
        reason = None
        if not self.inside_watch_paths(path):
            reason = "Requested file is outside the folders this agent watches."
        elif not os.path.isfile(path):
            reason = "The file no longer exists on the lab computer."
        elif os.path.getsize(path) > self.max_upload_bytes:
            reason = "The file is larger than the VirusTotal upload limit."
        else:
            _, digest = sha256_of(path, self.max_upload_bytes)
            if digest != request["sha256"]:
                reason = "The file has changed since the event was recorded."
        try:
            if reason:
                log.warning("Upload request #%s refused: %s", request["request_id"], reason)
                self.client.call("upload-failed", {"request_id": request["request_id"], "reason": reason})
                return
            self.client.upload(request["request_id"], path, request["sha256"])
            log.info("Uploaded %s for VirusTotal analysis (request #%s).", path, request["request_id"])
        except (AgentError, requests.RequestException) as error:
            log.warning("Upload for request #%s failed: %s", request["request_id"], error)

    # -- main --------------------------------------------------------------
    def run(self) -> None:
        log.info("%s %s starting on %s. Server: %s", AGENT_NAME, AGENT_VERSION, socket.gethostname(), self.config["server_url"])
        observer = Observer()
        handler = WatchHandler(self)
        for path in self.config["watch_paths"]:
            if os.path.isdir(path):
                observer.schedule(handler, path, recursive=True)
                log.info("Watching %s", path)
            else:
                log.warning("Watch path does not exist and is skipped: %s", path)
        observer.start()
        threads = [threading.Thread(target=target, name=target.__name__, daemon=True)
                   for target in (self.heartbeat_loop, self.process_events, self.send_events)]
        for thread in threads:
            thread.start()
        try:
            while not self.stop_event.is_set():
                time.sleep(1)
        except KeyboardInterrupt:
            log.info("Stopping %s.", AGENT_NAME)
        finally:
            self.stop_event.set()
            observer.stop()
            observer.join(timeout=5)
            self._save_queue()


def check_connectivity(config: dict) -> int:
    """Prints a step-by-step network diagnosis for lab technicians."""
    parsed = urlparse(config["server_url"])
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    details = computer_details(config)
    print(f"{AGENT_NAME} {AGENT_VERSION} connectivity check")
    print(f"  This computer : {details['hostname']}  IP {details['ip_address']}  ({details['connection_type']})")
    print(f"  Server        : {config['server_url']}")
    try:
        address = socket.gethostbyname(parsed.hostname)
        print(f"  [OK]   Server name resolves to {address}")
    except OSError as error:
        print(f"  [FAIL] Cannot resolve {parsed.hostname}: {error}")
        return 1
    try:
        socket.create_connection((address, port), timeout=5).close()
        print(f"  [OK]   TCP port {port} is reachable")
    except OSError as error:
        print(f"  [FAIL] Cannot open TCP port {port}: {error}")
        print("         Check that START_CYBER_SHIELD.bat is running, both PCs are on the same LAN/Wi-Fi,")
        print("         and Windows Firewall on the server allows the port.")
        return 1
    try:
        response = requests.post(f"{config['server_url']}/agent_api.php?action=ping", timeout=10,
                                 verify=ServerClient(config).session.verify)
        print(f"  [OK]   Cyber-Shield agent API answered (HTTP {response.status_code})")
    except requests.RequestException as error:
        print(f"  [FAIL] HTTP request failed: {error}")
        return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=f"{AGENT_NAME} - lab computer monitoring")
    parser.add_argument("--config", default=str(AGENT_DIR / "config.json"), help="path to config.json")
    parser.add_argument("--check", action="store_true", help="test connectivity to the server and exit")
    args = parser.parse_args()
    try:
        config = load_config(Path(args.config))
    except (AgentError, ValueError) as error:
        print(f"[{AGENT_NAME}] Configuration error: {error}", file=sys.stderr)
        return 2
    if args.check:
        return check_connectivity(config)
    setup_logging(config)
    Agent(config).run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
