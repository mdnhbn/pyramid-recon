"""Run Pyramid Recon as a loopback-only local web app."""

from __future__ import annotations

import socket
import threading
import time
import urllib.error
import urllib.request
import webbrowser
import argparse
import json
from pathlib import Path

import uvicorn


ROOT = Path(__file__).resolve().parent
HOST = "127.0.0.1"


def available_port() -> int:
    for port in range(8000, 8011):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind((HOST, port))
                return port
            except OSError:
                continue
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((HOST, 0))
        return int(sock.getsockname()[1])


def wait_until_ready(server: uvicorn.Server, url: str, timeout: float = 30.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not server.started and not server.should_exit:
            time.sleep(0.2)
            continue
        try:
            with urllib.request.urlopen(f"{url}/api/health", timeout=1.5) as response:
                payload = json.loads(response.read(4096).decode("utf-8"))
            if payload.get("status") == "ok" and payload.get("app") == "Pyramid Recon" and payload.get("phases") == 10:
                return True
        except (OSError, urllib.error.URLError, ValueError):
            time.sleep(0.25)
    return False


def main(open_browser: bool = True) -> int:
    port = available_port()
    url = f"http://{HOST}:{port}"
    config = uvicorn.Config("app:app", host=HOST, port=port, log_level="info", access_log=False, app_dir=str(ROOT))
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, name="pyramid-recon-server", daemon=True)
    thread.start()

    try:
        if not wait_until_ready(server, url):
            server.should_exit = True
            thread.join(timeout=5)
            print("Pyramid Recon did not become ready. Check the Python output above and try again.")
            return 1
        print(f"Pyramid Recon is running locally at {url}")
        print("This server listens only on this PC. Press Ctrl+C here to stop it.")
        if open_browser:
            webbrowser.open(url)
        thread.join()
    except KeyboardInterrupt:
        print("\nStopping the local Pyramid Recon server…")
        server.should_exit = True
        thread.join(timeout=10)
    finally:
        server.should_exit = True
        if thread.is_alive():
            thread.join(timeout=5)
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the local Pyramid Recon dashboard.")
    parser.add_argument("--no-browser", action="store_true", help="Do not open a browser automatically.")
    arguments = parser.parse_args()
    raise SystemExit(main(open_browser=not arguments.no_browser))
