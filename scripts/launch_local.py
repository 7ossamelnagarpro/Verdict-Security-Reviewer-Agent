"""Desktop entrypoint: open or start the local Waitress service without a terminal."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.request
import webbrowser
from pathlib import Path


def main():
    repository = Path(__file__).resolve().parents[1]
    url = "http://127.0.0.1:8765"

    def health():
        try:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(url + "/api/health", timeout=1) as response:
                return json.load(response)
        except (OSError, ValueError):
            return None

    state = health()
    if state:
        if (
            state.get("ui_version") != "2"
            or Path(state.get("repository", "")).resolve() != repository
        ):
            raise RuntimeError(
                "An older or different Verdict instance is using port 8765. Stop its server (Ctrl+C in its PowerShell window), then open this shortcut again."
            )
        webbrowser.open(url)
        return
    from security_reviewer_v2.web.storage import data_root

    logs = data_root() / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["PATH"] = str(Path(sys.executable).parent) + os.pathsep + env.get("PATH", "")
    with (logs / "web-server.log").open("a", encoding="utf-8") as log:
        process = subprocess.Popen(
            [sys.executable, str(repository / "scripts" / "run_local_web.py")],
            cwd=repository,
            env=env,
            stdout=log,
            stderr=log,
            stdin=subprocess.DEVNULL,
            creationflags=(subprocess.CREATE_NO_WINDOW | subprocess.DETACHED_PROCESS)
            if os.name == "nt"
            else 0,
            start_new_session=os.name != "nt",
        )
    for _ in range(40):
        if health():
            webbrowser.open(url)
            return
        if process.poll() is not None:
            break
        time.sleep(0.5)
    raise RuntimeError(f"Local server did not start. Inspect {logs / 'web-server.log'}")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        import tkinter
        from tkinter import messagebox

        window = tkinter.Tk()
        window.withdraw()
        messagebox.showerror("Verdict startup", str(error))
        window.destroy()
        raise SystemExit(1)
