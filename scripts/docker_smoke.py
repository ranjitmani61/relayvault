"""Exercise the built non-root container without mounting a personal vault."""

import json
import os
import secrets
import subprocess
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def main():
    env = dict(
        os.environ,
        RELAYVAULT_API_KEY=secrets.token_urlsafe(32),
        RELAYVAULT_WORKSPACES='{"smoke":["read","write"]}',
    )
    container = subprocess.check_output(
        [
            "docker",
            "run",
            "--rm",
            "-d",
            "-p",
            "127.0.0.1::8000",
            "-e",
            "RELAYVAULT_API_KEY",
            "-e",
            "RELAYVAULT_WORKSPACES",
            "relayvault-ci",
        ],
        env=env,
        text=True,
    ).strip()
    try:
        address = subprocess.check_output(["docker", "port", container, "8000"], text=True).strip()
        url = "http://" + address
        for _ in range(100):
            try:
                with urlopen(url + "/health", timeout=1) as response:
                    assert response.status == 200
                break
            except (URLError, ConnectionError):
                time.sleep(0.1)
        else:
            raise RuntimeError("Container did not become healthy")
        payload = json.dumps(
            {"workspace_id": "smoke", "source_model": "container", "objective": "demo@example.org"}
        ).encode()
        request = Request(
            url + "/v1/checkpoints/commit", data=payload, headers={"Content-Type": "application/json"}
        )
        try:
            urlopen(request, timeout=5)
        except HTTPError as exc:
            assert exc.code in (401, 403)
        else:
            raise AssertionError("Unauthenticated container request was accepted")
        request.add_header("Authorization", "Bearer " + env["RELAYVAULT_API_KEY"])
        with urlopen(request, timeout=5) as response:
            assert json.load(response)["redactions_applied"] == 1
        user = subprocess.check_output(["docker", "exec", container, "id", "-u"], text=True).strip()
        assert user == "10001"
        print("Container: non-root startup and authenticated REST checkpoint passed")
    finally:
        subprocess.run(["docker", "stop", "--time", "5", container], check=True, stdout=subprocess.DEVNULL)


if __name__ == "__main__":
    main()
