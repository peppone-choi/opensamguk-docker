#!/usr/bin/env python3
"""Exercise real nginx HTTP/TLS routing in an isolated, synthetic Docker sandbox.

Requires an already installed nginx:1.27-alpine image; never pulls or builds.
Does not start an application, touch existing volumes, or load environment files.
"""

import hashlib
import http.client
import json
from pathlib import Path
import ssl
import subprocess
import tempfile
import time
import uuid

from test_nginx_campaign_routes import APP_PAGE_ROOTS, ROOT


def command(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT).strip()


def main():
    image = "nginx:1.27-alpine"
    command("docker", "image", "inspect", image, "--format", "{{.Id}}")
    owner = "campaign-route-" + uuid.uuid4().hex[:12]
    network, container = owner + "-net", owner + "-nginx"
    created_network = created_container = False
    checks = []
    source = (ROOT / "infra/nginx/nginx.conf").read_bytes()
    with tempfile.TemporaryDirectory(prefix=owner + "-") as directory:
        temporary = Path(directory)
        certs = temporary / "certs"
        certs.mkdir()
        (temporary / "battle-ws").mkdir()
        # A disposable TLS fixture, not an application credential or trust-store change.
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=localhost", "-keyout", str(certs / "opensamguk.key"),
            "-out", str(certs / "opensamguk.crt"),
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        config = source.decode()
        before, closing = config.rsplit("}", 1)
        assert not closing.strip(), "unexpected nginx trailing content"
        config = before + """
    server {
        listen 3001;
        location / {
            add_header X-Route-Fixture game-web always;
            return 200 "$request_uri\\n";
        }
    }
    server { listen 3000; return 418 "gateway-fallback"; }
    server { listen 8080; return 418 "gateway-api-fallback"; }
}
"""
        (temporary / "nginx.conf").write_text(config)
        try:
            command("docker", "network", "create", "--label", "opensamguk.route-test=" + owner, network)
            created_network = True
            command(
                "docker", "run", "-d", "--pull=never", "--name", container,
                "--label", "opensamguk.route-test=" + owner,
                "--network", network, "--network-alias", "sqa160-web-game",
                "--network-alias", "sa1-web-game", "--memory", "64m", "--cpus", "0.5",
                "--add-host", "gateway-api:127.0.0.1", "--add-host", "web-gateway:127.0.0.1",
                "-p", "127.0.0.1::80", "-p", "127.0.0.1::443",
                "-v", str(temporary / "nginx.conf") + ":/etc/nginx/nginx.conf:ro",
                "-v", str(certs) + ":/etc/nginx/certs:ro",
                "-v", str(temporary / "battle-ws") + ":/etc/nginx/battle-ws:ro",
                image,
            )
            created_container = True
            ports = {scheme: int(command("docker", "port", container, port).rsplit(":", 1)[1])
                     for scheme, port in (("http", "80/tcp"), ("https", "443/tcp"))}

            def probe(scheme, path, cookie, expected, preserve=False):
                cookie_case = "missing" if cookie is None else "valid" if cookie == "qa160" else "invalid"
                connection = (http.client.HTTPSConnection(
                    "127.0.0.1", ports[scheme], timeout=5, context=ssl._create_unverified_context(),
                ) if scheme == "https" else http.client.HTTPConnection("127.0.0.1", ports[scheme], timeout=5))
                try:
                    headers = {} if cookie is None else {"Cookie": "sam_server=" + cookie}
                    connection.request("GET", path, headers=headers)
                    response = connection.getresponse()
                    body = response.read().decode()
                    assert response.status == expected, (scheme, path, cookie_case, response.status)
                    if preserve:
                        assert response.getheader("X-Route-Fixture") == "game-web", (scheme, path)
                        assert body.strip() == path, (scheme, path, body)
                    checks.append({"scheme": scheme, "path": path, "cookieCase": cookie_case,
                                   "status": response.status, "preserved": preserve})
                finally:
                    connection.close()

            for attempt in range(50):
                try:
                    probe("http", "/health", None, 200)
                    break
                except (OSError, http.client.HTTPException):
                    time.sleep(0.1)
            else:
                raise RuntimeError("isolated nginx did not become ready")
            syntax = command("docker", "exec", container, "nginx", "-t")
            for scheme in ports:
                for page in sorted(APP_PAGE_ROOTS):
                    for suffix in ("", "/", "/detail?slot=1&next=%2Fgame%2Fhelp"):
                        path = "/game/" + page + suffix
                        probe(scheme, path, "qa160", 200, preserve=True)
                    for cookie in (None, "", "PEP", "pep-1", "../qa160", "a" * 49, "territory", "all"):
                        probe(scheme, "/game/" + page, cookie, 404)
                for public_id in ("qa160", "a1"):
                    probe(scheme, "/game/" + public_id + "/territory?slot=1", None, 200, preserve=True)
                for path in ("/game/PEP", "/game/pep-1", "/game/" + "a" * 49):
                    probe(scheme, path, "qa160", 404)
            print(json.dumps({
                "status": "PASS", "image": image, "sourceSha256": hashlib.sha256(source).hexdigest(),
                "nginxSyntax": syntax, "checks": checks,
                "scope": "synthetic route branching; actual application acceptance NOT_RUN",
            }, indent=2))
        finally:
            # Remove only resources this invocation successfully created and still owns.
            if created_container and command("docker", "inspect", "--format",
                    '{{index .Config.Labels "opensamguk.route-test"}}', container) == owner:
                command("docker", "rm", "-f", container)
            if created_network and command("docker", "network", "inspect", "--format",
                    '{{index .Labels "opensamguk.route-test"}}', network) == owner:
                command("docker", "network", "rm", network)


if __name__ == "__main__":
    main()
