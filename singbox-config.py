import json
import os
from urllib.parse import parse_qs, unquote, urlparse


DEFAULT_DNS_REMOTE = "1.1.1.1"
DEFAULT_DNS_DIRECT = "1.1.1.1"


def ensure_runtime_defaults(config, proxy_tag="proxy"):
    config.setdefault("log", {"level": "info"})

    outbounds = config.setdefault("outbounds", [])
    existing_tags = {
        outbound.get("tag")
        for outbound in outbounds
        if isinstance(outbound, dict) and outbound.get("tag")
    }

    if "direct" not in existing_tags:
        outbounds.append({"type": "direct", "tag": "direct"})
    if "block" not in existing_tags:
        outbounds.append({"type": "block", "tag": "block"})

    if "dns" not in config:
        config["dns"] = {
            "servers": [
                {
                    "type": "udp",
                    "tag": "dns-remote",
                    "server": DEFAULT_DNS_REMOTE,
                    "server_port": 53,
                    "detour": proxy_tag,
                },
                {
                    "type": "local",
                    "tag": "dns-direct",
                },
            ],
            "final": "dns-remote",
        }

    route = config.setdefault("route", {})
    route.setdefault("auto_detect_interface", True)
    route.setdefault("final", proxy_tag)
    route.setdefault("default_domain_resolver", "dns-direct")

    return config


def vless_to_singbox(vless_url, enable_tun=True):
    parsed = urlparse(vless_url)

    uuid = parsed.username
    server = parsed.hostname
    port = parsed.port

    params = parse_qs(parsed.query)

    security = params.get("security", ["none"])[0]
    network = params.get("type", ["tcp"])[0]
    path = unquote(params.get("path", [""])[0])
    host = params.get("host", [""])[0]
    sni = params.get("sni", [server])[0]
    flow = params.get("flow", [""])[0]
    fingerprint = params.get("fp", params.get("fingerprint", [""]))[0]
    alpn = [
        item.strip()
        for item in params.get("alpn", [""])[0].split(",")
        if item.strip()
    ]

    outbound = {
        "type": "vless",
        "tag": "proxy",
        "server": server,
        "server_port": port,
        "uuid": uuid
    }

    if flow:
        outbound["flow"] = flow

    # TLS
    if security in ["tls", "reality"]:
        outbound["tls"] = {
            "enabled": True,
            "server_name": sni
        }
        if fingerprint:
            outbound["tls"]["utls"] = {
                "enabled": True,
                "fingerprint": fingerprint,
            }
        if alpn:
            outbound["tls"]["alpn"] = alpn

    # Reality
    if security == "reality":
        public_key = params.get("pbk", [""])[0]
        short_id = params.get("sid", [""])[0]

        outbound["tls"]["reality"] = {
            "enabled": True,
            "public_key": public_key,
            "short_id": short_id
        }

    # Transport
    if network == "ws":
        outbound["transport"] = {
            "type": "ws",
            "path": path,
            "headers": {
                "Host": host
            } if host else {}
        }

    elif network == "grpc":
        service_name = params.get("serviceName", [""])[0]

        outbound["transport"] = {
            "type": "grpc",
            "service_name": service_name
        }

    config = {
        "log": {
            "level": "info"
        },
        "outbounds": [outbound]
    }

    # ✅ FIXED TUN (sing-box 1.12+ format)
    if enable_tun:
        config["inbounds"] = [
            {
                "type": "tun",
                "tag": "tun-in",
                "interface_name": "singtun0",
                "address": [
                    "172.19.0.1/30"
                ],
                "auto_route": True,
                "strict_route": True,
                "stack": "system"
            }
        ]

    return ensure_runtime_defaults(config)


def get_unique_filename(base_name):
    """Avoid overwriting existing files"""
    filename = f"{base_name}.json"
    counter = 1

    while os.path.exists(filename):
        filename = f"{base_name}_{counter}.json"
        counter += 1

    return filename


if __name__ == "__main__":
    while True:
        vless = input("Paste VLESS URL (or 'exit'): ").strip()

        if vless.lower() == "exit":
            break

        config = vless_to_singbox(vless)

        server = config["outbounds"][0]["server"]

        filename = get_unique_filename(server)

        with open(filename, "w") as f:
            json.dump(config, f, indent=2)

        print(f"Generated sing-box config: {filename}")
