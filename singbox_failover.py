#!/usr/bin/env python3
"""Benchmark, select, and monitor sing-box VLESS configs."""

from __future__ import annotations

import argparse
import copy
import ipaddress
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    from rich.console import Console, Group
    from rich.live import Live
    from rich.panel import Panel
    from rich.table import Table

    RICH_AVAILABLE = True
except ImportError:
    Console = None
    Group = None
    Live = None
    Panel = None
    Table = None
    RICH_AVAILABLE = False


DEFAULT_DNS_REMOTE = "1.1.1.1"
DEFAULT_TUN_ADDRESS = "198.18.0.1/30"
TEST_URLS = (
    "https://cp.cloudflare.com/generate_204",
    "https://www.gstatic.com/generate_204",
    "https://cloudflare.com/cdn-cgi/trace",
)


@dataclass
class NodeState:
    path: Path
    server: str
    uuid: str
    base_config: dict[str, Any]
    label: str = ""
    status: str = "idle"
    latency_ms: float | None = None
    public_ip: str | None = None
    last_error: str | None = None
    success_count: int = 0
    failure_count: int = 0
    last_checked_at: float | None = None
    last_score: float = float("inf")

    @property
    def name(self) -> str:
        return self.label or self.path.stem


class Dashboard:
    def __init__(self, enabled: bool):
        self.enabled = enabled and RICH_AVAILABLE
        self.console = Console() if self.enabled else None
        self.live = None

    def start(self):
        if self.enabled:
            self.live = Live(self.render_placeholder(), console=self.console, refresh_per_second=4)
            self.live.start()

    def stop(self):
        if self.live:
            self.live.stop()
            self.live = None

    def update(self, renderable):
        if self.live:
            self.live.update(renderable)

    def print(self, message: str):
        if self.console:
            self.console.print(message)
        else:
            print(message)

    def render_placeholder(self):
        if not self.enabled:
            return None
        return Panel("Starting sing-box failover manager...", title="sing-box")


class SingboxFailoverManager:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.config_dir = Path(args.directory).resolve()
        self.console = Dashboard(enabled=not args.no_rich)
        self.nodes: list[NodeState] = []
        self.events: list[str] = []
        self.active_node: NodeState | None = None
        self.active_proc: subprocess.Popen | None = None
        self.active_log_path: Path | None = None
        self.active_log_handle = None
        self.active_temp_dir: Path | None = None
        self.monitor_port: int | None = None
        self.stop_requested = False
        self.shutdown_announced = False
        self.fail_streak = 0
        self.started_at = time.time()

    def log_event(self, message: str):
        timestamp = time.strftime("%H:%M:%S")
        self.events.append(f"[{timestamp}] {message}")
        self.events = self.events[-10:]
        self.refresh_ui()

    def stop_if_requested(self):
        if self.stop_requested:
            raise KeyboardInterrupt

    def refresh_ui(self):
        if self.console.enabled:
            self.console.update(self.build_dashboard())
        elif self.args.verbose:
            self.print_plain_snapshot()

    def build_dashboard(self):
        active_name = self.active_node.name if self.active_node else "-"
        active_server = self.active_node.server if self.active_node else "-"
        active_latency = self.format_latency(self.active_node.latency_ms if self.active_node else None)
        mode = "proxy-only" if self.args.proxy_only else "tun"
        proxy_port = str(self.monitor_port or "-")

        summary = Table.grid(expand=True)
        summary.add_column(justify="left")
        summary.add_column(justify="left")
        summary.add_row("Mode", mode)
        summary.add_row("Active", active_name)
        summary.add_row("Server", active_server)
        summary.add_row("Latency", active_latency)
        summary.add_row("Monitor Port", proxy_port)
        summary.add_row("Fail Streak", str(self.fail_streak))

        nodes_table = Table(expand=True)
        nodes_table.add_column("Node")
        nodes_table.add_column("Server")
        nodes_table.add_column("Status")
        nodes_table.add_column("Latency")
        nodes_table.add_column("Public IP")
        nodes_table.add_column("Failures")
        nodes_table.add_column("Last Error", overflow="fold")

        for node in sorted(self.nodes, key=self.node_sort_key):
            nodes_table.add_row(
                node.name,
                node.server,
                node.status,
                self.format_latency(node.latency_ms),
                node.public_ip or "-",
                str(node.failure_count),
                node.last_error or "-",
            )

        log_text = "\n".join(self.events[-8:]) or "No events yet."

        return Group(
            Panel(summary, title="Status", border_style="cyan"),
            Panel(nodes_table, title="Nodes", border_style="green"),
            Panel(log_text, title="Recent Events", border_style="magenta"),
        )

    def print_plain_snapshot(self):
        active = self.active_node.name if self.active_node else "-"
        print(f"\n[{time.strftime('%H:%M:%S')}] Active: {active} | Fail streak: {self.fail_streak}")
        for node in sorted(self.nodes, key=self.node_sort_key):
            latency = self.format_latency(node.latency_ms)
            print(
                f"  - {node.name}: status={node.status} latency={latency} "
                f"failures={node.failure_count} error={node.last_error or '-'}"
            )

    @staticmethod
    def format_latency(latency_ms: float | None) -> str:
        if latency_ms is None:
            return "-"
        return f"{latency_ms:.0f} ms"

    @staticmethod
    def tail_text(path: Path | None, lines: int = 8) -> str:
        if not path or not path.exists():
            return ""
        data = path.read_text(errors="replace").splitlines()
        return "\n".join(data[-lines:])

    @staticmethod
    def cleanup_temp_dir(temp_dir: Path | None):
        if not temp_dir or not temp_dir.exists():
            return
        for path in sorted(temp_dir.glob("**/*"), reverse=True):
            if path.is_file():
                path.unlink(missing_ok=True)
        for path in sorted(temp_dir.glob("**/*"), reverse=True):
            if path.is_dir():
                path.rmdir()
        temp_dir.rmdir()

    @staticmethod
    def node_sort_key(node: NodeState):
        ok = 0 if node.status in {"active", "ready", "healthy"} else 1
        return (ok, node.last_score, node.name)

    @staticmethod
    def is_ip_address(value: str | None) -> bool:
        if not value:
            return False
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    def resolve_server_ip(self, server: str, port: int) -> str:
        if self.is_ip_address(server):
            return server

        ipv4_candidates: list[str] = []
        fallback_candidates: list[str] = []
        for family, _, _, _, sockaddr in socket.getaddrinfo(server, port, type=socket.SOCK_STREAM):
            ip = sockaddr[0]
            if family == socket.AF_INET and ip not in ipv4_candidates:
                ipv4_candidates.append(ip)
            elif ip not in fallback_candidates:
                fallback_candidates.append(ip)

        if ipv4_candidates:
            return ipv4_candidates[0]
        if fallback_candidates:
            return fallback_candidates[0]
        return server

    def discover_nodes(self):
        self.stop_if_requested()
        json_files = sorted(
            path for path in self.config_dir.glob("*.json") if not path.name.startswith("_tmp-")
        )
        if not json_files:
            raise RuntimeError(f"No JSON configs found in {self.config_dir}")

        nodes: list[NodeState] = []
        for path in json_files:
            self.stop_if_requested()
            config = json.loads(path.read_text())
            outbounds = config.get("outbounds", [])
            if any(item.get("type") in {"selector", "urltest"} for item in outbounds):
                self.log_event(f"Skipping {path.name}: aggregate config, not a raw node file")
                continue

            vless_outbounds = [item for item in outbounds if item.get("type") == "vless"]
            if len(vless_outbounds) != 1:
                self.log_event(f"Skipping {path.name}: expected exactly one VLESS outbound")
                continue

            proxy = vless_outbounds[0]
            if not proxy:
                self.log_event(f"Skipping {path.name}: no VLESS outbound found")
                continue

            nodes.append(
                NodeState(
                    path=path,
                    label=path.stem,
                    server=proxy.get("server", "unknown"),
                    uuid=proxy.get("uuid", ""),
                    base_config=config,
                )
            )

        if not nodes:
            raise RuntimeError("No usable VLESS configs were found.")

        self.nodes = nodes
        self.log_event(f"Loaded {len(self.nodes)} VLESS configs from {self.config_dir}")

    def ensure_runtime_defaults(self, config: dict[str, Any], include_tun: bool, mixed_port: int):
        config = copy.deepcopy(config)
        config.setdefault("log", {})
        config["log"].setdefault("level", "info")

        outbounds = config.setdefault("outbounds", [])
        if not outbounds:
            raise RuntimeError("Config has no outbounds")

        proxy_outbound = next(
            (item for item in outbounds if item.get("type") not in {"direct", "block"}),
            outbounds[0],
        )
        proxy_tag = proxy_outbound.get("tag") or "proxy"
        proxy_outbound["tag"] = proxy_tag

        server = proxy_outbound.get("server")
        server_port = int(proxy_outbound.get("server_port", 443))
        tls = proxy_outbound.get("tls")
        if tls and tls.get("enabled") and isinstance(server, str) and not self.is_ip_address(server):
            tls.setdefault("server_name", server)
        if include_tun and isinstance(server, str) and not self.is_ip_address(server):
            proxy_outbound["server"] = self.resolve_server_ip(server, server_port)

        existing_tags = {
            item.get("tag")
            for item in outbounds
            if isinstance(item, dict) and item.get("tag")
        }
        if "direct" not in existing_tags:
            outbounds.append({"type": "direct", "tag": "direct"})
        if "block" not in existing_tags:
            outbounds.append({"type": "block", "tag": "block"})

        if "dns" not in config:
            config["dns"] = {
                "servers": [
                    {
                        "type": "https",
                        "tag": "dns-remote",
                        "server": DEFAULT_DNS_REMOTE,
                        "server_port": 443,
                        "path": "/dns-query",
                        "detour": proxy_tag,
                        "tls": {
                            "enabled": True,
                            "server_name": "cloudflare-dns.com",
                        },
                    },
                    {
                        "type": "local",
                        "tag": "dns-direct",
                    },
                ],
                "final": "dns-remote",
            }

        route = config.setdefault("route", {})
        route.setdefault("auto_detect_interface", include_tun)
        route.setdefault("final", proxy_tag)
        route.setdefault("default_domain_resolver", "dns-direct")
        route.setdefault(
            "rules",
            [
                {
                    "network": "udp",
                    "port": 53,
                    "action": "hijack-dns",
                },
                {
                    "network": "tcp",
                    "port": 53,
                    "action": "hijack-dns",
                },
                {
                    "ip_is_private": True,
                    "action": "route",
                    "outbound": "direct",
                },
            ],
        )

        inbounds = list(config.get("inbounds", []))
        if include_tun:
            tun_inbounds = [item for item in inbounds if item.get("type") == "tun"]
            if not tun_inbounds:
                tun_inbounds = [
                    {
                        "type": "tun",
                        "tag": "tun-in",
                        "interface_name": "singtun0",
                        "address": [DEFAULT_TUN_ADDRESS],
                        "auto_route": True,
                        "strict_route": True,
                        "stack": "system",
                    }
                ]
            inbounds = tun_inbounds
        else:
            inbounds = [item for item in inbounds if item.get("type") != "tun"]

        inbounds.append(
            {
                "type": "mixed",
                "tag": "manager-mixed",
                "listen": "127.0.0.1",
                "listen_port": mixed_port,
            }
        )
        config["inbounds"] = inbounds
        return config

    def write_runtime_config(self, node: NodeState, include_tun: bool, mixed_port: int):
        temp_dir = Path(tempfile.mkdtemp(prefix="singbox-manager-"))
        config_path = temp_dir / "runtime.json"
        log_path = temp_dir / "sing-box.log"
        runtime = self.ensure_runtime_defaults(node.base_config, include_tun=include_tun, mixed_port=mixed_port)
        config_path.write_text(json.dumps(runtime, indent=2))
        return temp_dir, config_path, log_path

    @staticmethod
    def reserve_port() -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            return sock.getsockname()[1]

    def spawn_singbox(self, config_path: Path, log_path: Path):
        handle = log_path.open("w", buffering=1)
        process = subprocess.Popen(
            ["sing-box", "run", "-c", str(config_path)],
            stdout=handle,
            stderr=subprocess.STDOUT,
            text=True,
        )
        return process, handle

    @staticmethod
    def stop_process(process: subprocess.Popen | None):
        if not process or process.poll() is not None:
            return
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)

    def wait_for_start(self, process: subprocess.Popen, port: int, timeout: float, log_path: Path):
        deadline = time.time() + timeout
        while time.time() < deadline:
            self.stop_if_requested()
            if process.poll() is not None:
                raise RuntimeError(self.tail_text(log_path) or "sing-box exited early")

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.3)
                try:
                    sock.connect(("127.0.0.1", port))
                    return
                except OSError:
                    time.sleep(0.2)

        raise RuntimeError(self.tail_text(log_path) or "timed out waiting for sing-box to listen")

    def fetch_via_proxy(self, port: int, url: str, timeout: float):
        self.stop_if_requested()
        proxy = f"http://127.0.0.1:{port}"
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy, "https": proxy})
        )
        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": "singbox-failover/1.0",
                "Cache-Control": "no-cache",
            },
        )
        started = time.perf_counter()
        with opener.open(request, timeout=timeout) as response:
            body = response.read(4096).decode("utf-8", errors="replace")
        latency_ms = (time.perf_counter() - started) * 1000
        return latency_ms, body

    @staticmethod
    def extract_public_ip(body: str) -> str | None:
        for line in body.splitlines():
            if line.startswith("ip="):
                return line.split("=", 1)[1].strip()
        return None

    def probe_node(self, node: NodeState):
        self.stop_if_requested()
        port = self.reserve_port()
        temp_dir, config_path, log_path = self.write_runtime_config(
            node, include_tun=False, mixed_port=port
        )
        node.status = "testing"
        node.last_error = None
        self.refresh_ui()

        process = None
        handle = None
        success = False
        try:
            subprocess.run(
                ["sing-box", "check", "-c", str(config_path)],
                check=True,
                capture_output=True,
                text=True,
            )

            process, handle = self.spawn_singbox(config_path, log_path)
            self.wait_for_start(process, port, self.args.start_timeout, log_path)

            measurements: list[float] = []
            public_ip = None
            last_error = None

            for url in TEST_URLS:
                self.stop_if_requested()
                try:
                    latency_ms, body = self.fetch_via_proxy(port, url, self.args.probe_timeout)
                    measurements.append(latency_ms)
                    public_ip = public_ip or self.extract_public_ip(body)
                    if len(measurements) >= self.args.samples:
                        break
                except (urllib.error.URLError, TimeoutError, OSError) as exc:
                    last_error = str(exc)

            if not measurements:
                raise RuntimeError(last_error or self.tail_text(log_path) or "all health checks failed")

            node.latency_ms = sum(measurements) / len(measurements)
            node.public_ip = public_ip
            node.last_error = None
            node.last_checked_at = time.time()
            node.last_score = node.latency_ms
            node.success_count += 1
            node.status = "ready"
            self.log_event(f"{node.name} is reachable in {node.latency_ms:.0f} ms")
            success = True
        except subprocess.CalledProcessError as exc:
            stderr = (exc.stderr or "").strip()
            node.last_error = stderr or exc.stdout.strip() or "sing-box check failed"
        except KeyboardInterrupt:
            node.last_error = "interrupted by user"
            raise
        except Exception as exc:  # noqa: BLE001
            node.last_error = str(exc)
        finally:
            self.stop_process(process)
            if handle:
                handle.close()
            if self.args.keep_temp:
                self.log_event(f"Kept temporary probe files in {temp_dir}")
            else:
                self.cleanup_temp_dir(temp_dir)

        if success:
            return True

        node.failure_count += 1
        node.last_checked_at = time.time()
        node.last_score = float("inf")
        node.status = "down"
        self.log_event(f"{node.name} failed test: {node.last_error}")
        return False

    def benchmark_nodes(self):
        self.log_event("Benchmarking all nodes...")
        for node in self.nodes:
            self.stop_if_requested()
            self.probe_node(node)

    def pick_best_node(self) -> NodeState | None:
        candidates = [node for node in self.nodes if node.latency_ms is not None and node.status != "down"]
        if not candidates:
            return None
        return min(candidates, key=lambda item: item.latency_ms or float("inf"))

    def activate_node(self, node: NodeState):
        self.stop_if_requested()
        if not self.args.proxy_only and os.geteuid() != 0:
            raise RuntimeError("TUN mode needs root privileges. Re-run with sudo or use --proxy-only.")

        self.deactivate_current()
        port = self.reserve_port()
        include_tun = not self.args.proxy_only
        temp_dir, config_path, log_path = self.write_runtime_config(
            node, include_tun=include_tun, mixed_port=port
        )
        process, handle = self.spawn_singbox(config_path, log_path)

        try:
            self.wait_for_start(process, port, self.args.start_timeout, log_path)
        except Exception:
            handle.close()
            self.stop_process(process)
            if not self.args.keep_temp:
                for path in sorted(temp_dir.glob("**/*"), reverse=True):
                    if path.is_file():
                        path.unlink(missing_ok=True)
                for path in sorted(temp_dir.glob("**/*"), reverse=True):
                    if path.is_dir():
                        path.rmdir()
                temp_dir.rmdir()
            raise

        self.active_node = node
        self.active_proc = process
        self.active_log_path = log_path
        self.active_log_handle = handle
        self.active_temp_dir = temp_dir
        self.monitor_port = port
        self.fail_streak = 0
        node.status = "active"
        self.log_event(f"Activated {node.name} on local monitor port {port}")

    def deactivate_current(self):
        self.stop_process(self.active_proc)
        if self.active_log_handle:
            self.active_log_handle.close()
            self.active_log_handle = None
        if self.active_node and self.active_node.status in {"active", "healthy", "unstable"}:
            self.active_node.status = "ready"
        self.active_proc = None
        self.active_log_path = None
        self.monitor_port = None
        if self.active_temp_dir and not self.args.keep_temp:
            self.cleanup_temp_dir(self.active_temp_dir)
        self.active_temp_dir = None

    def health_check_active(self):
        self.stop_if_requested()
        if not self.active_node or not self.monitor_port:
            raise RuntimeError("No active node")
        last_error = None
        for url in TEST_URLS:
            self.stop_if_requested()
            try:
                latency_ms, body = self.fetch_via_proxy(self.monitor_port, url, self.args.probe_timeout)
                self.active_node.latency_ms = latency_ms
                self.active_node.public_ip = self.active_node.public_ip or self.extract_public_ip(body)
                self.active_node.last_error = None
                self.active_node.last_checked_at = time.time()
                self.active_node.last_score = latency_ms
                self.active_node.status = "healthy"
                self.fail_streak = 0
                self.refresh_ui()
                return
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                last_error = str(exc)

        self.fail_streak += 1
        self.active_node.failure_count += 1
        self.active_node.last_error = last_error or self.tail_text(self.active_log_path)
        self.active_node.status = "unstable"
        self.log_event(
            f"Health check failed for {self.active_node.name} "
            f"({self.fail_streak}/{self.args.fail_threshold})"
        )
        if self.fail_streak < self.args.fail_threshold:
            return
        self.failover()

    def failover(self):
        self.stop_if_requested()
        failed = self.active_node
        if failed:
            failed.status = "down"
            failed.last_score = float("inf")
            self.log_event(f"Failing over away from {failed.name}")
        self.deactivate_current()
        self.benchmark_nodes()
        replacement = self.pick_best_node()
        if not replacement:
            raise RuntimeError("No working nodes remain after failover.")
        self.activate_node(replacement)

    def handle_signal(self, signum, _frame):
        self.stop_requested = True
        if not self.shutdown_announced:
            self.shutdown_announced = True
            print(f"\nReceived signal {signum}, shutting down...", flush=True)

    def run(self):
        signal.signal(signal.SIGINT, self.handle_signal)
        signal.signal(signal.SIGTERM, self.handle_signal)
        self.console.start()
        try:
            self.discover_nodes()
            self.benchmark_nodes()
            self.stop_if_requested()
            best = self.pick_best_node()
            if not best:
                raise RuntimeError("None of the VLESS configs passed the connectivity tests.")

            if self.args.check_only:
                self.log_event(f"Best node is {best.name} ({self.format_latency(best.latency_ms)})")
                return 0

            self.activate_node(best)
            self.log_event("Monitoring connectivity. Press Ctrl+C to stop.")

            while not self.stop_requested:
                time.sleep(self.args.interval)
                if self.active_proc and self.active_proc.poll() is not None:
                    log_tail = self.tail_text(self.active_log_path) or "sing-box exited"
                    if self.active_node:
                        self.active_node.last_error = log_tail
                    self.log_event("sing-box exited unexpectedly, trying another node")
                    self.failover()
                    continue
                self.health_check_active()

            return 0
        except KeyboardInterrupt:
            return 130
        finally:
            self.deactivate_current()
            self.console.stop()


def build_arg_parser():
    parser = argparse.ArgumentParser(
        description="Test sing-box VLESS configs, connect to the best one, and fail over automatically."
    )
    parser.add_argument(
        "--directory",
        default=str(Path(__file__).resolve().parent),
        help="Directory containing sing-box JSON configs.",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=15.0,
        help="Seconds between health checks after activation.",
    )
    parser.add_argument(
        "--probe-timeout",
        type=float,
        default=8.0,
        help="Timeout in seconds for each probe request.",
    )
    parser.add_argument(
        "--start-timeout",
        type=float,
        default=12.0,
        help="Time to wait for sing-box to start listening on the local test proxy.",
    )
    parser.add_argument(
        "--samples",
        type=int,
        default=2,
        help="Successful probe samples to collect per node before scoring it.",
    )
    parser.add_argument(
        "--fail-threshold",
        type=int,
        default=2,
        help="How many consecutive health check failures trigger failover.",
    )
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="Benchmark all nodes and print the best one without activating it.",
    )
    parser.add_argument(
        "--proxy-only",
        action="store_true",
        help="Run without TUN. Useful for unprivileged testing.",
    )
    parser.add_argument(
        "--keep-temp",
        action="store_true",
        help="Keep generated runtime configs and sing-box logs under /tmp for debugging.",
    )
    parser.add_argument(
        "--no-rich",
        action="store_true",
        help="Disable the rich dashboard and use plain stdout logging.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print plain status snapshots after each update when rich is disabled.",
    )
    return parser


def main():
    parser = build_arg_parser()
    args = parser.parse_args()
    manager = SingboxFailoverManager(args)
    try:
        return manager.run()
    except Exception as exc:  # noqa: BLE001
        message = f"ERROR: {exc}"
        if manager.console.enabled:
            manager.console.print(f"[bold red]{message}[/bold red]")
        else:
            print(message, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
