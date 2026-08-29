#!/usr/bin/env python3
"""Collect host-owned network evidence for an isolated candidate run."""
import argparse
import hashlib
import json
import os
import pathlib
import re
import shlex
import shutil
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit

PRIVATE_IPV4 = re.compile(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)")
PORTS = {"api": 8765, "qdrant": 6333, "ui": 3000}
MCP_LOOPBACK_HOSTS = {"127.0.0.1", "::1"}
PEER_RESULTS = {"api": "reachable", "qdrant": "unreachable", "ui": "unreachable"}
APPROVED_PEER_KEY_PATH = pathlib.Path(os.path.expanduser("~/.ssh/id_ed25519_codex_macmini_100_76_95_127"))
APPROVED_PEER_KNOWN_HOSTS_PATH = pathlib.Path(os.path.expanduser("~/.ssh/known_hosts"))


def command_output(command, timeout=5):
    return subprocess.check_output(command, stderr=subprocess.DEVNULL, timeout=timeout, text=True).strip()


def tailscale_executable():
    executable = shutil.which("tailscale") or next(
        (path for path in ("/Applications/Tailscale.app/Contents/MacOS/tailscale", "/Applications/Tailscale.app/Contents/MacOS/Tailscale") if os.access(path, os.X_OK)),
        None,
    )
    if not executable:
        raise RuntimeError("tailscale executable is unavailable")
    return executable


def serve_status(executable):
    raw = command_output([executable, "serve", "status", "--json"], timeout=10)
    try:
        status = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("tailscale serve status is malformed") from exc
    if not isinstance(status, dict):
        raise RuntimeError("tailscale serve status is malformed")
    return status


def _loopback_mcp_target(target, web=False):
    if not isinstance(target, str) or not target:
        return False
    value = target if web else "//" + target
    parsed = urlsplit(value)
    if web and parsed.scheme not in {"http", "https"}:
        return False
    return parsed.hostname in MCP_LOOPBACK_HOSTS and parsed.port == PORTS["api"] and not parsed.path.rstrip("/")


def validate_serve_route(status):
    if not isinstance(status, dict):
        raise RuntimeError("tailscale serve status is malformed")
    allow_funnel = status.get("AllowFunnel", {})
    if allow_funnel is not None and (not isinstance(allow_funnel, dict) or any(allow_funnel.values())):
        raise RuntimeError("tailscale Funnel exposure is not allowed")
    routes = []
    tcp = status.get("TCP", {})
    if tcp is not None and not isinstance(tcp, dict):
        raise RuntimeError("tailscale serve TCP status is malformed")
    for listener, configuration in (tcp or {}).items():
        if not isinstance(configuration, dict) or set(configuration) != {"TCPForward"}:
            raise RuntimeError("tailscale serve TCP route is malformed")
        target = configuration["TCPForward"]
        if not _loopback_mcp_target(target):
            raise RuntimeError("tailscale serve route is not loopback MCP only")
        routes.append({"kind": "tcp", "listener": str(listener), "target": target})

    web = status.get("Web", {})
    if web is not None and not isinstance(web, dict):
        raise RuntimeError("tailscale serve Web status is malformed")
    for listener, configuration in (web or {}).items():
        if not isinstance(configuration, dict) or not isinstance(configuration.get("Handlers"), dict):
            raise RuntimeError("tailscale serve Web route is malformed")
        handlers = configuration["Handlers"]
        for path, handler in handlers.items():
            if not isinstance(handler, dict) or set(handler) != {"Proxy"}:
                raise RuntimeError("tailscale serve Web handler is malformed")
            target = handler["Proxy"]
            if not _loopback_mcp_target(target, web=True):
                raise RuntimeError("tailscale serve route is not loopback MCP only")
            routes.append({"kind": "web", "listener": str(listener), "path": str(path), "target": target})

    if len(routes) != 1:
        raise RuntimeError("tailscale serve must expose exactly one loopback MCP route")
    return routes[0]


def addresses():
    try:
        output = command_output(["/sbin/ifconfig"])
    except (OSError, subprocess.SubprocessError):
        return []
    values = []
    for line in output.splitlines():
        match = re.search(r"\binet6?\s+([0-9a-fA-F:.]+)", line)
        if match and match.group(1) not in {"127.0.0.1", "::1"}:
            values.append(match.group(1).split("%", 1)[0])
    return values


def tailscale_addresses(executable):
    result = []
    for family in ("-4", "-6"):
        value = command_output([executable, "ip", family])
        if value:
            result.append(value)
    return result


def _secure_ssh_file(path, label):
    try:
        metadata = path.stat()
    except OSError as exc:
        raise RuntimeError("approved peer {} is unavailable".format(label)) from exc
    if not pathlib.Path(path).is_file() or metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
        raise RuntimeError("approved peer {} is not owner-only".format(label))


def _peer_hostname(host):
    if not isinstance(host, str) or not host or any(character.isspace() for character in host):
        raise RuntimeError("peer host is malformed")
    hostname = host.rsplit("@", 1)[-1]
    if not hostname or not re.fullmatch(r"[A-Za-z0-9_.:-]+", hostname) or hostname.startswith("-"):
        raise RuntimeError("peer host is malformed")
    return hostname


def _peer_host_key_evidence(host):
    hostname = _peer_hostname(host)
    _secure_ssh_file(APPROVED_PEER_KNOWN_HOSTS_PATH, "known-hosts file")
    try:
        evidence = command_output(
            ["/usr/bin/ssh-keygen", "-F", hostname, "-f", str(APPROVED_PEER_KNOWN_HOSTS_PATH)], timeout=5
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError("approved peer host-key evidence is unavailable") from exc
    if not evidence:
        raise RuntimeError("peer host is absent from the approved known-hosts file")
    return hashlib.sha256("\n".join(sorted(evidence.splitlines())).encode()).hexdigest()


def _validated_peer_command(command, host, target):
    try:
        command_parts = shlex.split(command)
    except ValueError as exc:
        raise RuntimeError("peer SSH command is malformed") from exc
    if not command_parts:
        raise RuntimeError("peer SSH command is empty")
    ssh_path = shutil.which("ssh")
    if not ssh_path or os.path.realpath(command_parts[0]) != os.path.realpath(ssh_path):
        raise RuntimeError("peer probe must use the system SSH executable")
    try:
        command_argv = [part.format(host=host, target=target) for part in command_parts]
    except (KeyError, ValueError) as exc:
        raise RuntimeError("peer SSH command has unsupported placeholders") from exc
    if any("{" in part or "}" in part for part in command_argv):
        raise RuntimeError("peer SSH command has unresolved placeholders")
    hostname = _peer_hostname(host)
    if hostname not in command_argv:
        raise RuntimeError("peer SSH command must address the approved peer host")
    key_path = str(APPROVED_PEER_KEY_PATH)
    known_hosts_path = str(APPROVED_PEER_KNOWN_HOSTS_PATH)
    identity_paths = []
    known_hosts_values = []
    strict_host_key_values = []
    identities_only_values = []
    forbidden_options = {
        "proxycommand",
        "proxyjump",
        "localcommand",
        "remotecommand",
        "knownhostscommand",
        "hostkeyalias",
        "identityagent",
    }
    option_arguments = {"-b", "-c", "-D", "-E", "-I", "-i", "-J", "-L", "-l", "-m", "-O", "-o", "-p", "-R", "-S", "-W", "-w"}
    destination_index = None
    index = 1
    while index < len(command_argv):
        part = command_argv[index]
        option = None
        option_value = None
        if part.startswith("-o") and part != "-o":
            option_value = part[2:]
            if "=" not in option_value:
                raise RuntimeError("peer SSH option is malformed")
            option, option_value = option_value.split("=", 1)
        elif part in option_arguments:
            if index + 1 >= len(command_argv):
                raise RuntimeError("peer SSH option is incomplete")
            option = part
            option_value = command_argv[index + 1]
        elif part.startswith("-"):
            if part not in {"-4", "-6", "-A", "-a", "-C", "-N", "-n", "-q", "-T", "-t", "-v", "-x", "-X"}:
                raise RuntimeError("peer SSH option is not approved")
            index += 1
            continue
        else:
            if destination_index is not None:
                index += 1
                continue
            destination_index = index
            index += 1
            continue
        if part == "-i":
            identity_paths.append(option_value)
        elif option == "-o":
            if "=" not in option_value:
                raise RuntimeError("peer SSH option is malformed")
            option_name, option_value = option_value.split("=", 1)
            option_name = option_name.lower()
            if option_name in forbidden_options:
                raise RuntimeError("peer SSH wrapper options are not allowed")
            if option_name == "userknownhostsfile":
                known_hosts_values.append(option_value)
            if option_name == "stricthostkeychecking":
                strict_host_key_values.append(option_value.lower())
            if option_name == "identitiesonly":
                identities_only_values.append(option_value.lower())
        index += 1 if part.startswith("-o") and part != "-o" else 2
    if destination_index is None or command_argv[destination_index] != host:
        raise RuntimeError("peer SSH command must address the approved peer host")
    if identity_paths != [key_path] or known_hosts_values != [known_hosts_path] or strict_host_key_values != ["yes"] or identities_only_values != ["yes"]:
        raise RuntimeError("peer SSH command is not bound to the approved identity and host-key policy")
    if command_argv.count(host) != 1:
        raise RuntimeError("peer SSH command must contain exactly one peer destination")
    if destination_index == len(command_argv) - 1:
        raise RuntimeError("peer SSH command must run the approved remote probe")
    remote_argv = command_argv[destination_index + 1 :]
    if not remote_argv or any(token in {"sh", "bash", "zsh", "fish", "eval", "exec"} for token in remote_argv):
        raise RuntimeError("peer SSH command must not use a remote shell wrapper")
    if target not in remote_argv:
        raise RuntimeError("peer SSH command must pass the tailnet target to the peer probe")
    return command_argv


def peer_probe(host, command, input_path, target):
    contract = {
        "status": "unverified",
        "host": host,
        "transport": "ssh",
        "input": None,
        "result": None,
    }
    if not host and not command and not input_path:
        contract["reason"] = "independent peer probe contract was not supplied"
        return contract
    if not host or not command or not input_path:
        contract["reason"] = "peer host, command, and input are required together"
        return contract
    input_path = pathlib.Path(input_path)
    try:
        input_bytes = input_path.read_bytes()
        contract["input"] = {"name": input_path.name, "sha256": hashlib.sha256(input_bytes).hexdigest()}
        _secure_ssh_file(APPROVED_PEER_KEY_PATH, "private key")
        contract["peer_identity"] = {
            "host": host,
            "host_key_evidence_sha256": _peer_host_key_evidence(host),
        }
        command_argv = _validated_peer_command(command, host, target)
        contract["command_sha256"] = hashlib.sha256(
            json.dumps(command_argv, separators=(",", ":")).encode()
        ).hexdigest()
        completed = subprocess.run(
            command_argv,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=20,
            check=False,
        )
        result = json.loads(completed.stdout.decode())
    except (KeyError, OSError, ValueError, RuntimeError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        contract["reason"] = "independent peer probe failed: {}".format(type(exc).__name__)
        return contract
    contract["result"] = result
    if completed.returncode != 0 or not isinstance(result, dict):
        contract["reason"] = "peer probe command did not return a JSON object successfully"
        return contract
    if result.get("host") != host or result.get("target") != target or result.get("reachable") is not True or result.get("results") != PEER_RESULTS:
        contract["reason"] = "peer probe result does not prove the Serve MCP route"
        return contract
    contract["status"] = "verified"
    return contract


def probe(address, port, timeout=2):
    try:
        with socket.create_connection((address, port), timeout=timeout):
            return "reachable"
    except OSError:
        return "unreachable"


def listener_process(address):
    code = """
import socket
import sys

address = sys.argv[1]
family = socket.AF_INET6 if ":" in address else socket.AF_INET
server = socket.socket(family, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((address, 0))
server.listen(8)
print(server.getsockname()[1], flush=True)
while True:
    server.settimeout(1)
    try:
        connection, _ = server.accept()
        connection.close()
    except socket.timeout:
        pass
"""
    process = subprocess.Popen([sys.executable, "-c", code, address], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    line = process.stdout.readline().strip() if process.stdout else ""
    if not line.isdigit():
        process.kill()
        process.wait()
        raise RuntimeError("host listener failed to start")
    return process, int(line)


def listener_command_hash(pid):
    output = command_output(["/bin/ps", "-p", str(pid), "-o", "uid=,command="], timeout=5)
    fields = output.split(None, 1)
    if len(fields) != 2 or fields[0] != str(os.getuid()):
        raise RuntimeError("host listener ownership could not be verified")
    return hashlib.sha256(fields[1].encode()).hexdigest()


def docker_loopback_bindings(context, docker_host):
    docker = shutil.which("docker")
    if not docker:
        raise RuntimeError("docker executable is unavailable")
    environment = {
        "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME": os.path.expanduser("~"),
        "DOCKER_CONTEXT": context,
        "DOCKER_HOST": docker_host,
    }
    docker_command = [docker, "--config", str(pathlib.Path.home() / ".docker"), "--context", context]
    output = subprocess.check_output(
        [*docker_command, "ps", "-q", "--filter", "label=com.docker.compose.project=openmemory"],
        stderr=subprocess.DEVNULL,
        timeout=15,
        env=environment,
        text=True,
    ).strip()
    bindings = {"qdrant": False, "ui": False}
    for container in output.splitlines():
        inspect = json.loads(subprocess.check_output(
            [*docker_command, "inspect", container], stderr=subprocess.DEVNULL, timeout=15, env=environment, text=True
        ))[0]
        name = str(inspect.get("Name", "")).lstrip("/")
        ports = inspect.get("NetworkSettings", {}).get("Ports", {}) or {}
        for key, service in (("6333/tcp", "qdrant"), ("3000/tcp", "ui")):
            for binding in ports.get(key) or []:
                if binding.get("HostIp") in {"127.0.0.1", "::1"}:
                    bindings[service] = True
        if name == "mem0_store" and not ports.get("6333/tcp"):
            bindings["qdrant"] = False
    if not all(bindings.values()):
        raise RuntimeError("Qdrant/UI loopback bindings are not proven")
    return bindings


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("run_id")
    parser.add_argument("output", type=pathlib.Path)
    parser.add_argument("docker_context")
    parser.add_argument("docker_host")
    parser.add_argument("--peer-host", default=os.getenv("OPENMEMORY_TAILNET_PEER_HOST"))
    parser.add_argument("--peer-command", default=os.getenv("OPENMEMORY_TAILNET_PEER_COMMAND"))
    parser.add_argument("--peer-input", type=pathlib.Path, default=os.getenv("OPENMEMORY_TAILNET_PEER_INPUT"))
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9]{8}-[0-9]{6}-[0-9]+", args.run_id):
        raise SystemExit("invalid run id")
    executable = tailscale_executable()
    serve = serve_status(executable)
    serve_route = validate_serve_route(serve)
    ts_ips = tailscale_addresses(executable)
    tailnet = next((value for value in ts_ips if "." in value), "")
    tailnet_ipv6 = next((value for value in ts_ips if ":" in value), "")
    host_addresses = addresses()
    ipv6 = next((value for value in host_addresses if ":" in value and value not in ts_ips), "")
    lan = next((value for value in host_addresses if "." in value and PRIVATE_IPV4.match(value) and value != tailnet), "")
    if not tailnet or not tailnet_ipv6 or not ipv6 or not lan:
        raise SystemExit("tailnet, LAN, and non-tailnet IPv6 addresses are required")
    loopback = {service: probe("127.0.0.1", port) for service, port in PORTS.items()}
    if any(value != "reachable" for value in loopback.values()):
        raise SystemExit("required localhost service is unreachable")
    listener, port = listener_process(tailnet)
    try:
        command_hash = listener_command_hash(listener.pid)
        if probe(tailnet, port) != "reachable":
            raise SystemExit("host listener is not reachable on tailnet")
        remote = {
            label: {service: probe(address, service_port) for service, service_port in PORTS.items()}
            for label, address in (("tailnet", tailnet), ("lan", lan), ("ipv6", ipv6))
        }
        if any(result != "unreachable" for label in ("lan", "ipv6") for result in remote[label].values()):
            raise SystemExit("non-tailnet service exposure violates the network policy")
        peer = peer_probe(args.peer_host, args.peer_command, args.peer_input, tailnet)
        remote["tailnet"] = peer.get("result", {}).get("results", {}) if isinstance(peer.get("result"), dict) else {}
        listener_record = {
            "address": tailnet,
            "source": "host-probe",
            "method": "tcp-listen",
            "port": port,
            "pid": listener.pid,
            "command_sha256": command_hash,
            "reachable": True,
            "verified_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }
        listener_record["evidence_sha256"] = hashlib.sha256(json.dumps(listener_record, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        document = {
            "schema": 1,
            "kind": "openmemory.host-network-evidence",
            "run_id": args.run_id,
            "source": "host",
            "captured_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "complete": peer["status"] == "verified",
            "remote_probe": peer["status"],
            "remote_listener": listener_record,
            "probe_evidence": {
                "tailnet": {"address": tailnet, "method": "tcp-connect", "results": remote["tailnet"]},
                "lan": {"address": lan, "method": "tcp-connect", "results": remote["lan"]},
                "ipv6": {"address": ipv6, "method": "tcp-connect", "results": remote["ipv6"]},
            },
            "loopback_bindings": docker_loopback_bindings(args.docker_context, args.docker_host),
            "tailscale": {
                "ip4": tailnet,
                "ip6": tailnet_ipv6,
                "executable": executable,
                "serve_status": serve,
                "serve_route": {**serve_route, "verified": True},
                "peer_probe": peer,
            },
            "host_identity_sha256": hashlib.sha256(socket.gethostname().encode()).hexdigest(),
        }
        args.output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        args.output.write_text(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
        args.output.chmod(0o600)
        if peer["status"] != "verified":
            raise SystemExit("independent tailnet peer probe is unverified; NO-GO")
    finally:
        listener.terminate()
        try:
            listener.wait(timeout=2)
        except subprocess.TimeoutExpired:
            listener.kill()
            listener.wait()


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        raise SystemExit(str(exc)) from exc
