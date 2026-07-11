"""Privileged Hestia Anchor household certificate primitives.

This module is the mutation engine behind Caduceus' Rust certificate band.  Its
nine public primitives are intentionally small and composable; only
``state_commit`` replaces durable state.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Sequence

SCHEMA = "caduceus.household.tls.v1"
PLATFORMS = {"windows", "android", "chromeos", "linux", "macos"}


def _root() -> Path:
    return Path(os.environ.get("CADUCEUS_ROOT", "/"))


def _path(env: str, absolute: str) -> Path:
    override = os.environ.get(env)
    return Path(override) if override else _root() / absolute.lstrip("/")


def cert_dir() -> Path:
    return _path("CADUCEUS_CERT_DIR", "/var/lib/caduceus/certs")


def state_path() -> Path:
    return _path("CADUCEUS_STATE_PATH", "/var/lib/caduceus/state.json")


def _run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=True, text=True, capture_output=True)


def _fingerprint(path: Path) -> str:
    line = _run(["openssl", "x509", "-in", str(path), "-noout", "-fingerprint", "-sha256"]).stdout.strip()
    return line.split("=", 1)[-1]


def _not_after(path: Path) -> str:
    return _run(["openssl", "x509", "-in", str(path), "-noout", "-enddate"]).stdout.strip().removeprefix("notAfter=")


def _profile() -> str:
    path = _path("CADUCEUS_PROFILE_PATH", "/etc/caduceus/profile.yaml")
    if path.is_file():
        for line in path.read_text().splitlines():
            if line.startswith("profile:"):
                return line.split(":", 1)[1].strip()
    return os.environ.get("CADUCEUS_PROFILE", "homeserver")


def _receipt(primitive: str, *, changed: bool, dry_run: bool = False, **fields: Any) -> dict[str, Any]:
    return {"schema": f"caduceus.staff.house_ca.{primitive}.v1", "ok": True,
            "primitive": primitive, "role": _profile(), "changed": changed,
            "dry_run": dry_run, "client_reinstall_required": False,
            "firstMissingSignal": "none", **fields}


def ensure_root(*, dry_run: bool = False) -> dict[str, Any]:
    """Converge the stable household root; never rotates an existing root."""
    d = cert_dir(); ca = d / "ca.pem"; key = d / "ca.key.pem"
    if ca.exists() != key.exists():
        raise RuntimeError("caduceus-house-ca-partial-root")
    if ca.is_file():
        return _receipt("ensure_root", changed=False, dry_run=dry_run,
                        ca_fingerprint=_fingerprint(ca), ca_not_after=_not_after(ca))
    if dry_run:
        return _receipt("ensure_root", changed=False, dry_run=True, plan=["create-house-root"])
    d.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=d, delete=False) as f:
        f.write("[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=ca\n[dn]\nO=HomeServer\nCN=HomeServer House CA\n[ca]\nbasicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n")
        config = Path(f.name)
    try:
        _run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(ca), "-days", "3650", "-sha256", "-config", str(config)])
    finally:
        config.unlink(missing_ok=True)
    key.chmod(0o600); ca.chmod(0o644)
    return _receipt("ensure_root", changed=True, ca_fingerprint=_fingerprint(ca), ca_not_after=_not_after(ca))


def _split_sans(values: Sequence[str]) -> tuple[list[str], list[str]]:
    dns, ips = [], []
    for value in values:
        value = value.strip()
        if not value: continue
        try: ips.append(str(ipaddress.ip_address(value)))
        except ValueError:
            if any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-*._" for c in value):
                raise ValueError("caduceus-cert-san-invalid")
            dns.append(value.lower())
    return list(dict.fromkeys(dns)), list(dict.fromkeys(ips))


def issue_leaf(identity: str = "home.arpa", dns_names: Sequence[str] = (), ip_addresses: Sequence[str] = (), *, dry_run: bool = False) -> dict[str, Any]:
    root = ensure_root(dry_run=dry_run)
    dns, ips = _split_sans([identity, *dns_names, *ip_addresses])
    if dry_run:
        return _receipt("issue_leaf", changed=False, dry_run=True, identity=identity, sans=dns + ips, ca_fingerprint=root.get("ca_fingerprint"), plan=["ensure_root", "issue_leaf"])
    d = cert_dir(); safe = identity.replace("*", "wildcard").replace("/", "_")
    leaf = d / f"{safe}.pem"; key = d / f"{safe}.key.pem"; csr = d / f"{safe}.csr.pem"
    alt = [*(f"DNS.{i}={v}" for i,v in enumerate(dns,1)), *(f"IP.{i}={v}" for i,v in enumerate(ips,1))]
    config = d / f".{safe}.cnf"
    config.write_text("[req]\nprompt=no\ndistinguished_name=dn\nreq_extensions=ext\n[dn]\nO=HomeServer\nCN=" + identity + "\n[ext]\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=@alt\n[alt]\n" + "\n".join(alt) + "\n")
    try:
        _run(["openssl","req","-new","-newkey","rsa:2048","-nodes","-keyout",str(key),"-out",str(csr),"-config",str(config)])
        _run(["openssl","x509","-req","-in",str(csr),"-CA",str(d/"ca.pem"),"-CAkey",str(d/"ca.key.pem"),"-CAcreateserial","-out",str(leaf),"-days","824","-sha256","-extfile",str(config),"-extensions","ext"])
        _run(["openssl","verify","-CAfile",str(d/"ca.pem"),str(leaf)])
    finally:
        csr.unlink(missing_ok=True); config.unlink(missing_ok=True)
    key.chmod(0o600); leaf.chmod(0o644)
    return _receipt("issue_leaf", changed=True, identity=identity, sans=dns+ips,
                    ca_fingerprint=_fingerprint(d/"ca.pem"), leaf_fingerprint=_fingerprint(leaf),
                    leaf_not_after=_not_after(leaf), certificate=str(leaf), key_path=str(key))


def bundle_export(platform: str = "linux", *, dry_run: bool = False) -> dict[str, Any]:
    if platform not in PLATFORMS: raise ValueError("caduceus-cert-platform-invalid")
    root = ensure_root(dry_run=dry_run)
    out_dir = _path("CADUCEUS_CERT_BUNDLE_DIR", "/var/lib/caduceus/certs/bundles")
    suffix = ".cer" if platform == "windows" else ".crt"
    out = out_dir / f"homeserver-house-ca-{platform}{suffix}"
    if dry_run: return _receipt("bundle_export", changed=False, dry_run=True, platform=platform, path=str(out), ca_fingerprint=root.get("ca_fingerprint"), plan=["export-ca-only"])
    out_dir.mkdir(parents=True, exist_ok=True)
    if platform == "windows": _run(["openssl","x509","-in",str(cert_dir()/"ca.pem"),"-outform","DER","-out",str(out)])
    else: shutil.copyfile(cert_dir()/"ca.pem", out)
    if b"PRIVATE KEY" in out.read_bytes(): raise RuntimeError("caduceus-cert-private-key-leaked")
    out.chmod(0o644)
    return _receipt("bundle_export", changed=True, platform=platform, path=str(out), ca_fingerprint=_fingerprint(cert_dir()/"ca.pem"))


def trust_install(bundle: str, platform: str = "linux", *, dry_run: bool = False) -> dict[str, Any]:
    source = Path(bundle)
    if not source.is_file(): raise ValueError("caduceus-cert-bundle-missing")
    _run(["openssl","x509","-in",str(source),"-noout"])
    fingerprint = _fingerprint(source)
    store = _path("CADUCEUS_TRUST_STORE", "/usr/local/share/ca-certificates")
    target = store / "homeserver-house-ca.crt"
    same = target.is_file() and hashlib.sha256(target.read_bytes()).digest() == hashlib.sha256(source.read_bytes()).digest()
    if dry_run: return _receipt("trust_install", changed=False, dry_run=True, platform=platform, path=str(target), ca_fingerprint=fingerprint, plan=["verify-ca", "install-trust"])
    if not same:
        store.mkdir(parents=True, exist_ok=True); shutil.copyfile(source, target); target.chmod(0o644)
    return _receipt("trust_install", changed=not same, platform=platform, path=str(target), ca_fingerprint=fingerprint, bundle_installed=True)


def apply_nginx(portal: str, upstream: str, certificate: str, key_path: str, *, dry_run: bool = False) -> dict[str, Any]:
    directory = _path("CADUCEUS_NGINX_DIR", "/etc/nginx/conf.d")
    target = directory / f"caduceus-{portal.replace('.', '-')}.conf"
    body = f"server {{ listen 443 ssl; server_name {portal}; ssl_certificate {certificate}; ssl_certificate_key {key_path}; location / {{ proxy_pass {upstream}; }} }}\n"
    if dry_run: return _receipt("apply_nginx", changed=False, dry_run=True, portal=portal, path=str(target), plan=["stage-nginx", "validate-nginx", "activate-nginx"])
    directory.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(".tmp"); tmp.write_text(body); os.replace(tmp, target)
    return _receipt("apply_nginx", changed=True, portal=portal, path=str(target))


def constituent_lock(portal: str, lan_ip: str, *, dry_run: bool = False) -> dict[str, Any]:
    ip = str(ipaddress.ip_address(lan_ip))
    # V1 truthfully records the declared DHCP/DNS plan. Daemon adapters are debt.
    return _receipt("constituent_lock", changed=not dry_run, dry_run=dry_run, portal=portal, lan_ip=ip,
                    dhcp_dns_applied=False, debt="dhcp-dns-adapter-dry-run", plan=["reserve-dhcp", "bind-dns"])


def state_commit(transition: dict[str, Any], *, dry_run: bool = False) -> dict[str, Any]:
    path = state_path(); existing: dict[str, Any] = {}
    if path.is_file():
        try: existing = json.loads(path.read_text())
        except json.JSONDecodeError: raise ValueError("caduceus-state-invalid")
    old = existing.get(SCHEMA, {})
    generation = int(old.get("generation", 0)) + (0 if dry_run else 1)
    value = {"profile": _profile(), "root_fingerprint": transition.get("root_fingerprint", old.get("root_fingerprint")),
             "bundle_installed": bool(transition.get("bundle_installed", old.get("bundle_installed", False))),
             "portals": transition.get("portals", old.get("portals", [])),
             "constituents": transition.get("constituents", old.get("constituents", [])), "generation": generation}
    if dry_run: return _receipt("state_commit", changed=False, dry_run=True, generation=generation, state=value, plan=["atomic-state-replace"])
    existing[SCHEMA] = value; path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=".state.")
    try:
        with os.fdopen(fd, "w") as stream: json.dump(existing, stream, indent=2, sort_keys=True); stream.write("\n")
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)
    return _receipt("state_commit", changed=True, generation=generation, state=value)


def portal_admit(portal: str, lan_ip: str, upstream: str, aliases: Sequence[str] = (), *, dry_run: bool = False) -> dict[str, Any]:
    # Exact required composition and order:
    locked = constituent_lock(portal, lan_ip, dry_run=dry_run)
    leaf = issue_leaf(portal, aliases, [lan_ip], dry_run=dry_run)
    applied = apply_nginx(portal, upstream, leaf.get("certificate", str(cert_dir()/f"{portal}.pem")), leaf.get("key_path", str(cert_dir()/f"{portal}.key.pem")), dry_run=dry_run)
    transition = {"root_fingerprint": leaf.get("ca_fingerprint"), "portals": [{"fqdn": portal, "lan_ip": lan_ip, "upstream": upstream}], "constituents": [{"identity": portal, "lan_ip": lan_ip}]}
    committed = state_commit(transition, dry_run=dry_run)
    return _receipt("portal_admit", changed=not dry_run, dry_run=dry_run, portal=portal,
                    generation=committed.get("generation"), children=[locked, leaf, applied, committed])


def status() -> dict[str, Any]:
    ca = cert_dir()/"ca.pem"; state = state_path(); role = _profile()
    value = _receipt("status", changed=False, profile=role, root_present=ca.is_file(), bundle_installed=False, portals=[], constituents=[])
    if ca.is_file(): value.update(ca_fingerprint=_fingerprint(ca), ca_not_after=_not_after(ca))
    else: value.update(ok=False, firstMissingSignal="caduceus-house-ca-missing")
    if state.is_file():
        ledger = json.loads(state.read_text()).get(SCHEMA, {})
        for key in ("bundle_installed", "generation"): value[key] = ledger.get(key, value.get(key))
        if role == "homeserver":
            value["portals"] = ledger.get("portals", []); value["constituents"] = ledger.get("constituents", [])
    return value


def _emit(call) -> int:
    try: value = call()
    except (ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        value = {"schema":"caduceus.staff.house_ca.error.v1","ok":False,"firstMissingSignal":str(error),"client_reinstall_required":False}
    print(json.dumps(value, sort_keys=True)); return 0 if value.get("ok") else 1


def main(argv: Sequence[str] | None = None) -> int:
    parser=argparse.ArgumentParser(prog="caduceus-house-ca"); sub=parser.add_subparsers(dest="cmd",required=True)
    for name in ("ensure-root","status"): sub.add_parser(name)
    issue=sub.add_parser("issue-leaf"); issue.add_argument("identity",nargs="?",default="home.arpa"); issue.add_argument("--sans",default=""); issue.add_argument("--ips",default=""); issue.add_argument("--dry-run",action="store_true")
    bundle=sub.add_parser("bundle-export"); bundle.add_argument("platform",choices=sorted(PLATFORMS)); bundle.add_argument("--dry-run",action="store_true")
    trust=sub.add_parser("trust-install"); trust.add_argument("bundle"); trust.add_argument("--platform",default="linux",choices=sorted(PLATFORMS)); trust.add_argument("--dry-run",action="store_true")
    apply=sub.add_parser("apply-nginx"); apply.add_argument("portal"); apply.add_argument("upstream"); apply.add_argument("certificate"); apply.add_argument("key_path"); apply.add_argument("--dry-run",action="store_true")
    admit=sub.add_parser("portal-admit"); admit.add_argument("portal"); admit.add_argument("lan_ip"); admit.add_argument("upstream"); admit.add_argument("--aliases",default=""); admit.add_argument("--dry-run",action="store_true")
    args=parser.parse_args(argv)
    if args.cmd=="ensure-root": return _emit(lambda:ensure_root())
    if args.cmd=="status": return _emit(status)
    if args.cmd=="issue-leaf": return _emit(lambda:issue_leaf(args.identity,args.sans.split(",") if args.sans else (),args.ips.split(",") if args.ips else (),dry_run=args.dry_run))
    if args.cmd=="bundle-export": return _emit(lambda:bundle_export(args.platform,dry_run=args.dry_run))
    if args.cmd=="trust-install": return _emit(lambda:trust_install(args.bundle,args.platform,dry_run=args.dry_run))
    if args.cmd=="apply-nginx": return _emit(lambda:apply_nginx(args.portal,args.upstream,args.certificate,args.key_path,dry_run=args.dry_run))
    if args.cmd=="portal-admit": return _emit(lambda:portal_admit(args.portal,args.lan_ip,args.upstream,args.aliases.split(",") if args.aliases else (),dry_run=args.dry_run))
    return 2


if __name__ == "__main__": raise SystemExit(main())
