#!/usr/bin/env python3
"""Prometheus Continuity Tools (v0.1)

Implements:
- bundle export (create manifest, sign, encrypt)
- bundle verify (decrypt, verify signature + hashes)

Design goals:
- minimal dependencies (uses system: age, age-keygen, ssh-keygen)
- safe defaults (only exports public repo artifacts unless explicitly included)

NOTE: This tool is designed for the public repo `prometheus-continuity`.
It intentionally avoids exporting private OpenClaw workspace files by default.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICY_PATH = REPO_ROOT / "policy" / "export-allowlist.txt"

CONFIG_DIR = Path.home() / ".config" / "prometheus"
SIGNING_KEY = CONFIG_DIR / "signing_ed25519"
SIGNING_PUB = CONFIG_DIR / "signing_ed25519.pub"
ALLOWED_SIGNERS = CONFIG_DIR / "allowed_signers"
AGE_DIR = CONFIG_DIR / "age"
AGE_IDENTITY = AGE_DIR / "identity.txt"  # private age key
AGE_RECIPIENT = AGE_DIR / "recipient.txt"  # public age recipient

DELEGATIONS_DIR = CONFIG_DIR / "delegations"  # key rotation proofs


class ShellError(RuntimeError):
    pass


def sh(cmd: list[str], *, cwd: Path | None = None, input_bytes: bytes | None = None) -> bytes:
    try:
        return subprocess.check_output(
            cmd,
            cwd=str(cwd) if cwd else None,
            input=input_bytes,
            stderr=subprocess.STDOUT,
        )
    except subprocess.CalledProcessError as e:
        raise ShellError(
            f"command failed ({e.returncode}): {' '.join(cmd)}\n{e.output.decode('utf-8','replace')}"
        )


def ensure_tools() -> None:
    for exe in ("age", "age-keygen", "ssh-keygen"):
        if shutil.which(exe) is None:
            raise SystemExit(f"Missing dependency: {exe}. Please install it and retry.")


def ensure_dirs() -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    AGE_DIR.mkdir(parents=True, exist_ok=True)
    DELEGATIONS_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(CONFIG_DIR, 0o700)
    os.chmod(AGE_DIR, 0o700)
    os.chmod(DELEGATIONS_DIR, 0o700)


def ensure_signing_key() -> None:
    if SIGNING_KEY.exists() and SIGNING_PUB.exists() and ALLOWED_SIGNERS.exists():
        return
    # Create an ed25519 keypair using ssh-keygen.
    sh([
        "ssh-keygen",
        "-t",
        "ed25519",
        "-N",
        "",
        "-C",
        "prometheus-signing",
        "-f",
        str(SIGNING_KEY),
    ])
    os.chmod(SIGNING_KEY, 0o600)
    os.chmod(SIGNING_PUB, 0o644)

    pub = SIGNING_PUB.read_text().strip()
    # allowed_signers format: principal key
    # (We keep this simple for v0.1)
    ALLOWED_SIGNERS.write_text(f"prometheus {pub}\n")
    os.chmod(ALLOWED_SIGNERS, 0o644)


def ensure_age_identity() -> None:
    if AGE_IDENTITY.exists() and AGE_RECIPIENT.exists():
        return
    # Generate age identity keypair
    out = sh(["age-keygen"]).decode("utf-8").splitlines()
    # Output format includes both public recipient and private key. Example:
    # Public key: age1...
    # AGE-SECRET-KEY-1...
    pub = None
    priv = None
    for line in out:
        if line.startswith("Public key:"):
            pub = line.split(":", 1)[1].strip()
        elif line.startswith("AGE-SECRET-KEY-"):
            priv = line.strip()
    if not pub or not priv:
        raise ShellError("Unexpected age-keygen output")
    AGE_RECIPIENT.write_text(pub + "\n")
    AGE_IDENTITY.write_text(priv + "\n")
    os.chmod(AGE_RECIPIENT, 0o644)
    os.chmod(AGE_IDENTITY, 0o600)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def read_allowlist(path: Path) -> list[str]:
    if not path.exists():
        raise ShellError(
            f"export policy not found: {path}. Create it or pass --allowlist."
        )
    lines: list[str] = []
    for raw in path.read_text().splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        lines.append(s)
    return lines


def is_allowed_by_policy(rel: str, rules: list[str]) -> bool:
    for rule in rules:
        if rule.endswith("/"):
            if rel.startswith(rule):
                return True
        else:
            if rel == rule:
                return True
    return False


def list_repo_files() -> list[str]:
    # Respect git index (tracked files), but also allow exporting extra paths via args.
    out = sh(["git", "ls-files"], cwd=REPO_ROOT).decode("utf-8", "replace")
    return [line.strip() for line in out.splitlines() if line.strip()]


@dataclass
class BundlePaths:
    bundle_dir: Path
    payload_dir: Path
    manifest_json: Path
    manifest_sig: Path
    tar_path: Path
    enc_path: Path


def make_bundle_paths(work_dir: Path, out_dir: Path, bundle_id: str) -> BundlePaths:
    bundle_dir = work_dir / "prometheus-bundle"
    payload_dir = bundle_dir / "payload"
    manifest_json = bundle_dir / "manifest.json"
    manifest_sig = bundle_dir / "manifest.sig"
    tar_path = out_dir / f"bundle-{bundle_id}.tar"
    enc_path = out_dir / f"bundle-{bundle_id}.tar.age"
    return BundlePaths(bundle_dir, payload_dir, manifest_json, manifest_sig, tar_path, enc_path)


def build_manifest(payload_root: Path, agent_name: str, public_key: str) -> dict:
    files = []
    for p in sorted(payload_root.rglob("*")):
        if p.is_dir():
            continue
        rel = p.relative_to(payload_root.parent).as_posix()  # relative to bundle_dir
        files.append({
            "path": rel,
            "sha256": sha256_file(p),
            "bytes": p.stat().st_size,
        })
    return {
        "bundle_version": "0.1",
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "bundle_id": str(uuid.uuid4()),
        "agent": {
            "name": agent_name,
            "public_key": public_key,
        },
        "runtime": {
            "product": "openclaw",
            "host": os.uname().nodename,
        },
        "files": files,
    }


def write_manifest(path: Path, manifest: dict) -> None:
    # Deterministic JSON: stable key order, no trailing spaces.
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")


def ssh_sign_file(file_path: Path, sig_path: Path, *, namespace: str, key_path: Path) -> None:
    """Sign file_path with key_path and write detached signature to sig_path."""
    sh(["ssh-keygen", "-Y", "sign", "-f", str(key_path), "-n", namespace, str(file_path)])
    generated = file_path.with_suffix(file_path.suffix + ".sig")
    if not generated.exists():
        raise ShellError("ssh-keygen did not produce a .sig file")
    generated.replace(sig_path)


def sign_manifest(manifest_path: Path, sig_path: Path) -> None:
    ssh_sign_file(manifest_path, sig_path, namespace="prometheus", key_path=SIGNING_KEY)


def ssh_verify_file(file_path: Path, sig_path: Path, *, namespace: str, principal: str = "prometheus") -> None:
    # ssh-keygen -Y verify -f allowed_signers -I principal -n namespace -s sigfile < file
    data = file_path.read_bytes()
    sh(
        [
            "ssh-keygen",
            "-Y",
            "verify",
            "-f",
            str(ALLOWED_SIGNERS),
            "-I",
            principal,
            "-n",
            namespace,
            "-s",
            str(sig_path),
        ],
        input_bytes=data,
    )


def verify_signature(manifest_path: Path, sig_path: Path) -> None:
    ssh_verify_file(manifest_path, sig_path, namespace="prometheus")


def tar_bundle(bundle_dir: Path, tar_path: Path) -> None:
    with tarfile.open(tar_path, "w") as tf:
        tf.add(bundle_dir, arcname="prometheus-bundle")


def age_encrypt(tar_path: Path, enc_path: Path) -> None:
    recipient = AGE_RECIPIENT.read_text().strip()
    sh(["age", "-r", recipient, "-o", str(enc_path), str(tar_path)])


def age_decrypt(enc_path: Path, tar_path: Path) -> None:
    sh(["age", "-d", "-i", str(AGE_IDENTITY), "-o", str(tar_path), str(enc_path)])


def extract_tar(tar_path: Path, out_dir: Path) -> Path:
    with tarfile.open(tar_path, "r") as tf:
        tf.extractall(out_dir)
    return out_dir / "prometheus-bundle"


def verify_hashes(bundle_dir: Path) -> None:
    manifest_path = bundle_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    for entry in manifest.get("files", []):
        rel = entry["path"]
        expected = entry["sha256"]
        p = bundle_dir / rel
        if not p.exists():
            raise ShellError(f"missing file from payload: {rel}")
        actual = sha256_file(p)
        if actual != expected:
            raise ShellError(f"hash mismatch for {rel}: expected {expected} got {actual}")


def cmd_init(_: argparse.Namespace) -> None:
    ensure_tools()
    ensure_dirs()
    ensure_signing_key()
    ensure_age_identity()
    print("Initialized:")
    print(f"- signing pubkey: {SIGNING_PUB}")
    print(f"- age recipient: {AGE_RECIPIENT.read_text().strip()}")


def cmd_rotate_signing_key(args: argparse.Namespace) -> None:
    """Rotate signing key and emit a signed delegation proof.

    v0.1 semantics:
    - create a new ed25519 keypair
    - create delegation.json signed by the *old* key
    - update allowed_signers to include BOTH keys (old and new)
    """
    ensure_tools()
    ensure_dirs()
    ensure_signing_key()

    ts = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    old_pub = SIGNING_PUB.read_text().strip()

    # Create new keypair in temp location
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        new_key = td / "signing_ed25519"
        sh([
            "ssh-keygen",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            f"prometheus-signing-rotated-{ts}",
            "-f",
            str(new_key),
        ])
        new_pub = (td / "signing_ed25519.pub").read_text().strip()

        # Delegation statement
        delegation = {
            "kind": "prometheus.delegation.v0.1",
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "from_public_key": old_pub,
            "to_public_key": new_pub,
            "reason": args.reason or "key rotation",
        }

        delegation_path = DELEGATIONS_DIR / f"delegation-{ts}.json"
        sig_path = DELEGATIONS_DIR / f"delegation-{ts}.sig"
        delegation_path.write_text(json.dumps(delegation, indent=2, sort_keys=True) + "\n")

        # Sign delegation using old key BEFORE overwriting
        ssh_sign_file(delegation_path, sig_path, namespace="prometheus-delegation", key_path=SIGNING_KEY)

        # Backup old keypair
        backup_dir = CONFIG_DIR / "signing-backups" / ts
        backup_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(SIGNING_KEY, backup_dir / SIGNING_KEY.name)
        shutil.copy2(SIGNING_PUB, backup_dir / SIGNING_PUB.name)

        # Install new keypair
        shutil.copy2(new_key, SIGNING_KEY)
        shutil.copy2(td / "signing_ed25519.pub", SIGNING_PUB)
        os.chmod(SIGNING_KEY, 0o600)
        os.chmod(SIGNING_PUB, 0o644)

    # Update allowed_signers to include both old and new
    current_new_pub = SIGNING_PUB.read_text().strip()
    ALLOWED_SIGNERS.write_text(f"prometheus {old_pub}\n" f"prometheus {current_new_pub}\n")

    print("Rotated signing key.")
    print(f"- new pubkey: {current_new_pub}")
    print(f"- delegation: {delegation_path}")
    print(f"- signature: {sig_path}")


def cmd_verify_delegation(args: argparse.Namespace) -> None:
    ensure_tools()
    ensure_dirs()

    dpath = Path(args.delegation).expanduser().resolve()
    spath = Path(args.signature).expanduser().resolve()
    if not dpath.exists() or not spath.exists():
        raise SystemExit("delegation or signature file not found")

    ssh_verify_file(dpath, spath, namespace="prometheus-delegation")
    print("OK")


def cmd_export(args: argparse.Namespace) -> None:
    ensure_tools()
    ensure_dirs()
    ensure_signing_key()
    ensure_age_identity()

    out_dir = Path(args.out).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    allowlist = read_allowlist(Path(args.allowlist).expanduser())
    include = set(args.include or [])
    tracked = list_repo_files()

    payload_list: list[str] = []
    for rel in tracked:
        if is_allowed_by_policy(rel, allowlist) or rel in include or any(
            rel.startswith(p.rstrip("/") + "/") for p in include
        ):
            payload_list.append(rel)

    if not payload_list:
        raise SystemExit("Nothing to export (payload empty).")

    with tempfile.TemporaryDirectory() as td:
        work_dir = Path(td)
        bundle_id = time.strftime("%Y%m%d-%H%M%S")
        bp = make_bundle_paths(work_dir, out_dir, bundle_id)
        bp.payload_dir.mkdir(parents=True, exist_ok=True)

        # Copy selected files into payload, preserving relative paths.
        for rel in payload_list:
            src = REPO_ROOT / rel
            if not src.exists():
                continue
            dst = bp.payload_dir / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)

        # Record allowlist used (as provenance) if it exists.
        allowlist_src = Path(args.allowlist).expanduser().resolve()
        if allowlist_src.exists():
            prov_dst = bp.payload_dir / "policy" / "export-allowlist.used.txt"
            prov_dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(allowlist_src, prov_dst)

        public_key = SIGNING_PUB.read_text().strip()
        manifest = build_manifest(bp.payload_dir, agent_name=args.agent_name, public_key=public_key)
        write_manifest(bp.manifest_json, manifest)
        sign_manifest(bp.manifest_json, bp.manifest_sig)

        tar_bundle(bp.bundle_dir, bp.tar_path)
        age_encrypt(bp.tar_path, bp.enc_path)

        # cleanup tar (encrypted artifact is the deliverable)
        try:
            bp.tar_path.unlink()
        except FileNotFoundError:
            pass

        print(str(bp.enc_path))


@dataclass
class VerifiedBundle:
    tmp: tempfile.TemporaryDirectory
    bundle_dir: Path


def _decrypt_and_verify(enc_path: Path) -> VerifiedBundle:
    """Decrypt bundle to a temp dir and verify signature + hashes."""
    ensure_tools()
    ensure_dirs()

    td = tempfile.TemporaryDirectory()
    work_dir = Path(td.name)
    tar_path = work_dir / "bundle.tar"
    age_decrypt(enc_path, tar_path)
    bundle_dir = extract_tar(tar_path, work_dir)

    manifest_path = bundle_dir / "manifest.json"
    sig_path = bundle_dir / "manifest.sig"

    verify_signature(manifest_path, sig_path)
    verify_hashes(bundle_dir)

    return VerifiedBundle(tmp=td, bundle_dir=bundle_dir)


def cmd_verify(args: argparse.Namespace) -> None:
    enc_path = Path(args.bundle).expanduser().resolve()
    if not enc_path.exists():
        raise SystemExit(f"bundle not found: {enc_path}")

    vb = _decrypt_and_verify(enc_path)
    vb.tmp.cleanup()
    print("OK")


def _safe_relpath(p: Path) -> str:
    rel = p.as_posix()
    if rel.startswith("/") or rel.startswith("\\") or ".." in Path(rel).parts:
        raise ShellError(f"unsafe path in bundle: {rel}")
    return rel


def cmd_import(args: argparse.Namespace) -> None:
    enc_path = Path(args.bundle).expanduser().resolve()
    if not enc_path.exists():
        raise SystemExit(f"bundle not found: {enc_path}")

    target = Path(args.target).expanduser().resolve()
    target.mkdir(parents=True, exist_ok=True)

    vb = _decrypt_and_verify(enc_path)
    try:
        bundle_dir = vb.bundle_dir
        payload_root = bundle_dir / "payload"
        if not payload_root.exists():
            raise ShellError("bundle missing payload/")

        actions = []
        for src in sorted(payload_root.rglob("*")):
            if src.is_dir():
                continue
            rel = _safe_relpath(src.relative_to(payload_root))
            dst = target / rel
            actions.append((src, dst))

        for src, dst in actions:
            if args.no_clobber and dst.exists():
                raise ShellError(f"refusing to overwrite existing file: {dst}")
            if args.dry_run:
                print(f"WOULD_WRITE {dst}")
                continue
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
            print(f"WROTE {dst}")
    finally:
        vb.tmp.cleanup()


def main() -> None:
    p = argparse.ArgumentParser(prog="prometheus")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("init", help="Initialize local signing + encryption keys")
    sp.set_defaults(func=cmd_init)

    sp = sub.add_parser("export", help="Export an encrypted, signed bundle")
    sp.add_argument("--out", default=str(REPO_ROOT / "bundles"), help="output directory")
    sp.add_argument("--agent-name", default="mefistofeles-ai", help="agent name")
    sp.add_argument(
        "--allowlist",
        default=str(DEFAULT_POLICY_PATH),
        help="path to export allowlist (repo-relative paths)",
    )
    sp.add_argument("--include", action="append", help="extra repo path(s) to include (discouraged)")
    sp.set_defaults(func=cmd_export)

    sp = sub.add_parser("verify", help="Verify an encrypted bundle (signature + hashes)")
    sp.add_argument("bundle", help="path to .tar.age bundle")
    sp.set_defaults(func=cmd_verify)

    sp = sub.add_parser("import", help="Verify then apply a bundle payload into a target directory")
    sp.add_argument("bundle", help="path to .tar.age bundle")
    sp.add_argument("--target", required=True, help="target directory to apply payload into")
    sp.add_argument("--dry-run", action="store_true", help="print actions without writing")
    sp.add_argument("--no-clobber", action="store_true", help="refuse to overwrite existing files")
    sp.set_defaults(func=cmd_import)

    sp = sub.add_parser("rotate-signing-key", help="Rotate signing key and create a signed delegation proof")
    sp.add_argument("--reason", help="why the key is being rotated")
    sp.set_defaults(func=cmd_rotate_signing_key)

    sp = sub.add_parser("verify-delegation", help="Verify a delegation proof signature")
    sp.add_argument("delegation", help="path to delegation-*.json")
    sp.add_argument("signature", help="path to delegation-*.sig")
    sp.set_defaults(func=cmd_verify_delegation)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
