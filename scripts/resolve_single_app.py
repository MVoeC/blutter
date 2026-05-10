#!/usr/bin/env python3
"""Resolve dump parameters for a single Flutter App/libapp binary.

This helper is used by GitHub Actions when the user only has one `App` file and
no matching `Flutter`/`libflutter.so` file. It tries to extract enough metadata
from the app binary to select a Dart VM build automatically.
"""
import argparse
import os
import re
import struct
import subprocess
import sys
from pathlib import Path
from typing import Optional


# 常见 Flutter stable 对应的 Dart 版本。只有单个 App 且二进制里没有版本字符串时，
# workflow 会按这个列表从新到旧自动尝试，成功后停止。
def _fallback_versions() -> list[str]:
    return [
        "3.10.0",
        "3.9.2",
        "3.9.0",
        "3.8.1",
        "3.7.2",
        "3.7.0",
        "3.6.2",
        "3.6.0",
        "3.5.4",
        "3.5.3",
        "3.4.4",
        "3.4.3",
        "3.4.2",
        "3.3.4",
        "3.3.0",
        "3.2.6",
        "3.2.3",
        "3.1.5",
        "3.0.7",
        "2.19.6",
        "2.18.6",
        "2.17.6",
    ]


# 行为说明：读取二进制魔数，判断 App 是 Android ELF 还是 iOS/macOS Mach-O。
def detect_binary_format(data: bytes) -> tuple[str, str]:
    if data.startswith(b"\x7fELF"):
        if len(data) > 18:
            machine = struct.unpack_from("<H", data, 18)[0]
            if machine == 0xB7:
                return "elf", "arm64"
            if machine == 0x3E:
                return "elf", "x64"
        return "elf", "arm64"

    magic = data[:4]
    if magic in {b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf"}:
        return "macho", "arm64"
    if magic in {b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"}:
        return "fat-macho", "arm64"

    return "unknown", "arm64"


# 行为说明：尽量从 App 二进制中直接找出 Dart/Flutter 版本字符串。
def find_embedded_dart_version(data: bytes) -> Optional[str]:
    patterns = [
        rb"Dart VM version:\s*([0-9]+\.[0-9]+\.[0-9]+)",
        rb"Dart version:\s*([0-9]+\.[0-9]+\.[0-9]+)",
        rb"Flutter[^\x00\n\r]{0,120}Dart[^\x00\n\r]{0,120}([0-9]+\.[0-9]+\.[0-9]+)",
        rb"\x00([0-9]+\.[0-9]+\.[0-9]+) \((?:stable|beta|dev)\)",
    ]
    for pattern in patterns:
        match = re.search(pattern, data)
        if match:
            return match.group(1).decode("ascii", "ignore")
    return None


# 行为说明：从 snapshot 数据附近提取 32 字节 snapshot hash 和运行 flags。
def find_snapshot_hash_and_flags(data: bytes) -> tuple[Optional[str], list[str]]:
    flags: list[str] = []
    flag_match = re.search(rb"(?:--)?(?:use-)?compressed-pointers(?:\x00|\s)", data)
    if flag_match:
        flags.append("compressed-pointers")

    # Dart snapshot hash is a 32-byte lowercase hexadecimal string near snapshot
    # data. Prefer candidates close to known snapshot/flag markers.
    markers = [
        b"compressed-pointers",
        b"_kDartVmSnapshotData",
        b"_kDartIsolateSnapshotData",
        b"dart_app_snap",
        b"Dart VM",
    ]
    candidates: list[tuple[int, str]] = []
    for match in re.finditer(rb"(?<![0-9a-f])[0-9a-f]{32}(?![0-9a-f])", data):
        pos = match.start()
        score = 10**9
        for marker in markers:
            marker_pos = data.find(marker, max(0, pos - 4096), min(len(data), pos + 4096))
            if marker_pos != -1:
                score = min(score, abs(marker_pos - pos))
        candidates.append((score, match.group(0).decode("ascii")))

    if not candidates:
        return None, flags

    candidates.sort(key=lambda item: item[0])
    return candidates[0][1], flags


# 行为说明：通过 checkout Dart tag 并生成 version.cc，匹配 snapshot hash 对应的 Dart 版本。
def resolve_version_by_snapshot_hash(snapshot_hash: str, versions: list[str], work_dir: Path) -> Optional[str]:
    repo_dir = work_dir / "dart-sdk-version-probe"
    if not repo_dir.exists():
        subprocess.run(
            [
                "git",
                "clone",
                "--filter=blob:none",
                "--no-checkout",
                "--depth",
                "1",
                "https://github.com/dart-lang/sdk.git",
                str(repo_dir),
            ],
            check=True,
        )

    for version in versions:
        print(f"Trying Dart {version} for snapshot {snapshot_hash}...", flush=True)
        try:
            subprocess.run(["git", "fetch", "--depth", "1", "origin", f"refs/tags/{version}:refs/tags/{version}"], cwd=repo_dir, check=True, stdout=subprocess.DEVNULL)
            subprocess.run(["git", "checkout", "--force", version], cwd=repo_dir, check=True, stdout=subprocess.DEVNULL)
            version_in = repo_dir / "runtime" / "vm" / "version_in.cc"
            tools_version = repo_dir / "tools" / "VERSION"
            if not version_in.exists() or not tools_version.exists():
                subprocess.run(["git", "sparse-checkout", "set", "runtime/vm/version_in.cc", "tools/VERSION"], cwd=repo_dir, check=False, stdout=subprocess.DEVNULL)
            proc = subprocess.run(
                [sys.executable, "tools/make_version.py", "--output", "runtime/vm/version.cc", "--input", "runtime/vm/version_in.cc"],
                cwd=repo_dir,
                text=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if proc.returncode != 0:
                # Old tags can be incompatible with new Python; use local lightweight generator.
                local_make_version = Path(__file__).with_name("dartvm_make_version.py").resolve()
                subprocess.run([sys.executable, str(local_make_version), str(repo_dir), snapshot_hash], check=True)
            generated = (repo_dir / "runtime" / "vm" / "version.cc").read_text(encoding="utf-8", errors="ignore")
            if snapshot_hash in generated:
                return version
        except subprocess.CalledProcessError:
            continue
    return None


# 行为说明：输出 shell 可 source 的 KEY=VALUE 文件，供 GitHub Actions 后续步骤使用。
def main() -> int:
    parser = argparse.ArgumentParser(description="Resolve Dart target from a single Flutter App/libapp binary")
    parser.add_argument("app", help="Path to App or libapp.so")
    parser.add_argument("--output", required=True, help="Output env file")
    parser.add_argument("--work-dir", default=".dart_version_probe", help="Temporary work directory")
    parser.add_argument("--versions", default="", help="Comma-separated Dart versions to try before fallback list")
    args = parser.parse_args()

    app_path = Path(args.app)
    out_path = Path(args.output)
    work_dir = Path(args.work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    data = app_path.read_bytes()
    binary_format, arch = detect_binary_format(data)
    os_name = "ios" if "macho" in binary_format else "android"

    version = find_embedded_dart_version(data)
    snapshot_hash, flags = find_snapshot_hash_and_flags(data)
    compressed = "true" if "compressed-pointers" in flags else "false"

    unsupported_reason = ""
    if version is None and snapshot_hash:
        explicit_versions = [v.strip() for v in args.versions.split(",") if v.strip()]
        if explicit_versions:
            version = resolve_version_by_snapshot_hash(snapshot_hash, explicit_versions, work_dir)

    with out_path.open("w", encoding="utf-8") as f:
        f.write(f"BINARY_FORMAT={binary_format}\n")
        f.write(f"TARGET_OS={os_name}\n")
        f.write(f"TARGET_ARCH={arch}\n")
        f.write(f"COMPRESSED_POINTERS={compressed}\n")
        if snapshot_hash:
            f.write(f"SNAPSHOT_HASH={snapshot_hash}\n")
        if version:
            f.write(f"DART_VERSION={version}_{os_name}_{arch}\n")
        else:
            candidates = [v.strip() for v in args.versions.split(",") if v.strip()] or _fallback_versions()
            candidate_targets = ",".join(f"{candidate}_{os_name}_{arch}" for candidate in candidates)
            f.write(f"CANDIDATE_DART_VERSIONS={candidate_targets}\n")
        if unsupported_reason:
            f.write(f"UNSUPPORTED_REASON={unsupported_reason!r}\n")

    print(f"Binary format: {binary_format}")
    print(f"Target: {os_name} {arch}")
    print(f"Compressed pointers detected: {compressed}")
    print(f"Snapshot hash: {snapshot_hash or '<not found>'}")
    print(f"Resolved Dart version: {version or '<not resolved>'}")

    if unsupported_reason:
        print(unsupported_reason, file=sys.stderr)
        return 3

    if not version:
        print("Cannot resolve one exact Dart version from this single App file.", file=sys.stderr)
        print("A candidate version list was written so the workflow can try versions automatically.", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
