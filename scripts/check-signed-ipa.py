#!/usr/bin/env python3
"""Offline signing-field check for locally re-signed Cuven IPAs."""
import argparse
import datetime as dt
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from collections import Counter
from pathlib import Path
from xml.parsers.expat import ExpatError


class InspectionError(Exception):
    pass


def plist(data, source):
    try:
        result = plistlib.loads(data)
    except (plistlib.InvalidFileException, ValueError, TypeError, OverflowError, ExpatError) as exc:
        raise InspectionError(f"{source} 无法解码为 plist。") from exc
    if not isinstance(result, dict):
        raise InspectionError(f"{source} 缺少 plist 字典。")
    return result


def output(command, source):
    if not shutil.which(command[0]):
        raise InspectionError(f"{source} 需要安装 {command[0]}。")
    result = subprocess.run(command, capture_output=True, timeout=30, check=False)
    if result.returncode or not result.stdout:
        raise InspectionError(f"{source} 读取失败，请确认 IPA 已重签并包含可读权限和描述文件。")
    return result.stdout


def member(archive, counts, name):
    if counts[name] != 1:
        raise InspectionError(f"IPA 内缺少或重复保存了 {name}。")
    return archive.read(name)


def read_target(archive, counts, root, temp):
    info = plist(member(archive, counts, root + "/Info.plist"), root)
    exe = info.get("CFBundleExecutable")
    if not isinstance(exe, str) or not exe or exe in (".", "..") or "/" in exe or "\\" in exe:
        raise InspectionError(f"{root} 的 CFBundleExecutable 无效。")
    # Use our own filenames, never paths from the archive, for temporary files.
    profile_path = temp / "signed-profile"
    profile_path.write_bytes(member(archive, counts, root + "/embedded.mobileprovision"))
    binary = temp / "target-executable"
    if counts[root + "/" + exe] != 1:
        raise InspectionError(f"{root} 的可执行文件缺失或重复。")
    with archive.open(root + "/" + exe) as src, binary.open("wb") as dest:
        shutil.copyfileobj(src, dest)
    if sys.platform == "darwin":
        profile_args = ["/usr/bin/security", "cms", "-D", "-i", str(profile_path)]
        signing_args = ["/usr/bin/codesign", "-d", "--arch", "arm64", "--entitlements", ":-", str(binary)]
    else:
        profile_args = ["openssl", "cms", "-verify", "-inform", "DER", "-noverify", "-in", str(profile_path)]
        signing_args = ["ldid", "-arch", "arm64", "-e", str(binary)]
    return (info, plist(output(signing_args, root), "可执行文件签名"),
            plist(output(profile_args, root), "描述文件"))


def values(obj, name):
    value = obj.get(name)
    return [entry for entry in value if isinstance(entry, str)] if isinstance(value, list) else []


def permits(patterns, value):
    # Provisioning profiles may authorize a trailing wildcard. A signed
    # executable must claim the concrete identifier the app actually uses.
    return any(pattern == value or (pattern.endswith("*") and value.startswith(pattern[:-1]))
               for pattern in patterns)


def checks(label, info, signed, profile, now):
    errors, shared = [], []
    bundle = info.get("CFBundleIdentifier")
    if not isinstance(bundle, str) or not re.fullmatch(r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+", bundle):
        raise InspectionError(f"{label} 缺少有效的 Bundle ID。")
    claim = signed.get("application-identifier")
    allowed = profile.get("Entitlements")
    if not isinstance(claim, str) or not isinstance(allowed, dict):
        raise InspectionError(f"{label} 缺少签入的 application-identifier 或描述文件 Entitlements。")
    prefix, _, _ = claim.partition(".")
    prefixes = values(profile, "ApplicationIdentifierPrefix")
    if prefix not in prefixes or claim != prefix + "." + bundle:
        errors.append(f"Bundle ID 为 {bundle}，签入的 application-identifier 为 {claim}。")
    profile_id = allowed.get("application-identifier")
    if not isinstance(profile_id, str) or not permits([profile_id], claim):
        errors.append("描述文件未授权签入的 application-identifier。")
    elif not any(permits([profile_id], value + "." + bundle) for value in prefixes):
        errors.append(f"描述文件 {profile_id} 未授权此 Bundle ID，需要匹配的描述文件。")
    team = signed.get("com.apple.developer.team-identifier")
    if not isinstance(team, str) or team not in values(profile, "TeamIdentifier"):
        errors.append("签入的开发者团队与描述文件不匹配。")
    for field in ("CreationDate", "ExpirationDate"):
        date = profile.get(field)
        if not isinstance(date, dt.datetime):
            raise InspectionError(f"{label} 描述文件缺少 {field}。")
        if date.tzinfo is None:
            date = date.replace(tzinfo=dt.timezone.utc)
        if field == "CreationDate" and now < date:
            errors.append("描述文件尚未生效。")
        if field == "ExpirationDate" and now >= date:
            errors.append("描述文件已过期。")
    ne = "com.apple.developer.networking.networkextension"
    if "packet-tunnel-provider" not in values(signed, ne) or not permits(values(allowed, ne), "packet-tunnel-provider"):
        errors.append("可执行文件签名和描述文件需要同时授权 packet-tunnel-provider。")
    setting = info.get("CuvenKeychainAccessGroup")
    group = None
    if isinstance(setting, str):
        suffix = re.sub(r"^(?:\$\(AppIdentifierPrefix\)|[A-Z0-9]{10}\.)", "", setting, count=1)
        if suffix and "$(" not in suffix and "*" not in suffix:
            group = prefix + "." + suffix
    if not group:
        shared.append("Info.plist 未指定可解析的共享钥匙串组。")
    elif group not in values(signed, "keychain-access-groups"):
        shared.append(f"可执行文件未签入具体共享组 {group}。")
    elif not permits(values(allowed, "keychain-access-groups"), group):
        shared.append(f"描述文件未授权共享组 {group}。")
    return bundle, team, group, errors, shared


def inspect(path):
    now = dt.datetime.now(dt.timezone.utc)
    problems, shared_problems = [], []
    with zipfile.ZipFile(path) as archive, tempfile.TemporaryDirectory() as work:
        counts = Counter(archive.namelist())
        roots = [name.rsplit("/", 1)[0] for name in counts if re.fullmatch(r"Payload/[^/]+\.app/Info\.plist", name)]
        if len(roots) != 1:
            raise InspectionError("IPA 应包含一个主 App。")
        app_root = roots[0]
        targets = []
        for label, root in (("Cuven", app_root), ("CuvenTunnel", app_root + "/PlugIns/CuvenTunnel.appex")):
            info, signed, profile = read_target(archive, counts, root, Path(work))
            bundle, team, group, errors, shared = checks(label, info, signed, profile, now)
            if label == "CuvenTunnel":
                extension = info.get("NSExtension")
                if not isinstance(extension, dict) or extension.get("NSExtensionPointIdentifier") != "com.apple.networkextension.packet-tunnel":
                    errors.append("扩展未声明 Packet Tunnel 扩展点。")
            print(f"{label}  {bundle}")
            problems.extend(f"{label}：{msg}" for msg in errors)
            shared_problems.extend(f"{label}：{msg}" for msg in shared)
            targets.append((bundle, team, group))
    app, tunnel = targets
    if not tunnel[0].startswith(app[0] + "."):
        problems.append("扩展 Bundle ID 必须以主 App 的 Bundle ID 和句点开头。")
    if app[1] != tunnel[1]:
        problems.append("主 App 和扩展的签名团队不同。")
    if app[2] != tunnel[2]:
        shared_problems.append("主 App 和扩展配置的共享组不同。")
    for message in problems + shared_problems:
        print("• " + message)
    if problems:
        print("签名字段不匹配。请修正相应目标并重新签名。")
        return 1
    if shared_problems:
        print("Packet Tunnel 签名字段匹配。可测试 App 内手动连接；按需连接仍缺少共享钥匙串授权。")
        return 3
    print("两个目标的 Packet Tunnel、身份和共享钥匙串字段均匹配，可进行真机连接验证。")
    return 0


def main():
    parser = argparse.ArgumentParser(description="在本地核对重签后的 Cuven IPA。macOS 使用系统工具，Linux 需要 ldid 和 OpenSSL。")
    parser.add_argument("ipa", type=Path)
    args = parser.parse_args()
    try:
        return inspect(args.ipa)
    except (OSError, zipfile.BadZipFile, KeyError, InspectionError, subprocess.TimeoutExpired) as exc:
        print(f"未完成签名字段检查：{exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
