#!/usr/bin/env python3
"""Offline signing-field check for locally re-signed Cuven IPAs."""
import argparse
import getpass
import datetime as dt
import mmap
import plistlib
import re
import shutil
import ssl
import struct
import subprocess
import sys
import tempfile
import zipfile
from collections import Counter
from pathlib import Path
from xml.parsers.expat import ExpatError


class InspectionError(Exception):
    pass


class NonDeviceExecutable(InspectionError):
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


# Apple mach-o/fat.h, loader.h and Security's CSCommon: integers in the
# embedded signature are big-endian even when the Mach-O header is not.
ARM64 = 0x0100000C
LEGACY_BUILD_PLATFORMS = {0x24: 1, 0x25: 2, 0x2F: 3, 0x30: 4}


def region(offset, size, lower, upper):
    if offset < lower or size < 0 or offset + size > upper:
        raise InspectionError("可执行文件的签名结构超出边界。")
    return offset + size


def arm64_images(data):
    fat_formats = {
        b"\xca\xfe\xba\xbe": ">IIIII", b"\xbe\xba\xfe\xca": "<IIIII",
        b"\xca\xfe\xba\xbf": ">IIQQII", b"\xbf\xba\xfe\xca": "<IIQQII",
    }
    record = fat_formats.get(data[:4])
    if record is None:
        return [(0, len(data))]
    region(0, 8, 0, len(data))
    count = struct.unpack_from(record[0] + "I", data, 4)[0]
    size = struct.calcsize(record)
    table_end = region(8, count * size, 0, len(data))
    images = []
    for entry in range(8, table_end, size):
        cpu, _, offset, length, *_ = struct.unpack_from(record, data, entry)
        if cpu == ARM64:
            images.append((offset, region(offset, length, table_end, len(data))))
    if not images:
        raise InspectionError("可执行文件缺少 arm64 架构。")
    return images


def code_signature(data, start, end):
    position = region(start, 32, start, end)
    if struct.unpack_from("<II", data, start) != (0xFEEDFACF, ARM64):
        raise InspectionError("无法识别 arm64 Mach-O 头。")
    count, length = struct.unpack_from("<II", data, start + 16)
    commands_end = region(position, length, position, end)
    signature = None
    platforms = set()
    minimum_platforms = set()
    for _ in range(count):
        region(position, 8, start, commands_end)
        command, size = struct.unpack_from("<II", data, position)
        following = region(position, size, position, commands_end)
        if size < 8:
            raise InspectionError("Mach-O 命令长度无效。")
        if command == 0x32:  # LC_BUILD_VERSION
            if size < 24:
                raise InspectionError("Mach-O 平台版本命令不完整。")
            platform, _, _, tool_count = struct.unpack_from("<4I", data, position + 8)
            if 24 + 8 * tool_count > size:
                raise InspectionError("Mach-O 平台工具列表超出命令边界。")
            platforms.add(platform)
        elif command in LEGACY_BUILD_PLATFORMS:  # LC_VERSION_MIN_*
            if size < 16:
                raise InspectionError("Mach-O 最低系统版本命令不完整。")
            minimum_platforms.add(LEGACY_BUILD_PLATFORMS[command])
        elif command == 0x1D:  # LC_CODE_SIGNATURE
            if size < 16 or signature is not None:
                raise InspectionError("Mach-O 签名命令无效。")
            offset, size_on_disk = struct.unpack_from("<II", data, position + 8)
            begin = start + offset
            signature = (begin, region(begin, size_on_disk, commands_end, end))
        position = following
    declared = platforms or minimum_platforms
    if declared and 2 not in declared:  # PLATFORM_IOS
        if declared == {7}:  # PLATFORM_IOSSIMULATOR
            raise NonDeviceExecutable("arm64 可执行文件面向 iOS 模拟器。请使用 iphoneos SDK 构建设备版。")
        raise NonDeviceExecutable("arm64 可执行文件声明的平台不包含 iOS 真机。请核对构建目标。")
    if signature is None:
        return None
    base, limit = signature
    region(base, 12, base, limit)
    magic, length, count = struct.unpack_from(">III", data, base)
    limit = region(base, length, base, limit)
    table_end = region(base + 12, 8 * count, base, limit)
    if magic != 0xFADE0CC0:
        raise InspectionError("无法识别嵌入签名。")
    parts = {}
    for entry in range(base + 12, table_end, 8):
        slot, relative = struct.unpack_from(">II", data, entry)
        if slot not in (0, 0x10000):
            continue
        header = base + relative
        region(header, 8, table_end, limit)
        kind, length = struct.unpack_from(">II", data, header)
        finish = region(header, length, table_end, limit)
        expected = 0xFADE0C02 if slot == 0 else 0xFADE0B01
        if length < 8 or kind != expected or slot in parts:
            raise InspectionError("CodeDirectory 或 CMS 签名条目无效。")
        parts[slot] = data[header:finish] if slot == 0 else data[header + 8:finish]
    if not parts.get(0x10000):
        return None
    if 0 not in parts:
        raise InspectionError("缺少 CMS 对应的 CodeDirectory。")
    return parts[0], parts[0x10000]


def signer_problem(binary, profile, temp, now):
    openssl = "/usr/bin/openssl" if sys.platform == "darwin" else "openssl"
    if not shutil.which(openssl):
        raise InspectionError("核对签名证书需要 OpenSSL。")
    authorized = profile.get("DeveloperCertificates", [])
    if not binary.stat().st_size:
        raise InspectionError("可执行文件为空。")
    with binary.open("rb") as source, mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as data:
        for start, end in arm64_images(data):
            try:
                parts = code_signature(data, start, end)
            except NonDeviceExecutable as exc:
                return str(exc)
            if parts is None:
                return "arm64 可执行文件缺少证书签名。请使用描述文件授权的签名身份重签。"
            directory, cms = parts
            content = temp / "code-directory"
            signer = temp / "cms-signer.pem"
            signer.unlink(missing_ok=True)
            content.write_bytes(directory)
            # -signer on verification returns only actual signers, excluding
            # unrelated certificates in the embedded certification chain.
            result = subprocess.run(
                [openssl, "smime", "-verify", "-inform", "DER", "-binary", "-noverify",
                 "-content", str(content), "-signer", str(signer)],
                input=cms, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=30,
            )
            if result.returncode:
                return "CMS 签名与可执行文件的 CodeDirectory 不匹配。"
            if not signer.is_file():
                raise InspectionError("无法提取 CMS 签名证书。")
            pem = signer.read_text(encoding="ascii")
            if pem.count("-----BEGIN CERTIFICATE-----") != 1:
                raise InspectionError("无法确定唯一的 CMS 签名证书。")
            leaf = ssl.PEM_cert_to_DER_cert(pem)
            if not isinstance(authorized, list) or leaf not in authorized:
                return "实际签名证书未列入本目标描述文件的 DeveloperCertificates。"
            dates = output([openssl, "x509", "-in", str(signer), "-noout", "-dates"], "签名证书有效期")
            try:
                fields = dict(line.split("=", 1) for line in dates.decode("ascii").splitlines())
                start = ssl.cert_time_to_seconds(fields["notBefore"])
                end = ssl.cert_time_to_seconds(fields["notAfter"])
            except (KeyError, ValueError, OverflowError) as exc:
                raise InspectionError("无法读取实际签名证书的有效期。") from exc
            if now.timestamp() < start:
                return "实际签名证书尚未生效，请核对系统时间和重签身份。"
            if now.timestamp() > end:
                return "实际签名证书已过期，请使用有效且获描述文件授权的身份重签。"
    return None


def read_target(archive, counts, root, temp, now):
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
    signed = plist(output(signing_args, root), "可执行文件签名")
    profile = plist(output(profile_args, root), "描述文件")
    return info, signed, profile, signer_problem(binary, profile, temp, now)


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
    if "Platform" in profile and "iOS" not in values(profile, "Platform"):
        errors.append("描述文件的 Platform 列表未授权 iOS 真机。")
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
    if signed.get("get-task-allow") is True and allowed.get("get-task-allow") is not True:
        errors.append("可执行文件签入了 get-task-allow 调试权限，描述文件未授权此权限。")
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


def device_problems(profiles, device_udid=None):
    errors, registered_sets = [], []
    for label, profile in profiles:
        if profile.get("ProvisionsAllDevices") is True:
            continue
        if "ProvisionedDevices" not in profile:
            if device_udid is not None:
                errors.append(f"{label} 的描述文件缺少直接安装到所选设备的授权。")
            continue
        entries = profile["ProvisionedDevices"]
        if not isinstance(entries, list) or not all(isinstance(v, str) and v.strip() for v in entries):
            raise InspectionError(f"{label} 描述文件的 ProvisionedDevices 无法解析。")
        devices = {value.strip().casefold() for value in entries}
        if not devices:
            errors.append(f"{label} 描述文件中的已注册设备列表为空。")
        elif device_udid is not None and device_udid.casefold() not in devices:
            errors.append(f"{label} 描述文件未授权所选设备。")
        registered_sets.append(devices)
    if len(registered_sets) == 2 and all(registered_sets) and registered_sets[0].isdisjoint(registered_sets[1]):
        errors.append("主 App 和扩展的描述文件没有共同授权的设备。")
    return errors


def inspect(path, device_udid=None):
    now = dt.datetime.now(dt.timezone.utc)
    problems, shared_problems = [], []
    with zipfile.ZipFile(path) as archive, tempfile.TemporaryDirectory() as work:
        counts = Counter(archive.namelist())
        roots = [name.rsplit("/", 1)[0] for name in counts if re.fullmatch(r"Payload/[^/]+\.app/Info\.plist", name)]
        if len(roots) != 1:
            raise InspectionError("IPA 应包含一个主 App。")
        app_root = roots[0]
        targets, profiles = [], []
        for label, root in (("Cuven", app_root), ("CuvenTunnel", app_root + "/PlugIns/CuvenTunnel.appex")):
            info, signed, profile, signer_error = read_target(archive, counts, root, Path(work), now)
            bundle, team, group, errors, shared = checks(label, info, signed, profile, now)
            if signer_error:
                errors.append(signer_error)
            if label == "CuvenTunnel":
                extension = info.get("NSExtension")
                if not isinstance(extension, dict) or extension.get("NSExtensionPointIdentifier") != "com.apple.networkextension.packet-tunnel":
                    errors.append("扩展未声明 Packet Tunnel 扩展点。")
            print(f"{label}  {bundle}")
            problems.extend(f"{label}：{msg}" for msg in errors)
            shared_problems.extend(f"{label}：{msg}" for msg in shared)
            targets.append((bundle, team, group))
            profiles.append((label, profile))
        problems.extend(device_problems(profiles, device_udid))
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
        print("IPA 未通过检查。请核对以上目标的签名和描述文件。")
        return 1
    if device_udid is not None:
        print("两个目标的描述文件均覆盖所选设备。")
    if shared_problems:
        print("Packet Tunnel 签名字段匹配。可测试 App 内手动连接；按需连接仍缺少共享钥匙串授权。")
        return 3
    print("两个目标的签名证书、Packet Tunnel、身份和共享钥匙串字段均匹配，可进行真机连接验证。")
    return 0


def main():
    parser = argparse.ArgumentParser(description="在本地核对重签后的 Cuven IPA。macOS 使用系统工具，Linux 需要 ldid 和 OpenSSL。")
    parser.add_argument("ipa", type=Path)
    parser.add_argument("--check-device", action="store_true",
                        help="从本机终端或标准输入读取 iPhone UDID，检查两个目标的直装授权")
    args = parser.parse_args()
    try:
        device = None
        if args.check_device:
            value = getpass.getpass("本机输入 iPhone UDID（隐藏显示） ") if sys.stdin.isatty() else sys.stdin.readline()
            device = value.strip()
            if not re.fullmatch(r"[0-9A-Fa-f]{40}|[0-9A-Fa-f]{8}-[0-9A-Fa-f]{16}", device):
                parser.error("请输入有效的 iPhone UDID。")
        return inspect(args.ipa, device)
    except (OSError, EOFError, zipfile.BadZipFile, KeyError, InspectionError, subprocess.TimeoutExpired) as exc:
        print(f"未完成签名字段检查：{exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
