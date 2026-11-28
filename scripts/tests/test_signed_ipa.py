import datetime as dt
import importlib.util
import pathlib
import plistlib
import ssl
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile
from unittest import mock

TOOL = pathlib.Path(__file__).resolve().parents[1] / "check-signed-ipa.py"
spec = importlib.util.spec_from_file_location("signing", TOOL)
signing = importlib.util.module_from_spec(spec)
spec.loader.exec_module(signing)

NOW = dt.datetime.now(dt.timezone.utc)
PREFIX = "APPX123456"
TEAM = "TEAM123456"
GROUP = PREFIX + ".dev.cuven.vpn.shared"
NETWORK = "com.apple.developer.networking.networkextension"


def fields(bundle="dev.cuven.vpn"):
    info = {"CFBundleIdentifier": bundle, "CuvenKeychainAccessGroup": "$(AppIdentifierPrefix)dev.cuven.vpn.shared"}
    signed = {"application-identifier": PREFIX + "." + bundle, "com.apple.developer.team-identifier": TEAM,
              NETWORK: ["packet-tunnel-provider"], "keychain-access-groups": [GROUP]}
    grant = {**signed, "keychain-access-groups": [PREFIX + ".*"]}
    date = NOW.replace(tzinfo=None)
    profile = {"Entitlements": grant, "TeamIdentifier": [TEAM], "ApplicationIdentifierPrefix": [PREFIX],
               "CreationDate": date - dt.timedelta(days=1), "ExpirationDate": date + dt.timedelta(days=1)}
    return info, signed, profile


class SigningFields(unittest.TestCase):
    def test_explicit_wrong_profile_for_claimed_identity(self):
        info, signed, profile = fields()
        signed["application-identifier"] = PREFIX + ".unrelated.product"
        profile["Entitlements"]["application-identifier"] = signed["application-identifier"]
        *_, errors, _ = signing.checks("App", info, signed, profile, NOW)
        self.assertEqual(len(errors), 2)

    def test_profile_wildcard_with_distinct_team_and_app_prefix(self):
        info, signed, profile = fields()
        profile["Entitlements"]["application-identifier"] = PREFIX + ".*"
        *_, errors, shared = signing.checks("App", info, signed, profile, NOW)
        self.assertEqual((errors, shared), ([], []))

    def test_signer_selects_custom_shared_group_without_plist_override(self):
        custom = PREFIX + ".vendor.chosen-by-signer"
        app, tunnel = [], []
        for bundle, selected in (("com.fixture.app", app), ("com.fixture.app.tunnel", tunnel)):
            info, signed, profile = fields(bundle)
            info.pop("CuvenKeychainAccessGroup")
            info["CuvenCredentialStorageVersion"] = 2
            identity = signed["application-identifier"]
            signed["keychain-access-groups"] = [identity, custom]
            profile["Entitlements"]["keychain-access-groups"] = [PREFIX + ".*"]
            _, _, groups, errors, shared = signing.checks(bundle, info, signed, profile, NOW)
            self.assertEqual((errors, shared), ([], []))
            selected.extend(groups)
        self.assertEqual(set(app).intersection(tunnel), {custom})

    def test_access_group_claims_must_be_authorized_even_if_other_groups_match(self):
        for version in (1, 2):
            for key in ("keychain-access-groups", "com.apple.security.application-groups"):
                with self.subTest(version=version, key=key):
                    info, signed, profile = fields()
                    info["CuvenCredentialStorageVersion"] = version
                    signed[key] = [GROUP, "other.ungranted"]
                    profile["Entitlements"][key] = [PREFIX + ".*"]
                    *_, errors, _ = signing.checks("App", info, signed, profile, NOW)
                    self.assertTrue(any(key in error for error in errors))

    def test_signed_access_groups_are_arrays_of_concrete_names(self):
        for claims in (PREFIX + ".one", [""], ["$(AppIdentifierPrefix)one"], [PREFIX + ".*"], [1]):
            with self.subTest(claims=claims):
                info, signed, profile = fields()
                signed["keychain-access-groups"] = claims
                *_, errors, _ = signing.checks("App", info, signed, profile, NOW)
                self.assertTrue(any("keychain-access-groups" in error for error in errors))

    def test_valid_disjoint_grants_only_affect_shared_storage(self):
        for version in (1, 2):
            targets = []
            for bundle in ("dev.cuven.vpn", "dev.cuven.vpn.tunnel"):
                info, signed, profile = fields(bundle)
                info["CuvenCredentialStorageVersion"] = version
                identity = signed["application-identifier"]
                signed["keychain-access-groups"] = [identity]
                _, _, groups, errors, shared = signing.checks(bundle, info, signed, profile, NOW)
                self.assertFalse(errors)
                self.assertEqual(bool(shared), version == 1)
                targets.append(groups)
            self.assertTrue(targets[0].isdisjoint(targets[1]))

    def test_profile_must_allow_both_packet_tunnel_and_claimed_keychain_groups(self):
        info, signed, profile = fields()
        profile["Entitlements"][NETWORK] = ["dns-proxy"]
        profile["Entitlements"]["keychain-access-groups"] = [PREFIX + ".other"]
        *_, errors, _ = signing.checks("App", info, signed, profile, NOW)
        self.assertTrue(any("packet-tunnel-provider" in error for error in errors))
        self.assertTrue(any("keychain-access-groups" in error for error in errors))

    def test_additional_signed_network_extension_types_need_profile_grants(self):
        info, signed, profile = fields()
        signed[NETWORK] = ["packet-tunnel-provider", "dns-proxy"]
        for allowed, expected in (
            (["packet-tunnel-provider"], False),
            (["packet-tunnel-provider", "app-proxy-provider"], False),
            (["packet-tunnel-provider", "dns-proxy"], True),
            (["*"], True),
        ):
            with self.subTest(allowed=allowed):
                profile["Entitlements"][NETWORK] = allowed
                *_, errors, shared = signing.checks("App", info, signed, profile, NOW)
                self.assertEqual(not errors, expected)
                self.assertEqual(shared, [])

    def test_debugger_permission_needs_an_explicit_profile_grant(self):
        info, signed, profile = fields()
        signed["get-task-allow"] = True
        for permission in (None, False, True):
            if permission is not None:
                profile["Entitlements"]["get-task-allow"] = permission
            *_, errors, _ = signing.checks("App", info, signed, profile, NOW)
            self.assertEqual(bool(errors), permission is not True)
        signed["get-task-allow"] = False
        *_, errors, _ = signing.checks("App", info, signed, profile, NOW)
        self.assertFalse(errors)

    def test_device_lists_must_admit_the_same_phone(self):
        first, other = "A" * 40, "B" * 40
        targets = [("App", {"ProvisionedDevices": [first, other]}),
                   ("Extension", {"ProvisionedDevices": [first.lower()]})]
        self.assertEqual(signing.device_problems(targets), [])
        self.assertEqual(signing.device_problems(targets, first), [])
        missing = signing.device_problems(targets, other)
        self.assertEqual(len(missing), 1)
        self.assertIn("Extension", missing[0])
        self.assertNotIn(other, missing[0])
        targets[1][1]["ProvisionedDevices"] = ["C" * 40]
        self.assertIn("没有共同", signing.device_problems(targets)[0])

    def test_optional_device_check_respects_profile_distribution(self):
        unrestricted = ("App", {"ProvisionsAllDevices": True})
        store = ("Extension", {})
        self.assertEqual(signing.device_problems([unrestricted, store]), [])
        self.assertEqual(len(signing.device_problems([unrestricted, store], "A" * 40)), 1)
        self.assertTrue(signing.device_problems([unrestricted, ("Extension", {"ProvisionedDevices": []})]))
        with self.assertRaises(signing.InspectionError):
            signing.device_problems([("App", {"ProvisionedDevices": [123]})])

    def test_provisioning_platform_when_declared(self):
        info, signed, profile = fields()
        for platforms, valid in ((["iOS"], True), (["tvOS", "iOS"], True),
                                 (["OSX"], False), (["tvOS"], False), ([], False)):
            with self.subTest(platforms=platforms):
                *_, errors, _ = signing.checks("App", info, signed, dict(profile, Platform=platforms), NOW)
                self.assertEqual(not errors, valid)
        profile.pop("Platform", None)
        *_, errors, _ = signing.checks("App", info, signed, profile, NOW)
        self.assertEqual(errors, [])

    def test_macho_device_platforms_and_command_bounds(self):
        def thin(*commands):
            body = b"".join(commands)
            return struct.pack("<8I", 0xFEEDFACF, signing.ARM64, 0, 2, len(commands), len(body), 0, 0) + body

        def build(platform, tools=0):
            return struct.pack("<6I", 0x32, 24, platform, 0x110000, 0x110000, tools)

        old_ios = struct.pack("<4I", 0x25, 16, 0x90000, 0x90000)
        for image in (thin(build(2)), thin(old_ios)):
            self.assertIsNone(signing.code_signature(image, 0, len(image)))
        for image in (thin(build(1)), thin(build(7)), thin(old_ios, build(7))):
            with self.assertRaises(signing.NonDeviceExecutable):
                signing.code_signature(image, 0, len(image))
        for image in (thin(struct.pack("<3I", 0x32, 12, 2)), thin(build(2, tools=1))):
            with self.assertRaises(signing.InspectionError):
                signing.code_signature(image, 0, len(image))

    @unittest.skipUnless(sys.platform == "darwin", "uses the iOS simulator SDK")
    def test_arm64_simulator_executable_is_reported_before_signer_mismatch(self):
        with tempfile.TemporaryDirectory() as path:
            root = pathlib.Path(path)
            binary = root / "simulator-app"
            subprocess.run(
                ["xcrun", "--sdk", "iphonesimulator", "clang", "-arch", "arm64",
                 "-mios-simulator-version-min=17.0", "-x", "c", "-", "-o", str(binary)],
                input=b"int main(void) { return 0; }", capture_output=True, check=True,
            )
            self.assertIn("iOS 模拟器", signing.signer_problem(binary, {}, root, NOW))

    def test_expired_profile(self):
        info, signed, profile = fields()
        *_, errors, _ = signing.checks("App", info, signed, profile, NOW + dt.timedelta(days=2))
        self.assertTrue(errors)

    def test_only_the_verified_cms_signer_can_satisfy_a_profile(self):
        with tempfile.TemporaryDirectory() as path:
            root = pathlib.Path(path)
            def openssl(*args, data=None):
                return subprocess.run(
                    ["openssl", *args], input=data, cwd=root, capture_output=True, check=True,
                ).stdout
            for name in ("signer", "unrelated"):
                openssl("req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-subj", "/CN=LocalFixture-" + name, "-keyout", name + ".key", "-out", name + ".pem")
            directory = b"code-directory-test-fixture"
            signature = openssl("smime", "-sign", "-binary", "-inkey", "signer.key", "-signer", "signer.pem",
                                "-certfile", "unrelated.pem", "-outform", "DER", data=directory)
            signing_cert = ssl.PEM_cert_to_DER_cert((root / "signer.pem").read_text())
            unrelated_cert = ssl.PEM_cert_to_DER_cert((root / "unrelated.pem").read_text())
            binary = root / "arm64"
            binary.write_bytes(b"fixture")
            now = dt.datetime.now(dt.timezone.utc)
            for content, allowed, day_offset, message in [
                (directory, [signing_cert], 0, None),
                (directory, [signing_cert], -2, "尚未生效"),
                (directory, [signing_cert], 2, "已过期"),
                (directory, [unrelated_cert], 0, "DeveloperCertificates"),
                (directory, [], 0, "DeveloperCertificates"),
                (directory + b"changed", [signing_cert], 0, "CodeDirectory"),
            ]:
                with self.subTest(message=message), mock.patch.object(
                    signing, "code_signature", return_value=(content, signature)
                ):
                    result = signing.signer_problem(
                        binary, {"DeveloperCertificates": allowed}, root, now + dt.timedelta(days=day_offset)
                    )
                    if message is None:
                        self.assertIsNone(result)
                    else:
                        self.assertIn(message, result)

    def test_fat_slices_and_embedded_signature_bounds(self):
        directory = struct.pack(">II", 0xFADE0C02, 8)
        cms = b"synthetic"
        wrapper = struct.pack(">II", 0xFADE0B01, 8 + len(cms)) + cms
        blob = (struct.pack(">7I", 0xFADE0CC0, 28 + len(directory + wrapper), 2,
                            0, 28, 0x10000, 28 + len(directory)) + directory + wrapper)
        header = struct.pack("<8I", 0xFEEDFACF, signing.ARM64, 0, 2, 1, 16, 0, 0)
        thin = header + struct.pack("<4I", 0x1D, 16, 48, len(blob)) + blob
        fat = struct.pack(">7I", 0xCAFEBABE, 1, signing.ARM64, 0, 28, len(thin), 2) + thin
        self.assertEqual(signing.arm64_images(fat), [(28, len(fat))])
        self.assertEqual(signing.code_signature(fat, 28, len(fat)), (directory, cms))
        for cut in (0, 28, len(fat) - 1):
            with self.subTest(cut=cut), self.assertRaises(signing.InspectionError):
                signing.code_signature(fat, 28, cut)
        with self.assertRaises(signing.InspectionError):
            signing.arm64_images(fat[:-1])

    @unittest.skipUnless(sys.platform == "darwin", "uses Apple signing tools")
    def test_macos_tools_reject_an_ad_hoc_signature_on_each_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            def run(*args, **kw):
                return subprocess.run(args, cwd=tmp, capture_output=True, check=True, **kw)
            run("/usr/bin/openssl", "req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", "qa.key", "-out", "qa.crt", "-days", "1", "-subj", "/CN=CuvenLocalFixture")
            run("xcrun", "--sdk", "iphoneos", "clang", "-arch", "arm64", "-miphoneos-version-min=17.0",
                "-x", "c", "-", "-o", "thin", input=b"int main(void) { return 0; }")
            archive = root / "fixture.ipa"
            with zipfile.ZipFile(archive, "w") as z:
                for exe, path, bundle in (
                    ("Cuven", "Payload/Cuven.app", "dev.cuven.vpn"),
                    ("CuvenTunnel", "Payload/Cuven.app/PlugIns/CuvenTunnel.appex", "dev.cuven.vpn.tunnel"),
                ):
                    info, signed, profile = fields(bundle)
                    info["CFBundleExecutable"] = exe
                    if exe == "CuvenTunnel":
                        info["NSExtension"] = {"NSExtensionPointIdentifier": "com.apple.networkextension.packet-tunnel"}
                    (root / "ent.plist").write_bytes(plistlib.dumps(signed))
                    run("/usr/bin/codesign", "--force", "-s", "-", "--timestamp=none", "--entitlements", "ent.plist", "thin")
                    cms = run("/usr/bin/openssl", "smime", "-sign", "-binary", "-nodetach", "-inkey", "qa.key",
                              "-signer", "qa.crt", "-outform", "DER", input=plistlib.dumps(profile))
                    z.writestr(path + "/Info.plist", plistlib.dumps(info))
                    z.writestr(path + "/embedded.mobileprovision", cms.stdout)
                    z.write(root / "thin", path + "/" + exe)
            result = subprocess.run([sys.executable, str(TOOL), str(archive)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
            self.assertEqual(result.stdout.count("缺少证书签名"), 2)
