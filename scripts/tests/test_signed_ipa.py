import datetime as dt
import importlib.util
import pathlib
import plistlib
import subprocess
import sys
import tempfile
import unittest
import zipfile

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

    def test_signed_wildcard_is_not_a_specific_shared_group(self):
        info, signed, profile = fields()
        signed["keychain-access-groups"] = [PREFIX + ".*"]
        *_, errors, shared = signing.checks("App", info, signed, profile, NOW)
        self.assertFalse(errors)
        self.assertTrue(shared)

    def test_profile_must_allow_claimed_packet_tunnel_and_shared_group(self):
        info, signed, profile = fields()
        profile["Entitlements"][NETWORK] = ["dns-proxy"]
        profile["Entitlements"]["keychain-access-groups"] = [PREFIX + ".other"]
        *_, errors, shared = signing.checks("App", info, signed, profile, NOW)
        self.assertTrue(errors)
        self.assertTrue(shared)

    def test_expired_profile(self):
        info, signed, profile = fields()
        *_, errors, _ = signing.checks("App", info, signed, profile, NOW + dt.timedelta(days=2))
        self.assertTrue(errors)

    @unittest.skipUnless(sys.platform == "darwin", "uses Apple signing tools")
    def test_macos_tools_read_both_archived_targets(self):
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
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
