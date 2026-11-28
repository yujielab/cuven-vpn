"""Update Cuven's generated MSS chain while holding the gateway installation lock."""
import os
from pathlib import Path
import re
import subprocess
import tempfile


FIREWALL = Path("/etc/cuven-gateway/firewall.nft")
CHAIN = "inet cuven_gateway tunnel_mss"
LEGACY = (
    "meta nfproto ipv4 tcp option maxseg size > 1240 tcp option maxseg size set 1240",
    "meta nfproto ipv6 tcp option maxseg size > 1220 tcp option maxseg size set 1220",
)
ROUTED = "tcp option maxseg size set rt mtu"
COMMENTS = {
    "# Keep a conservative MSS ceiling for both current and 1280-byte legacy peers.",
    "# cuven0 MTU is 1280. Allow for the fixed IP and TCP headers (RFC 6691).",
    "# Limit TCP segments to the smaller of the tunnel and egress path MTUs.",
}


def updated_config(config):
    blocks = list(re.finditer(r"^    chain tunnel_mss \{\n([^{}]*)^    \}$", config, re.M))
    if len(blocks) != 1:
        raise ValueError("未找到唯一的 Cuven MSS 规则链。")
    block = blocks[0]
    rules = tuple(line.strip() for line in block[1].splitlines()
                  if line.strip() and line.strip() not in COMMENTS)
    if rules == (ROUTED,):
        return config
    if rules != LEGACY:
        raise ValueError("磁盘 MSS 规则已自定义，请检查 firewall.nft。")
    body = "        # Limit TCP segments to the smaller of the tunnel and egress path MTUs.\n"
    return config[:block.start(1)] + body + "        " + ROUTED + "\n" + config[block.end(1):]


def live_update():
    listing = subprocess.check_output(["nft", "-a", "list", "chain", *CHAIN.split()], text=True)
    lines = [line.strip() for line in listing.splitlines()]
    if len(lines) < 4 or lines[0] != "table inet cuven_gateway {" or lines[-2:] != ["}", "}"] or not re.fullmatch(
            r"chain tunnel_mss \{ # handle \d+", lines[1]):
        raise ValueError("无法确认当前运行的 Cuven MSS 规则链。")
    entries = [re.fullmatch(r"(.+) # handle (\d+)", line) for line in lines[2:-2]]
    if any(entry is None for entry in entries):
        raise ValueError("无法确认运行中的 MSS 规则。")
    rules = tuple(entry[1] for entry in entries)
    if rules == (ROUTED,):
        return ""
    if rules != LEGACY:
        raise ValueError("运行中的 MSS 规则已自定义，请检查 tunnel_mss。")
    return (f"replace rule {CHAIN} handle {entries[0][2]} {ROUTED}\n"
            f"delete rule {CHAIN} handle {entries[1][2]}\n")


def update():
    if FIREWALL.is_symlink() or not FIREWALL.is_file():
        raise ValueError("需要已安装网关的常规 firewall.nft 配置文件。")
    original = FIREWALL.read_bytes()
    candidate = updated_config(original.decode()).encode()
    batch = live_update()
    if not batch and candidate == original:
        return
    if batch:
        subprocess.run(["nft", "--check", "-f", "-"], input=batch, text=True, check=True)
    # Publish the persistent setting before the live transaction. A retry can
    # finish either side independently after a power loss.
    with tempfile.TemporaryDirectory(dir=FIREWALL.parent) as work:
        saved = Path(work) / "previous"
        if candidate != original:
            prepared = Path(work) / "firewall.nft"
            prepared.write_bytes(candidate)
            os.chmod(prepared, 0o600)
            subprocess.run(["nft", "--check", "-f", prepared], check=True)
            os.link(FIREWALL, saved)
            os.replace(prepared, FIREWALL)
        if batch:
            try:
                subprocess.run(["nft", "-f", "-"], input=batch, text=True, check=True)
            except (OSError, subprocess.CalledProcessError):
                if saved.exists():
                    os.replace(saved, FIREWALL)
                raise


if __name__ == "__main__":
    try:
        update()
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        raise SystemExit(f"MSS 设置未完成。{error}")
    print("TCP 分段上限已按网关实际路由 MTU 调整。")
