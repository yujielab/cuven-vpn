#!/usr/bin/env python3
"""Remove Cuven's original, unconditional restart hook from its Certbot lineage."""
import errno
import fcntl
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile

LEGACY = b'/bin/sh -c "if systemctl is-active --quiet cuven-gateway.service; then systemctl restart cuven-gateway.service; fi"'
LINES = {b"renew_hook = '" + LEGACY + b"'", b"renew_hook = " + LEGACY}


def without_old_hook(data):
    in_params = False
    kept = []
    for line in data.splitlines(keepends=True):
        value = line.rstrip(b"\r\n")
        if value.startswith(b"["):
            in_params = value == b"[renewalparams]"
        if not (in_params and value in LINES):
            kept.append(line)
    return b"".join(kept)


def migrate(config):
    # The common path does not modify the lineage or acquire Certbot's lock.
    original = config.read_bytes()
    if without_old_hook(original) == original:
        return
    lock_path = config.parent.parent / ".certbot.lock"
    while True:
        fd = os.open(lock_path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as lock:
            # Certbot on Linux uses POSIX record locks and unlinks on release.
            fcntl.lockf(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            try:
                if not os.path.samestat(os.fstat(fd), lock_path.stat()):
                    continue
            except FileNotFoundError:
                continue
            try:
                info = config.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise ValueError("保留了非普通或有多个硬链接的 Certbot 配置，请检查旧续签钩子。")
                original = config.read_bytes()
                updated = without_old_hook(original)
                if updated == original:
                    return
                with tempfile.NamedTemporaryFile(dir=config.parent, delete=False) as out:
                    temp = Path(out.name)
                    try:
                        out.write(updated)
                        out.flush()
                        os.fchown(out.fileno(), info.st_uid, info.st_gid)
                        shutil.copystat(config, temp)
                        os.fsync(out.fileno())
                        os.replace(temp, config)
                    finally:
                        if temp.exists():
                            temp.unlink()
            finally:
                lock_path.unlink()
            return


if __name__ == "__main__":
    try:
        migrate(Path(sys.argv[1]))
    except OSError as exc:
        if exc.errno in (errno.EACCES, errno.EAGAIN):
            sys.exit("无法锁定 Certbot 续签配置。请在续签结束后重新运行安装器。")
        sys.exit(f"无法更新 Certbot 续签配置，系统错误 {exc.errno}。")
    except ValueError as exc:
        sys.exit(str(exc))
