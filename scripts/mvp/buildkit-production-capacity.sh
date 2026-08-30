#!/usr/bin/env bash
set -euo pipefail

die() { printf 'open-card buildkit-capacity: %s\n' "$*" >&2; exit 2; }
verb=${1:-}
[[ "$verb" = install || "$verb" = remove || "$verb" = verify ]] || die 'usage: buildkit-production-capacity.sh install|remove|verify [--task-root PATH]'
shift

root=/
if [[ $# -gt 0 ]]; then
  [[ $# -eq 2 && "$1" = --task-root ]] || die 'invalid arguments'
  root=$2
  [[ "${OPEN_CARD_BUILDKIT_CAPACITY_TEST:-}" = 1 ]] || die 'task capacity seam is disabled'
  [[ "$root" = /* && "$root" != / && -d "$root" && ! -L "$root" ]] || die 'task capacity root is unsafe'
  [[ "$(realpath "$root")" = "$root" ]] || die 'task capacity root must be canonical'
else
  [[ "$EUID" -eq 0 ]] || die 'production capacity helper requires root'
fi

python3 - "$verb" "$root" <<'PY'
import errno
import json
import os
import stat
import sys
import tempfile

verb, root = sys.argv[1:]
task = root != "/"
expected_uid, expected_gid = (os.getuid(), os.getgid()) if task else (0, 0)
system_root = os.path.join(root, "etc", "systemd", "system")
directory = os.path.join(system_root, "open-card-buildkit.service.d")
target = os.path.join(directory, "20-production-capacity.conf")
content = b"[Service]\nMemoryMax=2G\nCPUQuota=200%\n"


def emit(status, code=None):
    value = {"status": status}
    if code is not None:
        value["code"] = code
    print(json.dumps(value, separators=(",", ":")))


def fail(code):
    emit("fail", code)
    raise SystemExit(1)


def metadata(path):
    try:
        return os.lstat(path)
    except FileNotFoundError:
        return None


def require_directory(path, *, exact_mode=None):
    value = metadata(path)
    if value is None or stat.S_ISLNK(value.st_mode) or not stat.S_ISDIR(value.st_mode):
        fail("unsafe_parent")
    mode = stat.S_IMODE(value.st_mode)
    if value.st_uid != expected_uid or value.st_gid != expected_gid or mode & 0o022:
        fail("unsafe_parent")
    if exact_mode is not None and mode != exact_mode:
        fail("unsafe_directory")


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def create_task_parents():
    require_directory(root)
    parent = root
    for component in ("etc", "systemd", "system"):
        child = os.path.join(parent, component)
        if metadata(child) is None:
            os.mkdir(child, 0o755)
            os.chown(child, expected_uid, expected_gid)
            sync_directory(parent)
        require_directory(child, exact_mode=0o755)
        parent = child


def require_fixed_parents(create=False):
    if task and create:
        create_task_parents()
        return
    require_directory(root)
    require_directory(os.path.join(root, "etc"))
    require_directory(os.path.join(root, "etc", "systemd"))
    require_directory(system_root)


def ensure_capacity_directory():
    value = metadata(directory)
    if value is None:
        os.mkdir(directory, 0o755)
        os.chown(directory, expected_uid, expected_gid)
        sync_directory(system_root)
    require_directory(directory, exact_mode=0o755)


def exact_target():
    value = metadata(target)
    if value is None or stat.S_ISLNK(value.st_mode) or not stat.S_ISREG(value.st_mode):
        return False
    if stat.S_IMODE(value.st_mode) != 0o644 or value.st_uid != expected_uid or value.st_gid != expected_gid:
        return False
    try:
        fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            chunks = []
            while True:
                chunk = os.read(fd, 4096)
                if not chunk:
                    break
                chunks.append(chunk)
            return b"".join(chunks) == content
        finally:
            os.close(fd)
    except OSError:
        return False


if verb == "verify":
    require_fixed_parents()
    require_directory(directory, exact_mode=0o755)
    if not exact_target():
        fail("invalid_target")
    emit("existing")
    raise SystemExit

if verb == "install":
    require_fixed_parents(create=True)
    ensure_capacity_directory()
    if os.path.lexists(target):
        if not exact_target():
            fail("invalid_target")
        emit("existing")
        raise SystemExit
    fd, temporary = tempfile.mkstemp(prefix=".20-production-capacity.", dir=directory)
    published = False
    try:
        try:
            view = memoryview(content)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    fail("write_failed")
                view = view[written:]
            os.fsync(fd)
            os.fchmod(fd, 0o644)
            os.fchown(fd, expected_uid, expected_gid)
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            os.link(temporary, target, follow_symlinks=False)
        except FileExistsError:
            fail("target_raced")
        published = True
        os.unlink(temporary)
        sync_directory(directory)
    finally:
        if os.path.lexists(temporary):
            os.unlink(temporary)
            if published:
                sync_directory(directory)
    if not exact_target():
        fail("reread_failed")
    emit("created")
    raise SystemExit

parent_paths = (root, os.path.join(root, "etc"), os.path.join(root, "etc", "systemd"), system_root)
if any(metadata(path) is None for path in parent_paths):
    emit("absent")
    raise SystemExit
require_fixed_parents()
if not os.path.lexists(target):
    emit("absent")
    raise SystemExit
require_directory(directory, exact_mode=0o755)
if not exact_target():
    fail("invalid_target")
os.unlink(target)
sync_directory(directory)
try:
    os.rmdir(directory)
except OSError as error:
    if error.errno not in (errno.ENOTEMPTY, errno.EEXIST):
        fail("directory_remove_failed")
else:
    sync_directory(system_root)
emit("removed")
PY
