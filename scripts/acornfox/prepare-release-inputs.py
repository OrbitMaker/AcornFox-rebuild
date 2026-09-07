#!/usr/bin/env python3
"""Freeze local release inputs; this neither builds nor approves a release."""

import argparse
import hashlib
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys
import tarfile

TARGETS = (
    'open-card-server', 'open-card-agent', 'open-card-static-server',
    'open-card-secretctl', 'open-card-security-probe', 'open-card-imagegc',
    'acornfox', 'open-card-admin', 'open-card-upgrade', 'open-card-healthcheck',
    'acornfox-pi-worker',
)
MODULE = 'github.com/open-card/open-card'
VERSION = re.compile(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)'
                     r'(-[0-9A-Za-z]+(?:\.[0-9A-Za-z]+)*)?(\+[0-9A-Za-z]+(?:\.[0-9A-Za-z]+)*)?')
REPOSITORY = re.compile(r'https://github\.com/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}')
PI_ARCHIVE_SHA256 = '494e498f47d74d21f40b3386f6a5e921a3d49531a169cab55bbdaca0ea1fe25a'
PI_SHA256SUMS_SHA256 = '0b70b2e422339b7a1277c3addb3705e1239d21ca1c20a17741a7b1c06d7526b0'
PI_MANIFEST_SHA256 = 'e8d788ebaab78af97ca959b91a1abfe9fc820de4a4c6aadcd870bb500679934d'
PI_MANIFEST = pathlib.Path('internal/pibundle/assets-v0.85.1-linux-x64.json')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def canonical(value):
    # Preserve insertion order to match the Go DTO field order. encoding/json
    # additionally escapes HTML and the two JavaScript line separators.
    text = json.dumps(value, ensure_ascii=False, separators=(',', ':'), allow_nan=False)
    for literal, escaped in (('&', '\\u0026'), ('<', '\\u003c'), ('>', '\\u003e'),
                             ('\u2028', '\\u2028'), ('\u2029', '\\u2029')):
        text = text.replace(literal, escaped)
    return text.encode('utf-8')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def file_sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def clean_path(value, existing=True):
    path = pathlib.Path(value)
    require(path.is_absolute() and str(path) == value and path != pathlib.Path('/'),
            'paths must be absolute, normalized and different from /')
    require(path.resolve(strict=existing) == path, 'paths must not traverse symlinks')
    if existing:
        require(path.is_dir(), 'input roots must be directories')
    return path


def clean_file(value):
    path = pathlib.Path(value)
    require(path.is_absolute() and str(path) == value and path != pathlib.Path('/'),
            'pi archive path must be absolute and normalized')
    require(path.resolve(strict=True) == path, 'pi archive path must not traverse symlinks')
    info = path.stat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= 512 << 20,
            'pi archive must be a bounded single-link regular file')
    return path


def load_pi_manifest(source):
    path = source / PI_MANIFEST
    raw = path.read_bytes()
    require(len(raw) <= 1 << 20 and sha(raw) == PI_MANIFEST_SHA256,
            'pinned pi asset manifest digest mismatch')
    value = json.loads(raw)
    require(raw == canonical(value) + b'\n' and value.get('schema_version') == 1 and
            value.get('version') == '0.85.1' and value.get('archive_sha256') == PI_ARCHIVE_SHA256 and
            value.get('sha256sums_sha256') == PI_SHA256SUMS_SHA256,
            'pinned pi asset manifest identity mismatch')
    files = value.get('files')
    require(isinstance(files, list) and len(files) == 218,
            'pinned pi asset manifest file count mismatch')
    previous = ''
    for entry in files:
        require(list(entry) == ['path', 'mode', 'size', 'sha256'] and
                isinstance(entry['path'], str) and entry['path'].startswith('pi/') and
                entry['path'] > previous and entry['mode'] in (0o644, 0o755) and
                isinstance(entry['size'], int) and 0 <= entry['size'] <= 128 << 20 and
                re.fullmatch('[0-9a-f]{64}', entry['sha256']),
                'pinned pi asset manifest entry invalid')
        previous = entry['path']
    require(sum(entry['size'] for entry in files) == 113642165,
            'pinned pi asset manifest size mismatch')
    return value


def verify_pi_archive(source, archive):
    manifest = load_pi_manifest(source)
    require(file_sha(archive) == PI_ARCHIVE_SHA256, 'pi archive sha256 mismatch')
    expected = {entry['path']: entry for entry in manifest['files']}
    expected_dirs = {'pi/'}
    for name in expected:
        parent = pathlib.PurePosixPath(name).parent
        while str(parent) != '.':
            expected_dirs.add(str(parent) + '/')
            parent = parent.parent
    seen, directories = {}, set()
    with tarfile.open(archive, 'r:gz') as stream:
        members = stream.getmembers()
        require(len(members) <= 512, 'pi archive member count exceeds limit')
        for member in members:
            normalized = member.name.rstrip('/')
            require(normalized == pathlib.PurePosixPath(normalized).as_posix() and
                    (normalized == 'pi' or normalized.startswith('pi/')) and
                    '..' not in pathlib.PurePosixPath(normalized).parts,
                    'pi archive contains an unsafe path')
            if member.isdir():
                require(normalized + '/' not in directories, 'pi archive contains a duplicate directory')
                directories.add(normalized + '/')
                continue
            require(member.isfile() and member.name in expected and member.name not in seen,
                    'pi archive contains an unexpected member')
            wanted = expected[member.name]
            require(member.mode == wanted['mode'] and member.size == wanted['size'],
                    'pi archive member metadata mismatch')
            data = stream.extractfile(member).read(wanted['size'] + 1)
            require(len(data) == wanted['size'] and sha(data) == wanted['sha256'],
                    'pi archive member content mismatch')
            seen[member.name] = True
    require(set(seen) == set(expected) and directories == expected_dirs,
            'pi archive inventory mismatch')
    return manifest


def verify_pi_runtime(runtime_root, runtime_files, manifest):
    actual = {entry['path']: entry for entry in runtime_files if entry['path'].startswith('pi/')}
    expected = {entry['path']: entry for entry in manifest['files']}
    require(set(actual) == set(expected), 'runtime pi inventory mismatch')
    for path, wanted in expected.items():
        info = (runtime_root / path).stat()
        got = actual[path]
        require(got['mode'] == wanted['mode'] and got['sha256'] == wanted['sha256'] and
                info.st_size == wanted['size'], 'runtime pi asset mismatch')


def inventory(root, kind):
    limits = {'source': (16 << 20, 128 << 20),
              'runtime': (128 << 20, 1 << 30), 'license': (16 << 20, 64 << 20)}
    file_limit, tree_limit = limits[kind]
    result, total = [], 0
    for directory, dirs, files in os.walk(root, followlinks=False):
        base = pathlib.Path(directory)
        if base == root and kind == 'source':
            git_entry = root / '.git'
            if '.git' in dirs and not git_entry.is_symlink():
                dirs.remove('.git')
            elif '.git' in files and stat.S_ISREG(git_entry.lstat().st_mode):
                files.remove('.git')
        for name in dirs + files:
            path = base / name
            relative = path.relative_to(root).as_posix()
            require('.git' not in path.relative_to(root).parts and '\\' not in relative and
                    not any(ord(c) < 32 or ord(c) == 127 for c in relative),
                    'input tree contains an unsupported path')
            info = path.lstat()
            require(not stat.S_ISLNK(info.st_mode), 'input tree contains a symlink')
            if stat.S_ISDIR(info.st_mode):
                continue
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                    stat.S_IMODE(info.st_mode) in (0o644, 0o755),
                    'input files must be single-link regular files with mode 0644 or 0755')
            total += info.st_size
            require(info.st_size <= file_limit and total <= tree_limit,
                    'input tree exceeds the release builder size limits')
            result.append(dict(path=relative, sha256=file_sha(path), mode=stat.S_IMODE(info.st_mode)))
    require(0 < len(result) <= 4096, 'input tree must contain 1 to 4096 files')
    return sorted(result, key=lambda item: item['path'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'runtime', 'license', 'control', 'version'):
        parser.add_argument(name)
    parser.add_argument('--pi-archive', required=True)
    args = parser.parse_args()
    require(VERSION.fullmatch(args.version), 'invalid release version')
    source, runtime, licenses = [clean_path(value) for value in (args.source, args.runtime, args.license)]
    pi_archive = clean_file(args.pi_archive)
    control = clean_path(args.control, existing=False)
    roots = [source, runtime, licenses, control]
    for index, root in enumerate(roots):
        for other in roots[index + 1:]:
            require(not root.is_relative_to(other) and not other.is_relative_to(root),
                    'source, runtime, license and control roots must be separate')
    require(all(not pi_archive.is_relative_to(root) for root in roots),
            'pi archive must be outside source, runtime, license and control roots')
    require(not control.exists(), 'control output already exists; use a new directory')
    parent = control.parent.stat()
    require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.getuid() and
            stat.S_IMODE(parent.st_mode) == 0o700, 'control parent must be an owned 0700 directory')

    paths = {}
    for name in ('go', 'git', 'node', 'npm'):
        found = shutil.which(name)
        require(found is not None, 'go, git, node and npm must be on PATH')
        paths[name] = pathlib.Path(found).resolve(strict=True)
        require(paths[name].is_file(), 'tool path must resolve to a regular file')
    env = dict(os.environ)
    env.update(GOTOOLCHAIN='local', GOWORK='off', GOENV='off', GOFLAGS='',
               GOOS='linux', GOARCH='amd64', CGO_ENABLED='0', GOPROXY='off',
               GOSUMDB='off', GOVCS='*:off', GIT_CONFIG_NOSYSTEM='1',
               GIT_CONFIG_GLOBAL='/dev/null', GIT_TERMINAL_PROMPT='0',
               GIT_OPTIONAL_LOCKS='0', GIT_NO_REPLACE_OBJECTS='1')
    for name in tuple(env):
        if name.startswith('GIT_') and name not in {
            'GIT_CONFIG_NOSYSTEM', 'GIT_CONFIG_GLOBAL', 'GIT_TERMINAL_PROMPT',
            'GIT_OPTIONAL_LOCKS', 'GIT_NO_REPLACE_OBJECTS',
        }:
            del env[name]

    def run(tool, *arguments, allowed=(0,)):
        result = subprocess.run([str(paths[tool]), *arguments], cwd=source, env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                text=True, timeout=120, check=False)
        require(result.returncode in allowed, 'local tool inspection failed; check tools, source and offline caches')
        return result.stdout.strip(), result.returncode

    def output(tool, *arguments):
        return run(tool, *arguments)[0]

    def git_identity():
        require(pathlib.Path(output('git', 'rev-parse', '--show-toplevel')) == source,
                'source must be the repository root')
        require(run('git', 'symbolic-ref', '-q', 'HEAD', allowed=(0, 1))[1] == 1,
                'source must have a detached HEAD')
        require(not output('git', 'status', '--porcelain=v1', '--untracked-files=all'),
                'source must be clean, including untracked files')
        require(output('git', 'remote') == 'origin', 'source must have exactly one remote named origin')
        origin = output('git', 'remote', 'get-url', '--all', 'origin').removesuffix('.git')
        push = output('git', 'remote', 'get-url', '--push', '--all', 'origin').removesuffix('.git')
        require(REPOSITORY.fullmatch(origin) and push == origin, 'origin must be one HTTPS GitHub repository')
        commit = output('git', 'rev-parse', 'HEAD^{commit}')
        require(re.fullmatch('[0-9a-f]{40}', commit), 'source must resolve to a full Git commit')
        return origin, commit

    origin, commit = git_identity()
    pi_manifest = verify_pi_archive(source, pi_archive)
    before = inventory(source, 'source')
    require(output('go', 'list', '-m') == MODULE, 'unexpected project Go module')
    raw = output('go', 'list', '-deps', '-f', '{{if .Module}}{{if .Module.Main}}{{.ImportPath}}{{end}}{{end}}',
                 *('./cmd/' + target for target in TARGETS))
    packages = sorted(set(raw.splitlines()) - {''})
    require(packages and all(p == MODULE or p.startswith(MODULE + '/') for p in packages),
            'Go package closure is not confined to the project module')
    policy = dict(schema_version=1, product='acornfox', module_path=MODULE,
                  go_packages=packages, files=before)
    go_version = output('go', 'env', 'GOVERSION')
    git_fields = output('git', '--version').split()
    require(len(git_fields) >= 3 and git_fields[:2] == ['git', 'version'], 'invalid Git version output')
    git_version = git_fields[2]
    node_version = output('node', '--version')
    # Hash and invoke the resolved npm JS entrypoint, matching acornfox-release.
    npm_version = output('node', str(paths['npm']), '--version')
    for value, pattern in ((go_version, r'go\d+\.\d+\.\d+'), (git_version, r'\d+\.\d+\.\d+'),
                           (node_version, r'v\d+\.\d+\.\d+'), (npm_version, r'\d+\.\d+\.\d+')):
        require(re.fullmatch(pattern, value), 'tool version is outside the release contract')
    toolchain = dict(schema_version=1, product='acornfox', architecture='amd64',
                    go_version=go_version, go_binary_sha256=file_sha(paths['go']),
                    git_version=git_version, git_binary_sha256=file_sha(paths['git']),
                    node_version=node_version, node_binary_sha256=file_sha(paths['node']),
                    npm_version=npm_version, npm_cli_sha256=file_sha(paths['npm']),
                    build_policy=['build_id_empty', 'build_vcs_disabled', 'cgo_disabled', 'trimpath'])
    runtime_input = dict(schema_version=1, product='acornfox', architecture='amd64', files=inventory(runtime, 'runtime'))
    verify_pi_runtime(runtime, runtime_input['files'], pi_manifest)
    license_input = dict(schema_version=1, product='acornfox', files=inventory(licenses, 'license'))
    require(before == inventory(source, 'source') and git_identity() == (origin, commit),
            'source changed during input inspection')
    inputs = {'source-policy': policy, 'toolchain': toolchain,
              'runtime-inputs': runtime_input, 'license-inputs': license_input}
    encoded = {name + '.json': canonical(value) for name, value in inputs.items()}
    decision = dict(schema_version=1, product='acornfox', architecture='amd64', migration='0038', layout=1,
                    version=args.version, release_id='release-' + args.version,
                    source_repository=origin, source_commit=commit,
                    source_policy_sha256=sha(encoded['source-policy.json']),
                    toolchain_sha256=sha(encoded['toolchain.json']),
                    runtime_input_sha256=sha(encoded['runtime-inputs.json']),
                    license_input_sha256=sha(encoded['license-inputs.json']))
    encoded['decision.json'] = canonical(decision)
    require(all(len(value) <= 1 << 20 for value in encoded.values()), 'control input exceeds the CLI size limit')
    encoded['decision.sha256'] = (sha(encoded['decision.json']) + '\n').encode()
    control.mkdir(mode=0o700)
    for name, data in encoded.items():
        descriptor = os.open(control / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    descriptor = os.open(control, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    print(f'Frozen {len(before)} source files, {len(packages)} Go packages, '
          f'{len(runtime_input["files"])} runtime files; source {commit}')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError, tarfile.TarError) as error:
        # Do not print command output, credentials, file contents or environment.
        print('prepare-release-inputs:', str(error) if isinstance(error, ValueError)
              else 'local input inspection or output write failed', file=sys.stderr)
        sys.exit(1)
