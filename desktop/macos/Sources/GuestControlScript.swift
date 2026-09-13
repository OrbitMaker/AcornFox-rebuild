import Foundation

// Embedded into cloud-init; no extra mutable package resource or shell command API.
enum GuestControlScript {
    static let source = #"""
#!/usr/bin/python3
import ctypes, fcntl, hashlib, json, os, pathlib, re, stat, subprocess, sys, tarfile, tempfile
ROOT = pathlib.Path('/var/lib/acornfox-desktop')
HELPER = pathlib.Path('/opt/acornfox/upgrade-tools/acornfox-upgrade')
RUNTIME = pathlib.Path('/var/lib/acornfox/install/runtime-config.json')
CONFIG = pathlib.Path('/etc/acornfox-desktop.json')

def fail():
    raise RuntimeError('local instance validation failed')

def directory(path, create=False):
    if create:
        try: path.mkdir(mode=0o700)
        except FileExistsError: pass
    s = path.lstat()
    if not stat.S_ISDIR(s.st_mode) or s.st_uid != 0 or s.st_gid != 0 or s.st_mode & 0o022: fail()
    return path

def regular(path, mode=None):
    for parent in reversed(path.parents): directory(parent)
    s = path.lstat()
    if not stat.S_ISREG(s.st_mode) or s.st_uid != 0 or s.st_gid != 0 or s.st_nlink != 1 or s.st_mode & 0o022: fail()
    if mode is not None and stat.S_IMODE(s.st_mode) != mode: fail()
    return s

def digest(path):
    regular(path)
    h = hashlib.sha256()
    with path.open('rb') as f:
        while data := f.read(1048576): h.update(data)
    return h.hexdigest()

def jsonfile(path, mode=0o600):
    regular(path, mode)
    if path.stat().st_size > 65536: fail()
    return json.loads(path.read_text())

def syncdir(path):
    fd = os.open(path, os.O_DIRECTORY | os.O_RDONLY | os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)

def exclusive(path, data):
    fd, name = tempfile.mkstemp(prefix='.record-',dir=path.parent)
    temporary = pathlib.Path(name)
    with os.fdopen(fd, 'wb') as f: f.write(data); f.flush(); os.fsync(f.fileno())
    publish_directory(temporary,path)

def command(argv):
    result = subprocess.run(argv, env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C','LC_ALL':'C'}, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=120)
    if result.returncode or len(result.stdout) > 65536: fail()
    return json.loads(result.stdout)

def hex64(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None

def verify_current(config):
    regular(HELPER, 0o755)
    current_sha=digest(HELPER)
    c=command([str(HELPER),'contract-check','--product','acornfox','--layout-schema','1'])
    identity=c.get('identity',{})
    binding=c.get('binding_sha256')
    if not (c.get('schema_version') == 1 and c.get('ok') is True and c.get('code') == 'ok' and hex64(binding) and c.get('executable_sha256') == current_sha and hex64(c.get('substrate_receipt_sha256')) and identity.get('product') == 'acornfox' and identity.get('role') == 'upgrade' and identity.get('layout_version') == 1): fail()
    r=jsonfile(RUNTIME)
    if not (r.get('schema_version') == 1 and r.get('state') == 'RUNTIME_CONFIGURED' and r.get('binding_sha256') == binding and r.get('release_id') == identity.get('release_id') and r.get('source_commit') == identity.get('source_commit') and hex64(r.get('intent_sha256'))): fail()
    p=command([str(HELPER),'verify-prepared']); receipt=p.get('receipt',{})
    if not (p.get('ok') is True and p.get('command') == 'verify-prepared' and receipt.get('schema_version') == 1 and receipt.get('state') == 'REPO_PREPARED' and receipt.get('binding_sha256') == binding and receipt.get('release_id') == identity.get('release_id') and receipt.get('source_commit') == identity.get('source_commit') and hex64(receipt.get('final_evidence_sha256'))): fail()
    if config.get('instanceProtocol') != 1: fail()
    return {'schema':1,'instance':config['instance'],'instanceProtocol':1,'binding':binding,'helperSHA256':current_sha,'release':identity['release_id'],'sourceCommit':identity['source_commit'],'finalEvidenceSHA256':receipt['final_evidence_sha256']}

def verify_completed(config):
    current=verify_current(config)
    if current['binding'] != config['bindingSHA256'] or current['helperSHA256'] != config['helperSHA256']: fail()
    return {'installed':True,'release':current['release']}

def install_identity(config, state):
    return {'version':1,'state':state,'instance':config['instance'],'bindingSHA256':config['bindingSHA256'],'helperSHA256':config['helperSHA256'],'files':config['files']}

def owned_record(config, name, state):
    path=ROOT/name
    if not os.path.lexists(path): return False
    if jsonfile(path) != install_identity(config,state): fail()
    return True

def verify(config):
    started=owned_record(config,'install-started','installing')
    complete=owned_record(config,'install-complete','complete')
    if os.path.lexists(HELPER):
        try: return verify_completed(config)
        except Exception:
            if started and not complete: return {'installed':False,'resume':True}
            raise
    if complete: fail()
    if started: return {'installed':False,'resume':True}
    if any(os.path.lexists(p) for p in [pathlib.Path('/opt/acornfox'),pathlib.Path('/var/lib/acornfox/install')]): fail()
    if os.path.lexists(ROOT/'unpacked') and not os.path.lexists(ROOT/'unpacked-owner.json'): fail()
    return {'installed':False,'resume':False}

def publish_directory(source, target):
    libc=ctypes.CDLL(None,use_errno=True)
    if libc.renameat2(-100,ctypes.c_char_p(os.fsencode(source)),-100,ctypes.c_char_p(os.fsencode(target)),1) != 0:
        raise OSError(ctypes.get_errno(),'exclusive directory publication failed')
    syncdir(target.parent)


def candidate(config):
    return {entry['path'].split('/')[-1]:entry for entry in config['files']}

def upload(config, name):
    allowed = candidate(config)
    if name not in allowed: fail()
    expected = allowed[name]
    root = directory(ROOT/'candidate', create=True)
    fd, temporary = tempfile.mkstemp(prefix='.upload-', dir=root)
    path = pathlib.Path(temporary); h = hashlib.sha256(); size = 0
    try:
        with os.fdopen(fd, 'wb') as f:
            while data := sys.stdin.buffer.read(1048576):
                size += len(data)
                if size > expected['size']: fail()
                h.update(data); f.write(data)
            f.flush(); os.fsync(f.fileno())
        if size != expected['size'] or h.hexdigest() != expected['sha256']: fail()
        target = root/name
        if target.exists() or target.is_symlink():
            regular(target, 0o644)
            if target.stat().st_size != size or digest(target) != expected['sha256']: fail()
        else:
            os.chmod(path, 0o644)
            with path.open('rb') as f: os.fsync(f.fileno())
            publish_directory(path,target)
        return {'uploaded':name}
    finally:
        if path.exists(): path.unlink()

def stage(config):
    root = directory(ROOT/'candidate')
    for name, entry in candidate(config).items():
        regular(root/name, 0o644)
        if (root/name).stat().st_size != entry['size'] or digest(root/name) != entry['sha256']: fail()
    archive = root/config['archiveName']
    unpacked = ROOT/'unpacked'
    expected_archive = candidate(config)[config['archiveName']]['sha256']
    owner_path=ROOT/'unpacked-owner.json'
    saved=jsonfile(owner_path) if os.path.lexists(owner_path) else None
    if saved is not None:
        if saved.get('instance') != config['instance'] or saved.get('archiveSHA256') != expected_archive or not re.fullmatch(r'\.unpack-[A-Za-z0-9_]+',saved.get('temporary','')): fail()
        temporary=ROOT/saved['temporary']
        source=unpacked if os.path.lexists(unpacked) else temporary
        directory(source); info=source.lstat()
        if info.st_dev != saved['device'] or info.st_ino != saved['inode']: fail()
    else:
        if os.path.lexists(unpacked): fail()
        temporary=pathlib.Path(tempfile.mkdtemp(prefix='.unpack-',dir=ROOT)); source=temporary
    with tarfile.open(archive,'r:gz') as tar:
        members=tar.getmembers(); total=0; expected_paths=set()
        for member in members:
            path=pathlib.PurePosixPath(member.name)
            if path.is_absolute() or '..' in path.parts or not path.parts or path.parts[0] != 'release' or not (member.isfile() or member.isdir()) or member.mode & 0o022: fail()
            total+=member.size
            if total > 8*1024**3: fail()
            expected_paths.add(str(path))
            expected_paths.update(str(p) for p in path.parents if str(p) != '.')
        if saved is None: tar.extractall(source,members=members,filter='data')
        if {str(p.relative_to(source)) for p in source.rglob('*')} != expected_paths: fail()
        for member in members:
            path=source/member.name
            if member.isdir(): directory(path); continue
            regular(path)
            if path.stat().st_size != member.size: fail()
            h=hashlib.sha256()
            with tar.extractfile(member) as f:
                while data:=f.read(1048576): h.update(data)
            if digest(path) != h.hexdigest(): fail()
            with path.open('rb') as f: os.fsync(f.fileno())
        for path in sorted((p for p in source.rglob('*') if p.is_dir()),key=lambda p:len(p.parts),reverse=True): syncdir(path)
        syncdir(source)
    if saved is None:
        info=source.lstat()
        exclusive(owner_path,json.dumps({'instance':config['instance'],'archiveSHA256':expected_archive,'temporary':source.name,'device':info.st_dev,'inode':info.st_ino}).encode())
    if source != unpacked: publish_directory(source,unpacked)
    helper=unpacked/'release/bin/acornfox-upgrade'; installer=unpacked/'release/scripts/acornfox/install-host.sh'
    regular(helper,0o755); regular(installer,0o755)
    if digest(helper) != config['helperSHA256']: fail()
    return root,helper,installer

def install(config):
    if verify(config)['installed']: return verify_completed(config)
    root,helper,installer=stage(config)
    if not owned_record(config,'install-started','installing'):
        exclusive(ROOT/'install-started',json.dumps(install_identity(config,'installing')).encode())
    logfile=ROOT/'install.log'
    if not os.path.lexists(logfile): exclusive(logfile,b'')
    regular(logfile,0o600)
    env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C','LC_ALL':'C','DEBIAN_FRONTEND':'noninteractive','ACORNFOX_INSTALL_CONFIRMATION':'ACORNFOX-INSTALL','ACORNFOX_DEDICATED_HOST_CONFIRMATION':'ACORNFOX-DEDICATED-HOST','ACORNFOX_CONSOLE_ACCESS':'local_loopback'}
    with logfile.open('ab') as log:
        log.write(b'\nAcornFox owned installation attempt\n'); log.flush()
        result=subprocess.run([str(installer),'--candidate-dir',str(root),'--binding-sha256',config['bindingSHA256'],'--bootstrap-helper',str(helper),'--bootstrap-helper-sha256',config['helperSHA256']],env=env,stdout=log,stderr=log,timeout=1800)
        log.flush(); os.fsync(log.fileno())
    if result.returncode: fail()
    # Once install-host reports success, subsequent validation failures must not
    # cause a reinstallation that could reset user configuration or optional PI.
    if not owned_record(config,'install-complete','complete'):
        exclusive(ROOT/'install-complete',json.dumps(install_identity(config,'complete')).encode())
    return verify_completed(config)

def main():
    if os.geteuid() != 0: fail()
    args=sys.argv[1:]
    if args not in [['identity'],['verify'],['verify-current'],['install'],['shutdown'],['install-log'],['setup-code']] and not (len(args)==2 and args[0]=='upload'): fail()
    config = jsonfile(CONFIG)
    directory(ROOT)
    owner = jsonfile(ROOT/'owner-marker')
    if owner != {'product':'acornfox','instance':config['instance']}: fail()
    if args == ['identity']: return owner
    lockpath = ROOT/'control.lock'
    read_only=args in [['verify-current'],['install-log'],['setup-code']]
    flags=(os.O_RDONLY if read_only else os.O_RDWR | os.O_CREAT) | os.O_NOFOLLOW
    lockfd = os.open(lockpath, flags, 0o600)
    regular(lockpath, 0o600)
    fcntl.flock(lockfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    if args == ['shutdown']:
        result=subprocess.run(['/usr/bin/systemctl','--no-block','poweroff'],env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C','LC_ALL':'C'},stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
        if result.returncode: fail()
        return {'shutdown_requested':True,'instance':config['instance']}
    if args == ['verify']: return verify(config)
    if args == ['verify-current']: return verify_current(config)
    if len(args) == 2 and args[0] == 'upload': return upload(config,args[1])
    if args == ['install']: return install(config)
    if args == ['install-log']:
        path=ROOT/'install.log'; regular(path,0o600)
        with path.open('rb') as log:
            log.seek(max(0,path.stat().st_size-65536)); sys.stdout.buffer.write(log.read(65536))
        return None
    if args == ['setup-code']:
        path = pathlib.Path('/etc/acornfox/credentials/setup-token'); regular(path, 0o600)
        data = path.read_bytes().strip()
        if not re.fullmatch(b'[A-Za-z0-9_-]{16,256}', data): fail()
        sys.stdout.buffer.write(data); return None
    fail()

if __name__ == '__main__':
    try:
        result = main()
        if result is not None: print(json.dumps(result, separators=(',',':')))
    except Exception:
        print('AcornFox local operation failed; existing instance was preserved.', file=sys.stderr)
        sys.exit(23)
"""#
}
