#!/usr/bin/env python3
"""Build-time manifest from the exact copied package, never a hand-written input."""
import hashlib, json, pathlib, re, stat, sys, tarfile
root = pathlib.Path(sys.argv[1])
raw_sha, raw_bytes, binding_sha = sys.argv[2:5]
def digest_file(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size <= 0:
        raise ValueError('non-regular package input')
    h = hashlib.sha256()
    with path.open('rb') as file:
        while chunk := file.read(1048576): h.update(chunk)
    return h.hexdigest()
metadata = {'candidate-binding.json','candidate-binding.sha256','bundle-manifest.sha256','build-record.json','release-manifest.json'}
candidate = root/'candidate'
names = {p.name for p in candidate.iterdir()}
archives = names - metadata
if len(names) != 6 or len(archives) != 1 or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*\.tar\.gz', next(iter(archives))):
    raise ValueError('candidate requires five metadata files and one archive')
paths = ['base.raw.gz','acornfox-guest-bridge'] + ['candidate/'+name for name in sorted(names)]
files = [{'path':p,'sha256':digest_file(root/p),'size':(root/p).stat().st_size} for p in paths]
if digest_file(candidate/'candidate-binding.json') != binding_sha:
    raise ValueError('candidate binding digest mismatch')
if (candidate/'candidate-binding.sha256').read_text().split()[0] != binding_sha:
    raise ValueError('candidate binding receipt mismatch')
with tarfile.open(candidate/next(iter(archives)), 'r:gz') as archive:
    matching = [m for m in archive.getmembers() if m.name == 'release/bin/acornfox-upgrade']
    if len(matching) != 1 or not matching[0].isfile(): raise ValueError('missing bootstrap helper')
    h = hashlib.sha256()
    with archive.extractfile(matching[0]) as file:
        header = file.read(20)
        if len(header) != 20 or header[:6] != b'\x7fELF\x02\x01' or header[18:20] != b'\xb7\x00': raise ValueError('bootstrap helper must be Linux ARM64')
        h.update(header)
        while chunk := file.read(1048576): h.update(chunk)
    helper_sha = h.hexdigest()
manifest = {'baseRawSHA256':raw_sha,'baseRawBytes':int(raw_bytes),'candidateBindingSHA256':binding_sha,'bootstrapHelperSHA256':helper_sha,'files':files}
path = root/'resource-manifest.json'
with path.open('x') as file: json.dump(manifest, file, sort_keys=True, indent=2); file.write('\n')
