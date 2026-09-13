import hashlib, io, json, pathlib, subprocess, sys, tarfile, tempfile, unittest
SCRIPT = pathlib.Path(__file__).resolve().parents[1] / 'generate-manifest.py'
class ManifestTests(unittest.TestCase):
    def test_generated_exact_assets_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary); candidate = root/'candidate'; candidate.mkdir()
            (root/'base.raw.gz').write_bytes(b'base'); (root/'acornfox-guest-bridge').write_bytes(b'bridge')
            (candidate/'candidate-binding.json').write_text('{}')
            binding = hashlib.sha256(b'{}').hexdigest()
            (candidate/'candidate-binding.sha256').write_text(binding+'  candidate-binding.json\n')
            for name in ['build-record.json','release-manifest.json','bundle-manifest.sha256']:
                (candidate/name).write_text('{}')
            elf = bytearray(32); elf[:6] = b'\x7fELF\x02\x01'; elf[18] = 0xb7
            with tarfile.open(candidate/'candidate.tar.gz','w:gz') as archive:
                member = tarfile.TarInfo('release/bin/acornfox-upgrade'); member.size = len(elf); member.mode = 0o755; archive.addfile(member,io.BytesIO(elf))
            args = [sys.executable,str(SCRIPT),str(root),'a'*64,'1024',binding]
            subprocess.run(args,check=True)
            first = (root/'resource-manifest.json').read_bytes(); manifest = json.loads(first)
            self.assertEqual(len(manifest['files']),8)
            self.assertEqual(manifest['bootstrapHelperSHA256'],hashlib.sha256(elf).hexdigest())
            self.assertNotEqual(subprocess.run(args,stderr=subprocess.DEVNULL).returncode,0)
            self.assertEqual((root/'resource-manifest.json').read_bytes(),first)
    def test_extra_candidate_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary); (root/'candidate').mkdir(); (root/'candidate/unknown').write_text('foreign')
            result = subprocess.run([sys.executable,str(SCRIPT),str(root),'a'*64,'1','b'*64],stderr=subprocess.DEVNULL)
            self.assertNotEqual(result.returncode,0)
            self.assertFalse((root/'resource-manifest.json').exists())
if __name__ == '__main__': unittest.main()
