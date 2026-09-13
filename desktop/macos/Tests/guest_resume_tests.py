"""Runs the fixed guest dispatcher against task-private fake install effects.
Only root ownership and Linux renameat2 are adapted for the macOS test user.
The actual durable journal/classification/install/retry code is unchanged.
"""
import ast, importlib.util, json, os, pathlib, signal, subprocess, sys, tempfile, time, types, unittest
from unittest import mock
SOURCE=pathlib.Path(__file__).resolve().parents[1]/'Sources/GuestControlScript.swift'
class ResumeTests(unittest.TestCase):
    def test_sigkill_owned_install_resumes_without_reinstalling_complete(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=pathlib.Path(temporary)
            text=SOURCE.read_text(); script=text.split('#"""\n',1)[1].rsplit('\n"""#',1)[0]
            ast.parse(script); (root/'control.py').write_text(script)
            installer=root/'installer'
            installer.write_text('''#!/usr/bin/python3
import pathlib,time,sys
root=pathlib.Path(__file__).parent
count=root/'attempts'
n=int(count.read_text())+1 if count.exists() else 1
count.write_text(str(n))
print('private install attempt',n,flush=True)
if n==1:
    (root/'interrupted-ready').write_text('ready')
    time.sleep(60)
(root/'helper').write_text('installed')
'''); installer.chmod(0o755)
            runner=root/'runner.py'
            runner.write_text('''import importlib.util,json,os,pathlib,sys
root=pathlib.Path(__file__).parent
spec=importlib.util.spec_from_file_location('control',root/'control.py'); m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
m.ROOT=root; m.HELPER=root/'helper'
# Test host is macOS/user; production validates root files and uses renameat2.
m.regular=lambda *args: None
m.publish_directory=lambda source,target: os.rename(source,target)
m.stage=lambda config: (root,root/'helper',root/'installer')
m.verify_completed=lambda config: {'installed':True} if m.HELPER.exists() else m.fail()
config={'instance':'instance-a','bindingSHA256':'a'*64,'helperSHA256':'b'*64,'files':[]}
if len(sys.argv)>1: config['bindingSHA256']='c'*64
print(json.dumps(m.install(config)))
''')
            first=subprocess.Popen([sys.executable,str(runner)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
            try:
                until=time.monotonic()+10
                while not (root/'interrupted-ready').exists() and time.monotonic()<until: time.sleep(.02)
                self.assertTrue((root/'interrupted-ready').exists())
            finally:
                os.killpg(first.pid,signal.SIGKILL); first.communicate(timeout=5)
            self.assertTrue((root/'install-started').is_file())
            self.assertEqual((root/'install.log').stat().st_mode & 0o777,0o600)
            self.assertIn('private install attempt 1',(root/'install.log').read_text())
            mismatch=subprocess.run([sys.executable,str(runner),'mismatch'],capture_output=True)
            self.assertNotEqual(mismatch.returncode,0)
            self.assertEqual((root/'attempts').read_text(),'1')
            resumed=subprocess.run([sys.executable,str(runner)],capture_output=True,check=True)
            self.assertTrue(json.loads(resumed.stdout)['installed'])
            self.assertEqual((root/'attempts').read_text(),'2')
            self.assertTrue((root/'install-complete').is_file())
            subprocess.run([sys.executable,str(runner)],capture_output=True,check=True)
            self.assertEqual((root/'attempts').read_text(),'2')
            self.assertIn('private install attempt 2',(root/'install.log').read_text())
    def test_fixed_authenticated_shutdown_verb(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=pathlib.Path(temporary)
            text=SOURCE.read_text(); script=text.split('#"""\n',1)[1].rsplit('\n"""#',1)[0]
            path=root/'control.py'; path.write_text(script)
            spec=importlib.util.spec_from_file_location('shutdown_control',path); module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
            module.ROOT=root; module.CONFIG=root/'config.json'
            module.CONFIG.write_text(json.dumps({'instance':'owned-test'}))
            owner=root/'owner-marker'; owner.write_text(json.dumps({'product':'acornfox','instance':'owned-test'}))
            with mock.patch.object(module.os,'geteuid',return_value=0), mock.patch.object(module,'regular'), mock.patch.object(module,'directory'), mock.patch.object(module.fcntl,'flock'), mock.patch.object(module.subprocess,'run',return_value=types.SimpleNamespace(returncode=0)) as run:
                with mock.patch.object(sys,'argv',['control','shutdown']):
                    self.assertEqual(module.main(),{'shutdown_requested':True,'instance':'owned-test'})
                self.assertEqual(run.call_args.args[0],['/usr/bin/systemctl','--no-block','poweroff'])
                self.assertEqual(run.call_count,1)
                for args in [['shutdown','--force'],['shutdown','reboot'],['shutdown','/bin/sh']]:
                    run.reset_mock()
                    with mock.patch.object(sys,'argv',['control']+args), self.assertRaises(RuntimeError): module.main()
                    run.assert_not_called()
                owner.write_text(json.dumps({'product':'acornfox','instance':'foreign'})); run.reset_mock()
                with mock.patch.object(sys,'argv',['control','shutdown']), self.assertRaises(RuntimeError): module.main()
                run.assert_not_called()
                owner.write_text(json.dumps({'product':'acornfox','instance':'owned-test'})); run.return_value=types.SimpleNamespace(returncode=1)
                with mock.patch.object(sys,'argv',['control','shutdown']), self.assertRaises(RuntimeError): module.main()
    def test_identity_and_verify_current_never_create_missing_lock(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=pathlib.Path(temporary)
            script=SOURCE.read_text().split('#"""\n',1)[1].rsplit('\n"""#',1)[0]
            path=root/'control.py'; path.write_text(script)
            spec=importlib.util.spec_from_file_location('readonly_control',path); module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
            module.ROOT=root; module.CONFIG=root/'config.json'
            module.CONFIG.write_text(json.dumps({'instance':'owned-test','instanceProtocol':1}))
            owner={'product':'acornfox','instance':'owned-test'}; (root/'owner-marker').write_text(json.dumps(owner))
            with mock.patch.object(module.os,'geteuid',return_value=0), mock.patch.object(module,'regular'), mock.patch.object(module,'directory'), mock.patch.object(module,'verify_current') as verify:
                with mock.patch.object(sys,'argv',['control','identity']): self.assertEqual(module.main(),owner)
                self.assertFalse((root/'control.lock').exists())
                with mock.patch.object(sys,'argv',['control','verify-current']), self.assertRaises(FileNotFoundError): module.main()
                verify.assert_not_called(); self.assertFalse((root/'control.lock').exists())
                with mock.patch.object(sys,'argv',['control','verify-current','any-binding']), self.assertRaises(RuntimeError): module.main()
                self.assertFalse((root/'control.lock').exists())

if __name__=='__main__': unittest.main()
