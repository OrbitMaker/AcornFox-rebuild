"""Cross-language argv check against the actual CLI, plus an observed guest receipt."""
import ast
import copy
import importlib.util
import json
import os
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[3]
SWIFT = ROOT/'desktop/macos/Sources/GuestControlScript.swift'
GOLDEN = pathlib.Path(__file__).parent/'fixtures/debian16-recover-finalize.json'

def control_source():
    return SWIFT.read_text().split('#"""\n',1)[1].rsplit('\n"""#',1)[0]

def actual_verify_arguments():
    parsed = ast.parse(control_source())
    method = next(n for n in parsed.body if isinstance(n, ast.FunctionDef) and n.name == 'verify_current')
    values = []
    for node in ast.walk(method):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'command' and node.args and isinstance(node.args[0], ast.List):
            constants = [ast.literal_eval(value) for value in node.args[0].elts[1:]]
            if constants and constants[0].startswith('recover-'): raise AssertionError('launch verification must not call recovery')
            if constants and constants[0] == 'verify-prepared': values.append(constants)
    if len(values) != 1: raise AssertionError('must have one concrete read-only verification command')
    return values[0]

class HelperContractTests(unittest.TestCase):
    @unittest.skipIf(os.geteuid() == 0, 'must remain unprivileged; never invoke the host production state verifier')
    def test_actual_seed_argv_passes_real_helper_parser(self):
        arguments = actual_verify_arguments()
        self.assertEqual(arguments, ['verify-prepared'])
        with tempfile.TemporaryDirectory() as temporary:
            binary = pathlib.Path(temporary)/'acornfox-upgrade'
            flags = '-X main.processIdentity=acornfox -X main.buildVersion=1.2.3-test.1 -X main.buildSourceCommit=0123456789abcdef0123456789abcdef01234567 -X main.buildLayoutSchema=1'
            subprocess.run(['go','build','-buildvcs=false','-trimpath','-ldflags',flags,'-o',str(binary),'./cmd/open-card-upgrade'],cwd=ROOT,check=True)
            # Correct argv reaches the real privilege gate. It cannot reach a
            # production host operation because this process is not root.
            result = subprocess.run([str(binary)]+arguments,capture_output=True,check=False)
            self.assertNotEqual(result.returncode,0)
            self.assertEqual(json.loads(result.stdout)['code'],'root_ineligible')
            self.assertEqual(result.stderr,b'')
            for bad in [['verify-prepared','--pending'],['verify-prepared','extra']]:
                result = subprocess.run([str(binary)]+bad,capture_output=True,check=False)
                self.assertNotEqual(result.returncode,0)
                self.assertEqual(json.loads(result.stdout)['code'],'invalid_arguments')
                self.assertEqual(result.stderr,b'')

    def test_actual_cli_dispatch_never_enters_recovery(self):
        # Exercises the real runWithDependencies dispatcher, including upgrade
        # UPGRADED/ROLLED_BACK/nonterminal/error alternatives and every gate.
        self.assertEqual(actual_verify_arguments(), ['verify-prepared'])
        subprocess.run(['go','test','./cmd/open-card-upgrade','-run','^TestAcornFoxVerifyPrepared','-count=1'],cwd=ROOT,check=True)

    def test_observed_debian_payload_matches_verify_prepared_shape(self):
        golden = json.loads(GOLDEN.read_text()); receipt = golden['receipt']
        self.assertEqual(set(receipt), {'schema_version','state','binding_sha256','release_id','source_commit','layout_sha256','substrate_receipt_sha256','final_evidence_sha256'})
        self.assertEqual(receipt['schema_version'],1)
        self.assertEqual(receipt['state'],'REPO_PREPARED')
        with tempfile.TemporaryDirectory() as temporary:
            source = pathlib.Path(temporary)/'control.py'; source.write_text(control_source())
            spec = importlib.util.spec_from_file_location('observed_control',source)
            module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
            helper_sha = 'a'*64
            config = {'instance':'00000000-0000-0000-0000-000000000001','instanceProtocol':1,'helperSHA256':helper_sha,'bindingSHA256':receipt['binding_sha256']}
            module.regular = lambda *args: None
            module.digest = lambda *args: helper_sha
            module.jsonfile = lambda *args: {'schema_version':1,'state':'RUNTIME_CONFIGURED','binding_sha256':receipt['binding_sha256'],'release_id':receipt['release_id'],'source_commit':receipt['source_commit'],'intent_sha256':'b'*64}
            calls=[]
            # Only the observed receipt payload is reused. This envelope is the
            # new CLI contract, not a claimed observation of verify-prepared.
            response = {'command':'verify-prepared','ok':True,'receipt':copy.deepcopy(receipt)}
            def command(argv):
                calls.append(argv[1:])
                if argv[1:] == ['contract-check','--product','acornfox','--layout-schema','1']:
                    return {'schema_version':1,'ok':True,'code':'ok','binding_sha256':receipt['binding_sha256'],'executable_sha256':helper_sha,'substrate_receipt_sha256':receipt['substrate_receipt_sha256'],'identity':{'product':'acornfox','role':'upgrade','layout_version':1,'release_id':receipt['release_id'],'source_commit':receipt['source_commit']}}
                if argv[1:] == ['verify-prepared']: return response
                raise AssertionError('unexpected helper argv: '+repr(argv))
            module.command = command
            self.assertEqual(module.verify_completed(config),{'installed':True,'release':receipt['release_id']})
            self.assertEqual(calls,[['contract-check','--product','acornfox','--layout-schema','1'],['verify-prepared']])
            for field, value in [('binding_sha256','f'*64),('state','RECOVERY_PREPARED'),('final_evidence_sha256','bad')]:
                response = {'command':'verify-prepared','ok':True,'receipt':copy.deepcopy(receipt)}; response['receipt'][field]=value
                with self.assertRaises(RuntimeError): module.verify_completed(config)

    def test_verify_current_uses_current_chain_not_historical_bootstrap(self):
        golden=json.loads(GOLDEN.read_text()); receipt=golden['receipt']
        with tempfile.TemporaryDirectory() as temporary:
            source=pathlib.Path(temporary)/'control.py'; source.write_text(control_source())
            spec=importlib.util.spec_from_file_location('current_control',source); module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
            initial={'instance':'00000000-0000-0000-0000-000000000001','instanceProtocol':1,'bindingSHA256':'a'*64,'helperSHA256':'b'*64}
            saved=copy.deepcopy(initial); helper='f'*64; calls=[]
            module.regular=lambda *args: None
            module.digest=lambda *args: helper
            runtime={'schema_version':1,'state':'RUNTIME_CONFIGURED','binding_sha256':receipt['binding_sha256'],'release_id':receipt['release_id'],'source_commit':receipt['source_commit'],'intent_sha256':'c'*64}
            module.jsonfile=lambda *args: runtime
            def command(args):
                calls.append(args[1:])
                if args[1:]==['contract-check','--product','acornfox','--layout-schema','1']:
                    return {'schema_version':1,'ok':True,'code':'ok','binding_sha256':receipt['binding_sha256'],'executable_sha256':helper,'substrate_receipt_sha256':receipt['substrate_receipt_sha256'],'identity':{'product':'acornfox','role':'upgrade','layout_version':1,'release_id':receipt['release_id'],'source_commit':receipt['source_commit']}}
                if args[1:]==['verify-prepared']:
                    return {'command':'verify-prepared','ok':True,'receipt':receipt}
                raise AssertionError('read-only verification issued another operation')
            module.command=command
            current=module.verify_current(initial)
            self.assertEqual(current['binding'],receipt['binding_sha256']); self.assertEqual(current['helperSHA256'],helper)
            self.assertEqual(initial,saved)
            self.assertEqual(calls,[['contract-check','--product','acornfox','--layout-schema','1'],['verify-prepared']])
            with self.assertRaises(RuntimeError): module.verify_completed(initial)
            runtime['binding_sha256']='d'*64
            with self.assertRaises(RuntimeError): module.verify_current(initial)

if __name__ == '__main__': unittest.main()
