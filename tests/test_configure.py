import tempfile,subprocess,sys,shutil,unittest,stat
from pathlib import Path
SCRIPT=Path(__file__).resolve().parents[1]/'scripts/configure.py'
class ConfigureTests(unittest.TestCase):
 def test_private_unique_config_and_no_overwrite(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);(root/'scripts').mkdir();p=root/'scripts/configure.py';shutil.copy2(SCRIPT,p)
   result=subprocess.run([sys.executable,str(p),'--url','https://rmm.example.com'],capture_output=True,text=True)
   self.assertEqual(result.returncode,0);env=root/'.env';self.assertEqual(stat.S_IMODE(env.stat().st_mode),0o600)
   values=dict(l.split('=',1) for l in env.read_text().splitlines());self.assertGreaterEqual(len(values['ADMIN_PASSWORD']),16)
   for k in ['ADMIN_PASSWORD','AGENT_SECRET','JWT_SECRET']:self.assertNotIn(values[k],result.stdout)
   self.assertNotEqual(values['AGENT_SECRET'],values['JWT_SECRET'])
   self.assertNotEqual(subprocess.run([sys.executable,str(p),'--url','https://rmm.example.com'],capture_output=True).returncode,0)
 def test_insecure_origin_rejected(self):
  self.assertNotEqual(subprocess.run([sys.executable,str(SCRIPT),'--url','http://rmm.example.com'],capture_output=True).returncode,0)
if __name__=='__main__':unittest.main()
