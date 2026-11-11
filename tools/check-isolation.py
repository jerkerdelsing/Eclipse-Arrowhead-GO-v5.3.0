from pathlib import Path
import shutil,subprocess,tempfile,json,os
root=Path(__file__).resolve().parents[1];env={**os.environ,'GOWORK':'off','GOPROXY':'off','GOMAXPROCS':'2'};results=[]
selected=['Authentication','Blacklist','ServiceRegistry','LocalCloudManager'];mods=json.loads((root/'systems.json').read_text())
for name in selected:
 m=next(m for m in mods if m['name']==name)
 with tempfile.TemporaryDirectory(prefix='standalone-go-')as raw:
  folder=Path(raw)/'system';shutil.copytree(root/m['path'],folder,ignore=shutil.ignore_patterns('bin','.env','state','certs','secrets'))
  log=root/'verification'/(name+'-isolated-build.log')
  with log.open('w')as f:v=subprocess.run([os.environ.get('GO','go'),'build','-p','2','-trimpath','-o',str(folder/'executable'),m['entry']],cwd=folder,env=env,stdout=f,stderr=subprocess.STDOUT)
  assert v.returncode==0,(name,log)
  helpcheck=subprocess.run([str(folder/'executable'),'-h'],cwd=folder,env=env,capture_output=True,text=True);assert helpcheck.returncode==0,(name,helpcheck.stderr)
  print(name+': isolated external-directory build and help PASS',flush=True);results.append({'name':name,'isolatedBuild':True,'help':True})
  if name=='Authentication':
   (folder/'bin').mkdir();shutil.copy2(root/'ah5-core-go/serviceregistry/bin/ServiceRegistry',folder/'bin/serviceregistry')
   with (root/'verification/native-registry-integration.log').open('w')as f:v=subprocess.run([os.environ.get('GO','go'),'test','-p','2','-race','-count=1','-run','^TestNativeServiceRegistryIntegration$','-v','./internal/core'],cwd=folder,env=env,stdout=f,stderr=subprocess.STDOUT)
   results[-1]['nativeRegistryIntegration']=v.returncode==0
   print('Optional native registry integration: '+('PASS' if v.returncode==0 else 'registration compatibility failure; see log'),flush=True)
(root/'verification/isolation-results.json').write_text(json.dumps(results,indent=2)+'\n')
# Every support executable must reject the generic launcher switch.
for m in mods:
 if m['kind']=='core' or m['name']=='LocalCloudManager':continue
 v=subprocess.run([str(root/m['path']/'bin'/m['name']),'-system','OtherSystem'],env=env,capture_output=True,text=True)
 assert v.returncode!=0 and 'flag provided but not defined' in v.stderr,m['name']
print('All 16 dedicated support/test launchers reject role switching',flush=True)

if any(x.get('nativeRegistryIntegration') is False for x in results):
 raise SystemExit(1)
