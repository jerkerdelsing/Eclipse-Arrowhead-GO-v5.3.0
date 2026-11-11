from pathlib import Path
import subprocess,json,os
r=Path(__file__).resolve().parents[1];docker=os.environ.get('DOCKER','docker');results=[]
for name in ['Authentication','Blacklist','ServiceRegistry','LocalCloudManager']:
 m=next(m for m in json.loads((r/'systems.json').read_text())if m['name']==name);image='eclipse-arrowhead-go-reorg/'+name.lower()+':20261028'
 with (r/'verification'/(name+'-image-build.log')).open('w')as f:v=subprocess.run([docker,'build','--pull=false','-t',image,'.'],cwd=r/m['path'],stdout=f,stderr=subprocess.STDOUT)
 if v.returncode!=0:print(name+': image FAIL',flush=True);raise SystemExit(v.returncode)
 v=subprocess.run([docker,'run','--rm','--network','none','--read-only',image,'-h'],capture_output=True,text=True)
 (r/'verification'/(name+'-image-help.log')).write_text(v.stdout+v.stderr)
 assert v.returncode==0,(name,v.stderr)
 results.append({'name':name,'image':image,'sourceBuild':True,'isolatedHelp':True});print(name+': source-only Docker build and isolated help PASS',flush=True)
(r/'verification/image-results.json').write_text(json.dumps(results,indent=2)+'\n')
