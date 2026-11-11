#!/usr/bin/env python3
"""Check every standalone module with workspace resolution disabled."""
from pathlib import Path
import argparse,concurrent.futures,json,os,subprocess,time
root=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser();p.add_argument('action',choices=['build','test','vet']);p.add_argument('--go',default='go');p.add_argument('--jobs',type=int,default=2);a=p.parse_args()
modules=json.loads((root/'systems.json').read_text());logs=root/'verification';logs.mkdir(exist_ok=True)
env={**os.environ,'GOWORK':'off','GOPROXY':'off','GOMAXPROCS':'2'}
def run(m):
 folder=root/m['path'];start=time.time()
 if a.action=='build':
  (folder/'bin').mkdir(exist_ok=True);cmd=[a.go,'build','-p','2','-trimpath','-o',str(folder/'bin'/m['name']),m['entry']]
 elif a.action=='test':cmd=[a.go,'test','-p','2','-race','-json','./...']
 else:cmd=[a.go,'vet','-p','2','./...']
 path=logs/(m['name']+'-'+a.action+'.log')
 with path.open('w') as f:result=subprocess.run(cmd,cwd=folder,env=env,stdout=f,stderr=subprocess.STDOUT)
 item={'name':m['name'],'path':m['path'],'action':a.action,'exitCode':result.returncode,'seconds':round(time.time()-start,2),'log':str(path.relative_to(root))}
 if a.action=='test':
  events=[]
  for line in path.read_text().splitlines():
   try:events.append(json.loads(line))
   except ValueError:pass
  item['testsPassed']=sum(e.get('Action')=='pass' and 'Test'in e for e in events);item['testsFailed']=sum(e.get('Action')=='fail' and 'Test'in e for e in events)
 print(m['name']+': '+a.action+' '+('PASS'if result.returncode==0 else'FAIL'),flush=True);return item
with concurrent.futures.ThreadPoolExecutor(max_workers=max(1,min(a.jobs,4))) as pool:results=list(pool.map(run,modules))
(logs/(a.action+'-results.json')).write_text(json.dumps(results,indent=2)+'\n')
raise SystemExit(1 if any(x['exitCode'] for x in results)else 0)
