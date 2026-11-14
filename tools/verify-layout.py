#!/usr/bin/env python3
from pathlib import Path
import argparse,hashlib,json,os,re
parser=argparse.ArgumentParser();parser.add_argument('--check-originals',action='store_true');options=parser.parse_args()
r=Path(__file__).resolve().parents[1];modules=json.loads((r/'systems.json').read_text());errors=[]
for m in modules:
 p=r/m['path']
 for f in ['go.mod','go.sum','LICENSE','NOTICE.md','README.md','DEPLOYMENT.md','Dockerfile','compose.yaml','Makefile']:
  if not(p/f).is_file():errors.append(m['name']+': missing '+f)
 if not(p/'go.mod').read_text().startswith('module '+m['module']+'\n'):errors.append(m['name']+': wrong module')
 for f in p.rglob('*.go'):
  for block in re.finditer(r'(?ms)^import\s+(?:\((.*?)^\s*\)|"([^"\n]+)")',f.read_text()):
   for imp in re.findall(r'"(arrowhead/[^"\n]+)"',block.group(1) or ('"'+block.group(2)+'"')):
    if not imp.startswith(m['module']+'/'):errors.append(str(f)+': sibling/external Arrowhead import '+imp)
 if any(p.rglob('go.work')):errors.append(m['name']+': unexpected nested workspace')
 print(m['name']+': independent module layout OK')
# Hashes show the packaging operation did not modify any source files.
manifest=json.loads((r/'SOURCE-MANIFEST.json').read_text())
# Manifest paths are relative to the workspace folder that holds this repository; $GOMODCACHE/ is the Go module cache.
def original(raw):
 if raw.startswith('$GOMODCACHE/'):return Path(os.environ.get('GOMODCACHE') or Path.home()/'go/pkg/mod')/raw[len('$GOMODCACHE/'):]
 return Path(raw) if Path(raw).is_absolute() else r.parent/raw
for raw,expected in manifest['sourceFiles'].items():
 p=original(raw)
 if not p.is_file():
  if options.check_originals:errors.append('Original source missing: '+raw)
  continue
 if hashlib.sha256(p.read_bytes()).hexdigest()!=expected:errors.append('Source changed: '+raw)
print('Modules:',len(modules),'Source hashes checked:',len(manifest['sourceFiles']))
if errors:
 print('\n'.join(errors));raise SystemExit(1)
print('PASS: no sibling Arrowhead source imports; available original source snapshots unchanged (use --check-originals to require originals)')
