#!/usr/bin/env python3
from pathlib import Path
from difflib import SequenceMatcher
import re, sys
root=Path(__file__).resolve().parents[1]/'.agents/skills'
items=[]
for p in root.glob('*/SKILL.md'):
 t=p.read_text(encoding='utf-8')
 t=re.sub(r'^---.*?---','',t,flags=re.S)
 t='\n'.join(x for x in t.splitlines() if not x.startswith('# Codex') and '所有跨服务对象' not in x)
 items.append((p.parent.name,t))
errs=[]
for i in range(len(items)):
 for j in range(i+1,len(items)):
  r=SequenceMatcher(None,items[i][1],items[j][1]).ratio()
  if r>0.82: errs.append(f'near duplicate {items[i][0]} / {items[j][0]}: {r:.3f}')
if errs: print('\n'.join(errs)); sys.exit(1)
print('OK: no suspicious near-duplicate skills')
