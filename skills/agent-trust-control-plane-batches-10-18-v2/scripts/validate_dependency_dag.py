#!/usr/bin/env python3
from pathlib import Path
import json, sys
root=Path(__file__).resolve().parents[1]
manifest_path=root/'FULL_ROADMAP_MANIFEST.json'
if not manifest_path.exists(): manifest_path=root/'SKILLS_MANIFEST.json'
m=json.loads(manifest_path.read_text())
ids={int(x['batch']) for x in m['batches']}; edges={i:set() for i in ids}; errs=[]
for x in m['batches']:
 b=int(x['batch']); d=x['dependencies']
 for typ in ('contracts','implementation','runtime','optional'):
  for dep in d[typ]:
   if dep not in ids: errs.append(f'{b:02d} unknown {typ} dep {dep}')
 for dep in d['contracts']+d['implementation']:
  if dep==b: errs.append(f'{b:02d} self dependency')
  edges[b].add(dep)
# DFS dependencies; cycle in build graph.
state={i:0 for i in ids}; stack=[]
def dfs(n):
 state[n]=1; stack.append(n)
 for d in edges[n]:
  if state[d]==1: errs.append('cycle: '+' -> '.join(map(str,stack+[d])))
  elif state[d]==0: dfs(d)
 stack.pop(); state[n]=2
for i in sorted(ids):
 if state[i]==0: dfs(i)
if errs: print('\n'.join(errs)); sys.exit(1)
print('OK: dependency graph has no contract/implementation cycles')
