#!/usr/bin/env python3
from pathlib import Path
import re, sys
root=Path(__file__).resolve().parents[1]/'.agents'/'skills'
issues=[]
for p in root.glob('*/SKILL.md'):
 text=p.read_text(encoding='utf-8')
 batch=int(re.search(r'batch:\s*"(\d+)"',text).group(1))
 for ref in re.findall(r'Batch\s+(\d{1,2})',text):
  r=int(ref)
  if r<1 or r>36: issues.append(f'{p.parent.name}: invalid Batch {r}')
 if batch>=23 and '不得另建安全链路' not in text and '不修改公共内核' not in text and '不复制' not in text:
  issues.append(f'{p.parent.name}: domain pack missing shared-core guard')
if issues:
 print('\n'.join(issues)); sys.exit(1)
print('Dependency references and domain shared-core guards validated')
