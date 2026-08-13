#!/usr/bin/env python3
from pathlib import Path
import re, sys, json
root=Path(__file__).resolve().parents[1]
files=list((root/'.agents/skills').glob('*/SKILL.md'))
errs=[]; batches={}
for p in files:
 t=p.read_text(encoding='utf-8')
 for key in ['name:','description:','batch:','version: "2.0.0"','# 任务','# 完成Gate','# Codex最终报告格式']:
  if key not in t: errs.append(f'{p}: missing {key}')
 m=re.search(r'batch:\s*"(\d{2})"',t); n=re.search(r'name:\s*([^\n]+)',t)
 if not m or not n: continue
 b=int(m.group(1)); name=n.group(1).strip(); batches[b]=p
 if p.parent.name!=name: errs.append(f'{p}: dir/name mismatch')
 if len(t.splitlines())>650: errs.append(f'{p}: too long ({len(t.splitlines())})')
 if '不得只' not in t and '禁止' not in t: errs.append(f'{p}: weak implementation semantics')
manifest=json.loads((root/'SKILLS_MANIFEST.json').read_text())
expected={int(x['batch']) for x in manifest.get('batches',[])}
if manifest.get('skill_count')!=len(expected): errs.append('manifest skill_count')
if set(batches)!=expected: errs.append(f'actual batches={sorted(batches)}, expected={sorted(expected)}')
if errs:
 print('\n'.join(errs)); sys.exit(1)
print(f'OK: {len(files)} skills, batches '+','.join(f'{x:02d}' for x in sorted(expected)))
