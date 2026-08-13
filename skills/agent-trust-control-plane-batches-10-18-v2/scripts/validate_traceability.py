#!/usr/bin/env python3
from pathlib import Path
import re, sys
root=Path(__file__).resolve().parents[1]
files=['SYSTEM_CAPABILITIES.yaml','THREAT_CONTROL_MATRIX.yaml','CONTROL_EVIDENCE_MATRIX.yaml','END_TO_END_SCENARIOS.yaml','NON_FUNCTIONAL_REQUIREMENTS.yaml']
errs=[]
for f in files:
 t=(root/f).read_text(encoding='utf-8')
 for n in re.findall(r'"(\d{2})"',t):
  if int(n)<1 or int(n)>36: errs.append(f'{f}: invalid batch {n}')
 if len(t.splitlines())<5: errs.append(f'{f}: too small')
if errs: print('\n'.join(errs)); sys.exit(1)
print('OK: global traceability files reference valid batches')
