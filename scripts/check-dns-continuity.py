#!/usr/bin/env python3
"""Capture/check DNS health without modifying DNS settings or service state."""
import argparse,json,os,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from services.dns_continuity_service import snapshot,verify
parser=argparse.ArgumentParser();parser.add_argument('operation',choices=['snapshot','verify']);parser.add_argument('state',type=Path)
args=parser.parse_args()
if os.geteuid()!=0:raise SystemExit('Run DNS deployment checks as root')
if args.operation=='snapshot':
    state=snapshot()
    fd=os.open(args.state,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w') as handle:json.dump(state,handle)
else:verify(json.loads(args.state.read_text()))
print('DNS continuity check passed; no DNS settings/service changes performed.')
