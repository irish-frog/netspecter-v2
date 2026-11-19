#!/usr/bin/env python3
"""Consume exactly one fixed maintenance request as the systemd worker."""
import os,pwd,sys
from pathlib import Path
if os.geteuid()!=0 or len(sys.argv)!=1:raise SystemExit('Fixed root maintenance worker; no arguments accepted')
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from services.appliance_maintenance_service import process_request
account=pwd.getpwnam('netspecter')
state=process_request(uid=account.pw_uid,gid=account.pw_gid)
print('NetSpecter maintenance '+state['status'])
if state['status']=='failed':raise SystemExit(1)
