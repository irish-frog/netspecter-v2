#!/usr/bin/env python3
import argparse,json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from services.passive_deployment_service import validate,activate
p=argparse.ArgumentParser();p.add_argument('--config',default='/etc/netspecter/config.json');p.add_argument('--activate',action='store_true');p.add_argument('--internal-network',action='append',default=[])
a=p.parse_args()
if a.activate:c=activate(a.config,a.internal_network)
else:c=json.loads(Path(a.config).read_text())
interface,port=validate(c)
print(interface);print(port)
