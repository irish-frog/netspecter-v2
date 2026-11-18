#!/usr/bin/env python3
"""Build a pinned softflowd with bounded capture delivery; build hosts only."""
import argparse,hashlib,subprocess
from pathlib import Path

UPSTREAM_COMMIT='433fbb7102616c671d523d4e41ae5315cd70d442'
UPSTREAM_FILE_SHA256='7ebfec73e682e6a06ccf2ba245b6ba68677c03d7c971ba937f9f8307db7e9cd8'
ORIGINAL=b'pcap_set_timeout (*pcap, 0)'
PATCHED=b'pcap_set_timeout (*pcap, 100)'
PATCH_ID='capture-timeout-100ms-v1'


def main():
    parser=argparse.ArgumentParser();parser.add_argument('source',type=Path);args=parser.parse_args()
    source=args.source.resolve()
    revision=subprocess.check_output(['git','-C',str(source),'rev-parse','HEAD'],text=True).strip()
    path=source/'softflowd.c';data=path.read_bytes()
    if revision!=UPSTREAM_COMMIT or hashlib.sha256(data).hexdigest()!=UPSTREAM_FILE_SHA256 or data.count(ORIGINAL)!=1:
        raise SystemExit('Pinned exporter source mismatch; refusing to build')
    path.write_bytes(data.replace(ORIGINAL,PATCHED))
    for command in (['autoreconf','-fi'],['./configure','--prefix=/usr'],['make','-j2']):
        subprocess.run(command,cwd=source,check=True)


if __name__=='__main__':main()
