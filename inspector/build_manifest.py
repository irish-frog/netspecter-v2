#!/usr/bin/env python3
"""Create/verify the provenance and checksum of the shipped Linux sensor."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tomllib

ROOT=Path(__file__).resolve().parent


def fingerprint(root=ROOT):
    digest=hashlib.sha256()
    paths=[root/'Cargo.toml',root/'Cargo.lock',root/'rust-toolchain.toml',*sorted((root/'src').rglob('*.rs'))]
    for path in paths:
        digest.update(path.relative_to(root).as_posix().encode()+b'\0'+hashlib.sha256(path.read_bytes().replace(b"\r\n",b"\n")).digest())
    return digest.hexdigest()


def verify(bundle,root=ROOT):
    bundle=Path(bundle)
    manifest=bundle/'build.json';binary=bundle/'netspecter-tls-inspector'
    if manifest.is_symlink() or binary.is_symlink() or not binary.is_file():raise ValueError('Missing or linked sensor bundle')
    data=json.loads(manifest.read_text())
    if type(data.get('schema_version')) is not int or data.get('schema_version')!=1 or data.get('target')!='x86_64-unknown-linux-gnu' or data.get('source_sha256')!=fingerprint(root):raise ValueError('Sensor source and build manifest do not match')
    if not re.fullmatch('[0-9a-f]{40}',str(data.get('source_commit',''))):raise ValueError('Invalid build commit')
    if data.get('sha256')!=hashlib.sha256(binary.read_bytes()).hexdigest():raise ValueError('Sensor binary checksum mismatch')
    header=binary.read_bytes()[:64]
    if header[:6]!=b'\x7fELF\x02\x01' or len(header)<64 or struct.unpack_from('<H',header,18)[0]!=62:raise ValueError('Expected x86_64 Linux ELF binary')
    return data


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode',choices=['create','verify'])
    parser.add_argument('bundle',type=Path)
    parser.add_argument('--binary',type=Path)
    parser.add_argument('--source-commit')
    args=parser.parse_args()
    if args.mode=='create':
        if not args.binary or not args.source_commit:parser.error('create requires --binary and --source-commit')
        args.bundle.mkdir(parents=True,exist_ok=True)
        destination=args.bundle/'netspecter-tls-inspector'
        if args.binary.resolve()!=destination.resolve():shutil.copyfile(args.binary,destination)
        config=tomllib.loads((ROOT/'Cargo.toml').read_text())
        data=dict(schema_version=1,target='x86_64-unknown-linux-gnu',minimum_glibc='2.39',version=config['package']['version'],source_commit=args.source_commit,
            source_sha256=fingerprint(),sha256=hashlib.sha256(destination.read_bytes()).hexdigest(),toolchain=subprocess.check_output(['rustc','--version'],text=True).strip())
        (args.bundle/'build.json').write_text(json.dumps(data,indent=2)+'\n')
    print(json.dumps(verify(args.bundle),indent=2))


if __name__=='__main__':main()
