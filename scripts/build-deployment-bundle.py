#!/usr/bin/env python3
"""Build a portable Git bundle from an already tested/published revision; no device data."""
import argparse,hashlib,json
from pathlib import Path
import shutil,subprocess,tempfile

ROOT=Path(__file__).resolve().parents[1]


def git(*args):return subprocess.check_output(['git','-C',str(ROOT),*args])


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--commit',required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();commit=git('rev-parse',args.commit+'^{commit}').decode().strip()
    args.output.mkdir(parents=True,exist_ok=True)
    directory=args.output/('netspecter-deploy-'+commit[:8]);directory.mkdir(exist_ok=False)
    reference='refs/netspecter/deployment-bundle'
    old=subprocess.run(['git','-C',str(ROOT),'rev-parse','--verify',reference],capture_output=True,text=True)
    if old.returncode==0:raise SystemExit('A deployment packaging ref already exists; review before replacing')
    try:
        git('update-ref',reference,commit)
        bundle=directory/'netspecter-v2.gitbundle'
        git('bundle','create',str(bundle.resolve()),reference)
        subprocess.run(['git','-C',str(ROOT),'bundle','verify',str(bundle)],check=True)
        metadata={'schema_version':1,'commit':commit,'sha256':hashlib.sha256(bundle.read_bytes()).hexdigest(),'contains':'Published repository history and checked Linux binary; no working-tree device data, config or credentials.'}
        (directory/'bundle.json').write_text(json.dumps(metadata,indent=2)+'\n')
        (directory/'deploy-from-bundle.sh').write_bytes(git('show',commit+':scripts/deploy-from-bundle.sh'))
        (directory/'DEPLOYMENT.md').write_bytes(git('show',commit+':docs/engineering/PASSIVE-DEPLOYMENT.md'))
        archive=Path(shutil.make_archive(str(directory),'gztar',root_dir=directory.parent,base_dir=directory.name))
        digest=hashlib.sha256(archive.read_bytes()).hexdigest()
        Path(str(archive)+'.sha256').write_text(digest+'  '+archive.name+'\n')
        print(json.dumps({'archive':str(archive),'sha256':digest,'commit':commit,'bytes':archive.stat().st_size},indent=2))
    finally:git('update-ref','-d',reference,commit)


if __name__=='__main__':main()
