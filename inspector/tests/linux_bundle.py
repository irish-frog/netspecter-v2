#!/usr/bin/env python3
"""Exercise third-appliance bootstrap in a disposable CI runner, with inert deploy stub."""
import hashlib,json,os,shutil,socket,subprocess,tempfile
from pathlib import Path
SOURCE=Path(__file__).resolve().parents[2]
DEST=Path('/opt/netspecter')


def main():
    if os.geteuid()!=0 or os.environ.get('GITHUB_ACTIONS')!='true' or DEST.exists() or DEST.is_symlink():
        raise SystemExit('Requires disposable root CI with no existing /opt/netspecter')
    DEST.mkdir()
    def git(*args):return subprocess.check_output(['git','-C',str(DEST),*args],text=True).strip()
    try:
        git('init','-b','main');git('config','user.name','CI');git('config','user.email','ci@example.invalid')
        (DEST/'source.txt').write_text('original\n');git('add','.');git('commit','-m','Original')
        original=git('rev-parse','HEAD')
        (DEST/'scripts').mkdir()
        (DEST/'scripts/deploy-attribution.sh').write_text('#!/bin/bash\nset -eu\nprintf "%s\\n" "$@" > /opt/netspecter/deploy-arguments.txt\n')
        git('add','.');git('commit','-m','Inert deployment fixture');commit=git('rev-parse','HEAD')
        git('update-ref','refs/netspecter/deployment-bundle',commit)
        with tempfile.TemporaryDirectory(prefix='ns-bundle-') as directory:
            package=Path(directory);bundle=package/'netspecter-v2.gitbundle'
            git('bundle','create',str(bundle),'refs/netspecter/deployment-bundle')
            metadata={'commit':commit,'sha256':hashlib.sha256(bundle.read_bytes()).hexdigest()}
            (package/'bundle.json').write_text(json.dumps(metadata))
            shutil.copyfile(SOURCE/'scripts/deploy-from-bundle.sh',package/'deploy-from-bundle.sh')
            git('reset','--hard',original)
            def bootstrap(host=socket.gethostname()):
                return subprocess.run(['bash',str(package/'deploy-from-bundle.sh'),host,'--preflight'],capture_output=True,text=True)
            assert bootstrap('definitely-not-the-appliance').returncode!=0
            assert git('rev-parse','HEAD')==original
            (DEST/'source.txt').write_text('local edit\n')
            assert bootstrap().returncode!=0 and (DEST/'source.txt').read_text()=='local edit\n'
            git('restore','source.txt')
            metadata['sha256']='0'*64;(package/'bundle.json').write_text(json.dumps(metadata))
            assert bootstrap().returncode!=0 and git('rev-parse','HEAD')==original
            metadata['sha256']=hashlib.sha256(bundle.read_bytes()).hexdigest();(package/'bundle.json').write_text(json.dumps(metadata))
            result=bootstrap();assert result.returncode==0,(result.stdout,result.stderr)
            assert git('rev-parse','HEAD')==commit
            assert (DEST/'deploy-arguments.txt').read_text().splitlines()==['--expected-hostname',socket.gethostname(),'--preflight']
        print('PASS: offline bundle checksum, exact hostname, local-edit protection, fast-forward and preflight argument forwarding.')
    finally:
        if not DEST.is_symlink():shutil.rmtree(DEST)


if __name__=='__main__':main()
