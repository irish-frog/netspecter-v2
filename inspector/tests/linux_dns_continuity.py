#!/usr/bin/env python3
"""Disposable CI proof of a native DNS listener bound away from 127.0.0.1."""
import os,socket,struct,subprocess,sys,threading
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from services import dns_continuity_service as dns


def main():
    if sys.platform!='linux' or os.geteuid()!=0 or os.environ.get('GITHUB_ACTIONS')!='true':raise SystemExit('Disposable hosted root CI only')
    if any(path.exists() for path in dns.CONFIG_PATHS):raise SystemExit('Refusing an existing AdGuard configuration')
    if subprocess.run(['systemctl','is-active','--quiet','AdGuardHome'],check=False).returncode==0:raise SystemExit('Refusing an active AdGuard service')
    address='127.0.0.2';stop=threading.Event();sockets=[];threads=[];errors=[]
    def answer(query):
        offset=12
        while query[offset]:offset+=query[offset]+1
        offset+=5
        return query[:2]+struct.pack('!HHHHH',0x8180,1,1,0,0)+query[12:offset]+b'\xc0\x0c'+struct.pack('!HHIH',1,1,30,4)+socket.inet_aton('192.0.2.1')
    def serve_udp(sock):
        while not stop.is_set():
            try:query,peer=sock.recvfrom(4096);sock.sendto(answer(query),peer)
            except socket.timeout:continue
            except OSError:
                if not stop.is_set():errors.append('UDP socket failure')
                return
            except Exception as error:errors.append(type(error).__name__);return
    def serve_tcp(sock):
        while not stop.is_set():
            try:connection,_=sock.accept()
            except socket.timeout:continue
            except OSError:return
            with connection:
                connection.settimeout(3)
                try:
                    def exact(size):
                        data=b''
                        while len(data)<size:
                            part=connection.recv(size-len(data))
                            if not part:raise RuntimeError('Early EOF')
                            data+=part
                        return data
                    length=struct.unpack('!H',exact(2))[0];response=answer(exact(length))
                    connection.sendall(struct.pack('!H',len(response))+response)
                except Exception as error:errors.append(type(error).__name__)
    try:
        for kind,serve in ((socket.SOCK_DGRAM,serve_udp),(socket.SOCK_STREAM,serve_tcp)):
            sock=socket.socket(socket.AF_INET,kind);sockets.append(sock);sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,0)
            sock.bind((address,53));sock.settimeout(0.2)
            if kind==socket.SOCK_STREAM:sock.listen(4)
            thread=threading.Thread(target=serve,args=(sock,),daemon=True);threads.append(thread);thread.start()
        real_run=subprocess.run
        def run(args,**kwargs):
            if args[0]=='systemctl' and 'AdGuardHome' in args:
                return subprocess.CompletedProcess(args,0,stdout=str(os.getpid()) if 'show' in args else '')
            return real_run(args,**kwargs)
        # Only the service identity lookup is substituted. ss ownership discovery,
        # dig UDP/TCP queries and DNS response parsing use real Linux processes/sockets.
        with patch.object(subprocess,'run',side_effect=run):
            state=dns.snapshot();assert state['dns_server']==address,state
            dns.verify(state)
        assert not errors,errors
        print('PASS: actual ss PID ownership and UDP/TCP DNS continuity on a non-default loopback bind, no resolver changes.')
    finally:
        stop.set()
        for sock in sockets:sock.close()
        for thread in threads:thread.join(timeout=2)


if __name__=='__main__':main()
