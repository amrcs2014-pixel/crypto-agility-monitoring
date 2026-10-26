"""OpenSSL-stack client for the Paper B testbed: the same nine traffic profiles as `tlslab client`,
driving `openssl s_client` (OpenSSL 4.0.3) connections. Each s_client process is one TLS connection;
HTTP/1.1 requests are written to its stdin and responses parsed from its stdout (-quiet), so
keep-alive connections, uploads and think times behave like an application.

usage: b_osslclient.py PROFILE TARGET KX(classical|hybrid) CA ECHFILE|- DUR SEED
All traffic stays inside the lab's emulated network and targets the lab's own server.
"""
import os, random, subprocess, sys, threading, time, urllib.parse

B = os.environ.get('LAB', '/opt/p1920b')
OSSL = f'{B}/ossl4/bin/openssl'
ENV = dict(os.environ, LD_LIBRARY_PATH=f'{B}/ossl4/lib')
SNI = 'www.example.test'
# classical = OpenSSL 3.0-era default group list (no hybrid); hybrid = OpenSSL 4.0 default list
GROUPS = {'classical': ['-groups', 'X25519:P-256:X448:P-521:P-384'], 'hybrid': []}


class Conn:
    def __init__(self, target, kx, ca, ech, port=443):
        args = [OSSL, 's_client', '-connect', f'{target}:{port}', '-servername', SNI, '-tls1_3',
                '-alpn', 'http/1.1', '-CAfile', ca, '-quiet', '-verify_return_error'] + GROUPS[kx]
        if ech:
            args += ['-ech_config_list', ech]
        self.p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL, env=ENV, bufsize=0)
        self.buf = b''

    def _read(self, n):
        while len(self.buf) < n:
            c = self.p.stdout.read(65536)
            if not c:
                raise EOFError
            self.buf += c
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def _readline(self):
        while b'\r\n' not in self.buf:
            c = self.p.stdout.read(65536)
            if not c:
                raise EOFError
            self.buf += c
        i = self.buf.index(b'\r\n')
        line, self.buf = self.buf[:i], self.buf[i + 2:]
        return line

    def request(self, method, path, body=b'', ctype='application/octet-stream', close=False):
        h = f'{method} {path} HTTP/1.1\r\nHost: {SNI}\r\nUser-Agent: osslclient/1\r\n'
        if body:
            h += f'Content-Type: {ctype}\r\nContent-Length: {len(body)}\r\n'
        if close:
            h += 'Connection: close\r\n'
        self.p.stdin.write(h.encode() + b'\r\n' + body)
        self.p.stdin.flush()
        status = self._readline()
        clen, chunked = 0, False
        while True:
            l = self._readline()
            if not l:
                break
            k, _, v = l.decode('latin1').partition(':')
            if k.lower() == 'content-length':
                clen = int(v)
            if k.lower() == 'transfer-encoding' and 'chunked' in v.lower():
                chunked = True
        if chunked:
            while True:
                n = int(self._readline().split(b';')[0], 16)
                self._read(n + 2)
                if n == 0:
                    break
        else:
            self._read(clen)
        return status

    def close(self):
        try:
            self.p.stdin.close()
        except Exception:
            pass
        try:
            self.p.wait(3)
        except Exception:
            self.p.kill()


def main():
    prof, target, kx, ca, echf, dur, seed = sys.argv[1:8]
    dur, rng = float(dur), random.Random(int(seed))
    ech = open(echf).read().strip() if echf != '-' else None
    end = time.time() + dur
    st = {'n': 0, 'err': 0}

    def size(m):
        return int(m * (0.25 + 1.5 * rng.random()))

    def sleep(lo, hi):
        time.sleep(lo + rng.random() * (hi - lo))

    def one(method, path, body=b'', ctype='application/octet-stream'):  # fresh connection per request
        st['n'] += 1
        try:
            c = Conn(target, kx, ca, ech); c.request(method, path, body, ctype, close=True); c.close()
        except Exception:
            st['err'] += 1

    def persistent(fn):
        try:
            c = Conn(target, kx, ca, ech); fn(c); c.close()
        except Exception:
            st['err'] += 1

    if prof == 'web_page':  # page + 6-14 objects over up to 4 keep-alive connections
        conns = [None] * 4
        while time.time() < end:
            try:
                conns = [c or Conn(target, kx, ca, ech) for c in conns]
                conns[0].request('GET', '/'); st['n'] += 1
                objs = [size(9000) for _ in range(6 + rng.randrange(9))]
                def worker(c, items):
                    for n in items:
                        c.request('GET', f'/obj?n={n}')
                ts = [threading.Thread(target=worker, args=(conns[i], objs[i::4])) for i in range(4)]
                [t.start() for t in ts]; [t.join() for t in ts]; st['n'] += len(objs)
            except Exception:
                st['err'] += 1; conns = [None] * 4
            sleep(2, 5)
        for c in conns:
            c and c.close()
    elif prof == 'api_poll':
        def f(c):
            while time.time() < end:
                c.request('GET', f'/obj?n={size(900)}'); st['n'] += 1; sleep(1, 3)
        persistent(f)
    elif prof == 'download':
        st['n'] += 1; persistent(lambda c: c.request('GET', f'/obj?n={size(5 << 20)}'))
    elif prof == 'upload':
        st['n'] += 1; persistent(lambda c: c.request('POST', '/upload', os.urandom(size(2 << 20))))
    elif prof == 'video':
        def f(c):
            while time.time() < end:
                c.request('GET', f'/obj?n={size(400000)}'); st['n'] += 1; sleep(1.8, 2.2)
        persistent(f)
    elif prof == 'many_short':
        while time.time() < end:
            one('GET', f'/obj?n={size(3000)}'); sleep(0.3, 1.2)
    elif prof == 'beacon':
        while time.time() < end:
            one('GET', f'/beacon?id={rng.randrange(1 << 20)}'); sleep(4, 6)
    elif prof == 'brute':
        while time.time() < end:
            body = urllib.parse.urlencode({'user': 'admin', 'password': f'pw{rng.randrange(10**6):06d}'}).encode()
            one('POST', '/login', body, 'application/x-www-form-urlencoded'); sleep(0.05, 0.25)
    elif prof == 'beacon_rand':  # reviewer M3a: random request padding and random response size
        while time.time() < end:
            pad = ''.join(rng.choice('abcdefghijklmnopqrstuvwxyz') for _ in range(rng.randrange(1025)))
            one('GET', f'/obj?n={64 + rng.randrange(16321)}&id={rng.randrange(1 << 20)}&pad={pad}'); sleep(4, 6)
    elif prof == 'brute_rand':  # reviewer M3a: randomly padded form; the victim's reply is unchanged
        while time.time() < end:
            pad = ''.join(rng.choice('abcdefghijklmnopqrstuvwxyz') for _ in range(rng.randrange(4097)))
            body = urllib.parse.urlencode({'user': 'admin', 'password': f'pw{rng.randrange(10**6):06d}', 'pad': pad}).encode()
            one('POST', '/login', body, 'application/x-www-form-urlencoded'); sleep(0.05, 0.25)
    elif prof == 'beacon_mimic':  # reviewer M3a: beacon timing with the sizes of the benign many_short profile
        while time.time() < end:
            one('GET', f'/obj?n={size(3000)}'); sleep(4, 6)
    elif prof == 'scan':  # handshake sweep, close right after the handshake
        ports = [443, 8443, 9443, 10443, 4433, 443]
        while time.time() < end:
            st['n'] += 1
            args = [OSSL, 's_client', '-connect', f'{target}:{rng.choice(ports)}', '-servername', SNI, '-tls1_3',
                    '-CAfile', ca] + GROUPS[kx] + (['-ech_config_list', ech] if ech else [])
            try:
                subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               env=ENV, timeout=3)
            except Exception:
                st['err'] += 1
            sleep(0.05, 0.2)
    else:
        sys.exit('unknown profile ' + prof)
    print('requests', st['n'], 'errors', st['err'])


if __name__ == '__main__':
    main()
