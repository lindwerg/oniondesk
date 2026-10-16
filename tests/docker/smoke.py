"""Real Debian nginx/auth/websockify/Chromium integration with a minimal RFB peer."""

import base64
import hashlib
import http.client
from http import cookies
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import socketserver
import struct
import subprocess
import sys
import threading
import time
from urllib.parse import urlencode

ROOT = Path('/workspace/outputs/remote-desktop-kit')
LOG = Path('/logs')
HOST = 'a' * 56 + '.onion'
ORIGIN = 'http://' + HOST
REAL_VNC = '--real-vnc' in sys.argv
spec = importlib.util.spec_from_file_location('oniondesk_auth', ROOT / 'frontend/auth.py')
auth = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = auth
spec.loader.exec_module(auth)


def check(condition, message):
    if not condition:
        raise AssertionError(message)
    print('PASS ' + message, flush=True)


def exact(connection, length):
    value = bytearray()
    while len(value) < length:
        part = connection.recv(length - len(value))
        if not part:
            raise EOFError('RFB peer closed')
        value.extend(part)
    return bytes(value)


class RFB(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.communicate()
        except (EOFError, ConnectionError, TimeoutError):
            pass

    def communicate(self):
        self.request.settimeout(20)
        self.request.sendall(b'RFB 003.008\n')
        version = exact(self.request, 12)
        if version != b'RFB 003.008\n':
            return
        self.server.handshakes += 1
        self.request.sendall(b'\x01\x01')
        if exact(self.request, 1) != b'\x01':
            return
        self.request.sendall(b'\0\0\0\0')
        exact(self.request, 1)
        pixel = struct.pack('>BBBBHHHBBB3x', 32, 24, 0, 1, 255, 255, 255, 16, 8, 0)
        name = b'OnionDesk Docker mock ' + self.server.role.encode()
        self.request.sendall(struct.pack('>HH', 320, 200) + pixel + struct.pack('>I', len(name)) + name)
        try:
            while True:
                kind = exact(self.request, 1)[0]
                if kind == 0:
                    exact(self.request, 3)
                    pixel = exact(self.request, 16)
                elif kind == 2:
                    count = struct.unpack('>xH', exact(self.request, 3))[0]
                    exact(self.request, count * 4)
                elif kind == 3:
                    exact(self.request, 9)
                    self.server.updates += 1
                    bits, _, big, _, _, _, _, red, green, blue = struct.unpack('>BBBBHHHBBB3x', pixel)
                    rgb = (220 << red) | (110 << green) | (30 << blue)
                    color = rgb.to_bytes(bits // 8, 'big' if big else 'little')
                    self.request.sendall(b'\x00\x00\x00\x01' + struct.pack('>HHHHi', 0, 0, 320, 200, 0) + color * 64000)
                elif kind == 4:
                    exact(self.request, 7)
                elif kind == 5:
                    exact(self.request, 5)
                elif kind == 6:
                    length = struct.unpack('>3xI', exact(self.request, 7))[0]
                    exact(self.request, length)
                elif kind == 150:
                    exact(self.request, 9)
                else:
                    raise ValueError(f'Unsupported RFB message {kind}')
        except (EOFError, ConnectionError, TimeoutError):
            pass


def request(method, path, jar=None, form=None, headers=None):
    values = {'Host': HOST}
    if jar:
        values['Cookie'] = '; '.join(f'{key}={value}' for key, value in jar.items())
    body = None
    if form is not None:
        body = urlencode(form)
        values.update({'Content-Type': 'application/x-www-form-urlencoded', 'Origin': ORIGIN})
    values.update(headers or {})
    connection = http.client.HTTPConnection('127.0.0.1', 18080, timeout=15)
    connection.request(method, path, body, values)
    response = connection.getresponse()
    data = response.read().decode(errors='replace')
    pairs = response.getheaders()
    if jar is not None:
        for name, value in pairs:
            if name.lower() == 'set-cookie':
                for key, morsel in cookies.SimpleCookie(value).items():
                    if morsel['max-age'] == '0':
                        jar.pop(key, None)
                    else:
                        jar[key] = morsel.value
    status = response.status
    connection.close()
    return status, data, dict(pairs)


def websocket(path, jar=None, origin=ORIGIN):
    connection = socket.create_connection(('127.0.0.1', 18080), timeout=10)
    key = base64.b64encode(os.urandom(16)).decode()
    headers = [f'GET {path} HTTP/1.1', f'Host: {HOST}', 'Upgrade: websocket',
               'Connection: Upgrade', 'Sec-WebSocket-Version: 13', f'Sec-WebSocket-Key: {key}',
               'Sec-WebSocket-Protocol: binary']
    if origin is not None:
        headers.append('Origin: ' + origin)
    if jar:
        headers.append('Cookie: ' + '; '.join(f'{k}={v}' for k, v in jar.items()))
    connection.sendall(('\r\n'.join(headers) + '\r\n\r\n').encode())
    data = bytearray()
    while b'\r\n\r\n' not in data:
        data.extend(exact(connection, 1))
    status = int(bytes(data).split(b' ')[1])
    if status == 101:
        expected = base64.b64encode(hashlib.sha1((key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest())
        check(b'Sec-WebSocket-Accept: ' + expected in data, path + ' RFC6455 handshake')
        first = exact(connection, 2)
        length = first[1] & 127
        if length == 126:
            length = struct.unpack('>H', exact(connection, 2))[0]
        elif length == 127:
            length = struct.unpack('>Q', exact(connection, 8))[0]
        check(exact(connection, length) == b'RFB 003.008\n', path + ' real websockify RFB bytes')
    connection.close()
    return status


def main():
    LOG.mkdir(parents=True, exist_ok=True)
    state = Path('/run/oniondesk-test')
    state.mkdir(mode=0o700)
    auth.initialize(state, ORIGIN)
    credentials = json.loads((state / 'credentials.json').read_text())
    subprocess.run([sys.executable, str(ROOT / 'frontend/build-nginx-config.py'), HOST,
                    str(ROOT / 'frontend/nginx.conf.in'), '/usr/share/novnc/vnc.html',
                    '/etc/nginx/sites-available/oniondesk.conf'], check=True)
    Path('/etc/nginx/sites-enabled/default').unlink()
    Path('/etc/nginx/sites-enabled/oniondesk.conf').symlink_to('/etc/nginx/sites-available/oniondesk.conf')
    subprocess.run(['nginx', '-t'], check=True)
    expanded = subprocess.run(['nginx', '-T'], check=True, capture_output=True, text=True)
    (LOG / 'nginx-expanded.log').write_text(expanded.stdout)
    subprocess.run([sys.executable, str(ROOT / 'frontend/check-nginx-listeners.py'),
                    str(LOG / 'nginx-expanded.log')], check=True)
    servers = []
    processes = []
    streams = []
    for role, port in ([] if REAL_VNC else [('gateway', 5901), ('workstation', 5902)]):
        server = socketserver.ThreadingTCPServer(('127.0.0.1', port), RFB)
        server.daemon_threads = True
        server.role = role
        server.handshakes = server.updates = 0
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
    commands = [('auth', [sys.executable, str(ROOT / 'frontend/auth.py'), 'serve', '--config', str(state / 'auth.json'), '--state-dir', str(state)]),
                ('gateway', ['websockify', '127.0.0.1:16081', '127.0.0.1:5901']),
                ('workstation', ['websockify', '127.0.0.1:16082', '127.0.0.1:5902']),
                ('nginx', ['nginx', '-g', 'daemon off;'])]
    try:
        for name, command in commands:
            stream = (LOG / f'{name}.log').open('w')
            streams.append(stream)
            processes.append(subprocess.Popen(command, stdout=stream, stderr=stream))
        for port in (18081, 16081, 16082, 18080):
            for attempt in range(100):
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=1):
                        break
                except OSError:
                    time.sleep(0.1)
            else:
                raise TimeoutError(f'Service on port {port} did not start')
        listening = subprocess.check_output(['ss', '-lntp'], text=True)
        (LOG / 'listeners.log').write_text(listening)
        for port in (18080, 18081, 16081, 16082, 5901, 5902):
            sockets = [row.split()[3] for row in listening.splitlines()[1:] if row.split()[3].endswith(':' + str(port))]
            check(sockets == ['127.0.0.1:' + str(port)], f'port {port} binds only IPv4 loopback')
            try:
                with socket.create_connection(('::1', port), timeout=1):
                    raise AssertionError(f'port {port} unexpectedly listens on IPv6')
            except OSError:
                pass
        interfaces = json.loads(subprocess.check_output(['ip', '-json', 'address', 'show'], text=True))
        for interface in interfaces:
            for address in interface.get('addr_info', []):
                if address['family'] == 'inet' and address['scope'] == 'global':
                    for port in (18080, 18081, 16081, 16082, 5901, 5902):
                        try:
                            with socket.create_connection((address['local'], port), timeout=1):
                                raise AssertionError(f'port {port} exposed on container Ethernet')
                        except OSError:
                            pass
        print('PASS no service reachable through container Ethernet or IPv6 loopback', flush=True)
        menu_redirect = request('GET', '/')
        novnc_redirect = request('GET', '/novnc/vnc.html')
        check(menu_redirect[0] == 302 and menu_redirect[2].get('Location') == ORIGIN + '/login', 'unauthenticated menu has real login redirect')
        check(novnc_redirect[0] == 302 and novnc_redirect[2].get('Location') == ORIGIN + '/login', 'unauthenticated noVNC has real login redirect')
        check('Set-Cookie' not in menu_redirect[2] and 'Set-Cookie' not in novnc_redirect[2], 'unauthenticated asset redirects do not rotate login CSRF cookie')
        favicon = request('GET', '/favicon.ico')
        check(favicon[0] == 204 and 'Set-Cookie' not in favicon[2] and 'Location' not in favicon[2], 'background favicon cannot replace prelogin cookie')
        check(request('GET', '/auth-check')[0] == 404, 'nginx auth subrequest inaccessible externally')
        for role in ('gateway', 'workstation'):
            check(websocket('/ws/' + role) == 401, role + ' unauthorized WebSocket denied before upgrade')
        jar = {}
        status, body, headers = request('GET', '/login', jar)
        check(status == 200, 'login through real nginx')
        csrf = re.search(r'name="csrf" value="([A-Za-z0-9_-]+)"', body).group(1)
        form = {'login': credentials['login'], 'password': credentials['password'], 'otp': auth.totp(credentials['totp_secret'], int(time.time()) // 30 - 1), 'csrf': csrf}

        def login_attempt(overrides=None, headers=None):
            result = request('POST', '/login', jar, {**form, **(overrides or {})}, headers)
            replacement = re.search(r'name="csrf" value="([A-Za-z0-9_-]+)"', result[1])
            if replacement:
                form['csrf'] = replacement.group(1)
            return result

        check(login_attempt({'csrf': 'wrong'})[0] == 403, 'login CSRF denied')
        check(login_attempt(headers={'Origin': 'http://attacker.invalid'})[0] == 403, 'login foreign Origin denied')
        check(login_attempt({'password': 'wrong'})[0] == 401, 'wrong password denied')
        incorrect = '000000' if form['otp'] != '000000' else '999999'
        check(login_attempt({'otp': incorrect})[0] == 401, 'wrong TOTP denied')
        status, _, headers = login_attempt()
        check(status == 303 and auth.SESSION_COOKIE in jar, 'password plus TOTP login succeeds')
        check('HttpOnly' in headers['Set-Cookie'] and 'SameSite=Strict' in headers['Set-Cookie'], 'session cookie defenses preserved through nginx')
        status, body, headers = request('GET', '/', jar)
        check(status == 200 and '/ws/gateway' in body and '/ws/workstation' in body, 'authenticated menu exposes both desktops')
        check('script-src' in headers.get('Content-Security-Policy', ''), 'CSP header served by nginx')
        for role in ('gateway', 'workstation'):
            path = '/ws/' + role
            check(websocket(path, jar, 'http://attacker.invalid') == 403, role + ' foreign WebSocket Origin denied')
            check(websocket(path, jar, None) == 403, role + ' absent WebSocket Origin denied')
            check(websocket(path, jar) == 101, role + ' authenticated WebSocket succeeds')
        csrf = re.search(r'name="csrf" value="([A-Za-z0-9_-]+)"', body).group(1)
        check(request('POST', '/logout', jar, {'csrf': 'wrong'})[0] == 403, 'logout CSRF denied')
        check(request('POST', '/logout', jar, {'csrf': csrf}, {'Origin': 'null'})[0] == 403, 'logout null Origin denied')
        check(request('POST', '/logout', jar, {'csrf': csrf})[0] == 303 and not jar, 'logout revokes session')
        check(websocket('/ws/workstation', jar) == 401, 'logged-out WebSocket denied')
        try:
            request('GET', '/login', headers={'Host': 'attacker.invalid'})
        except http.client.RemoteDisconnected:
            print('PASS foreign Host connection closed by nginx 444', flush=True)
        else:
            raise AssertionError('foreign Host accepted')

        check(429 in [request('GET', '/login')[0] for _ in range(12)], 'nginx login burst rate limiting enforced')
        # Isolate browser authentication from the deliberately exhausted burst.
        processes[-1].terminate()
        processes[-1].wait(timeout=5)
        processes[-1] = subprocess.Popen(['nginx', '-g', 'daemon off;'], stdout=streams[-1], stderr=streams[-1])
        for attempt in range(100):
            try:
                with socket.create_connection(('127.0.0.1', 18080), timeout=1):
                    break
            except OSError:
                time.sleep(0.1)

        # Keep the browser's real origin at standard Tor HTTP port 80.
        relay = subprocess.Popen([sys.executable, str(ROOT / 'tests/docker/tcp-relay.py')], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        processes.append(relay)
        time.sleep(0.2)
        from playwright.sync_api import sync_playwright
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(executable_path='/usr/bin/chromium', args=['--no-sandbox', '--no-proxy-server', '--host-resolver-rules=MAP ' + HOST + ' 127.0.0.1'])
            context = browser.new_context()
            page = context.new_page()
            errors = []
            violations = []
            page.on('pageerror', lambda error: errors.append(str(error)))
            page.on('console', lambda message: violations.append(message.text) if 'Content Security Policy' in message.text else None)
            page.on('request', lambda req: print('BROWSER POST origin=' + req.headers.get('origin', '<absent>') + ' cookie_present=' + str('cookie' in req.all_headers()), flush=True) if req.method == 'POST' else None)
            page.on('response', lambda response: print(f'BROWSER {response.request.method} {response.url.split(HOST)[-1]} {response.status}', flush=True))
            page.goto(ORIGIN + '/login')
            print('BROWSER cookies=' + repr([{k: cookie[k] for k in ('name', 'domain', 'path', 'sameSite')} for cookie in context.cookies()]), flush=True)
            page.locator('[name=login]').fill(credentials['login'])
            page.locator('[name=password]').fill(credentials['password'])
            page.locator('[name=otp]').fill(auth.totp(credentials['totp_secret'], int(time.time()) // 30))
            page.locator('button[type=submit]').click()
            print('BROWSER url after submit=' + page.url + ' title=' + page.title(), flush=True)
            page.wait_for_url(ORIGIN + '/')
            check(page.locator('h1').inner_text() == 'Выберите рабочий стол', 'Chromium password/TOTP form navigation')
            prefix = 'guest-' if REAL_VNC else ''
            page.screenshot(path=str(LOG / (prefix + 'menu.png')), full_page=True)
            for role in ('gateway', 'workstation'):
                page.goto(ORIGIN + '/novnc/vnc.html?autoconnect=1&resize=scale&path=/ws/' + role)
                page.locator('#noVNC_status').filter(has_text='Connected').wait_for(timeout=15000)
                page.locator('canvas').wait_for(state='visible', timeout=10000)
                if REAL_VNC:
                    check(int(page.locator('canvas').first.get_attribute('width')) >= 320, role + ' noVNC receives existing QEMU framebuffer')
                else:
                    check(page.locator('canvas').first.get_attribute('width') == '320', role + ' noVNC rendered real RFB framebuffer')
                    page.wait_for_function("() => { const c = document.querySelector('canvas'); const p = c.getContext('2d').getImageData(1, 1, 1, 1).data; return p[0] === 220 && p[1] === 110 && p[2] === 30; }", timeout=10000)
                    check(next(s for s in servers if s.role == role).updates > 0, role + ' browser painted mock RFB pixel RGB(220,110,30)')
                page.screenshot(path=str(LOG / (prefix + role + '.png')), full_page=True)
            check(not errors, 'noVNC module bootstrap has no browser page errors: ' + repr(errors))
            check(not violations, 'noVNC 1.6 CSP causes no browser violations: ' + repr(violations))
            (LOG / (prefix + 'browser.json')).write_text(json.dumps({'backend': 'existing VNC' if REAL_VNC else 'mock RFB', 'errors': errors, 'csp_violations': violations, 'roles': {s.role: {'handshakes': s.handshakes, 'framebuffer_updates': s.updates} for s in servers}}, indent=2))
            browser.close()
        for name in ('auth.log', 'nginx.log', 'gateway.log', 'workstation.log'):
            content = (LOG / name).read_text()
            check(credentials['password'] not in content and credentials['totp_secret'] not in content,
                  name + ' does not expose password or TOTP secret')
    finally:
        for process in reversed(processes):
            process.terminate()
        for process in processes:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for stream in streams:
            stream.close()
        for server in servers:
            server.shutdown()
            server.server_close()


if __name__ == '__main__':
    main()
