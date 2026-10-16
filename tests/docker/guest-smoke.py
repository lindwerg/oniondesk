"""Boot signed read-only Whonix bases through x86 TCG and save QMP evidence."""
import json
from pathlib import Path
import socket
import subprocess
import sys
import time

ROOT = Path('/workspace/outputs/remote-desktop-kit')
LOG = Path('/logs')
BASE = Path('/artifacts/extracted')


class QMP:
    def __init__(self, path):
        self.socket = socket.socket(socket.AF_UNIX)
        self.socket.settimeout(20)
        self.socket.connect(str(path))
        self.stream = self.socket.makefile('rwb')
        self.stream.readline()
        self.command('qmp_capabilities')

    def command(self, command, arguments=None):
        payload = {'execute': command}
        if arguments:
            payload['arguments'] = arguments
        self.stream.write((json.dumps(payload) + '\r\n').encode())
        self.stream.flush()
        while True:
            response = json.loads(self.stream.readline())
            if 'error' in response:
                raise RuntimeError(response['error'])
            if 'return' in response:
                return response['return']

    def close(self):
        self.stream.close()
        self.socket.close()


def main():
    processes = []
    monitors = []
    streams = []
    evidence = {'acceleration': 'tcg', 'host_architecture': subprocess.check_output(['uname', '-m'], text=True).strip(), 'kvm_available': Path('/dev/kvm').exists(), 'roles': {}}
    started = time.monotonic()
    try:
        for role, upstream, vnc, udp_remote, udp_local in [('gateway', 'Whonix-Gateway', 1, 5577, 6688), ('workstation', 'Whonix-Workstation', 2, 6688, 5577)]:
            disk = BASE / (upstream + '-LXQt-18.2.1.9.Intel_AMD64.qcow2')
            overlay = Path('/run') / (role + '.qcow2')
            subprocess.run(['qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2', '-b', str(disk), str(overlay)], check=True)
            socket_path = Path('/run') / (role + '-qmp.sock')
            command = ['qemu-system-x86_64', '-accel', 'tcg,thread=multi', '-machine', 'q35', '-cpu', 'max', '-m', '2048', '-smp', '2',
                       '-display', 'none', '-vnc', '127.0.0.1:' + str(vnc), '-qmp', f'unix:{socket_path},server=on,wait=off',
                       '-serial', 'file:' + str(LOG / (role + '-serial.log')), '-device', 'virtio-vga',
                       '-drive', f'file={overlay},if=virtio,format=qcow2', '-device', 'virtio-serial-pci']
            if role == 'gateway':
                # This smoke uses QEMU user NAT, not the production passt/libvirt
                # backend; the difference is explicitly recorded in evidence.
                command += ['-netdev', 'user,id=ext0', '-device', 'virtio-net-pci,netdev=ext0,mac=52:54:00:00:00:01']
            command += ['-netdev', f'socket,id=int0,udp=127.0.0.1:{udp_remote},localaddr=127.0.0.1:{udp_local}',
                        '-device', 'virtio-net-pci,netdev=int0,mac=52:54:00:00:00:' + ('02' if role == 'gateway' else '03')]
            stream = (LOG / (role + '-qemu.log')).open('w')
            streams.append(stream)
            process = subprocess.Popen(command, stdout=stream, stderr=stream)
            processes.append(process)
            for attempt in range(100):
                if socket_path.exists():
                    break
                if process.poll() is not None:
                    raise RuntimeError(role + ' QEMU exited during startup')
                time.sleep(0.1)
            monitor = QMP(socket_path)
            monitors.append(monitor)
            evidence['roles'][role] = {'command': command, 'initial_status': monitor.command('query-status')}
        for checkpoint in (60, 180, 420):
            remaining = checkpoint - (time.monotonic() - started)
            if remaining > 0:
                time.sleep(remaining)
            for role, monitor in zip(('gateway', 'workstation'), monitors):
                screenshot = LOG / f'{role}-tcg-{checkpoint}.png'
                monitor.command('screendump', {'filename': str(screenshot), 'format': 'png'})
                evidence['roles'][role]['status_' + str(checkpoint)] = monitor.command('query-status')
                print(f'{role} TCG running at {checkpoint}s; screenshot saved', flush=True)
            (LOG / 'guest-tcg.json').write_text(json.dumps(evidence, indent=2))
        with (LOG / 'guest-browser-smoke.log').open('w') as log:
            subprocess.run(['/opt/testenv/bin/python', '-B', str(ROOT / 'tests/docker/smoke.py'), '--real-vnc'], check=True, stdout=log, stderr=log, timeout=90)
    finally:
        for monitor in monitors:
            try:
                monitor.command('system_powerdown')
            except (OSError, RuntimeError):
                pass
            monitor.close()
        # Termination only ends disposable test QEMU processes and their
        # disposable overlays. Production shutdown behavior is not claimed.
        for process in processes:
            process.terminate()
        for process in processes:
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for stream in streams:
            stream.close()


if __name__ == '__main__':
    main()
