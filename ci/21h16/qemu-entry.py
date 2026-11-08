#!/usr/bin/env python3
"""Check that QEMU translates the audited XNU candidate's physical entry."""
import argparse
from pathlib import Path
import re
import runpy
import shutil
import subprocess
import sys

ENTRY = re.compile(r'DARWINBOOT: ARM64 .*?\bentry=0x([a-fA-F0-9]+)')
HANDOFF = 'DARWINBOOT: inputs validated; exiting boot services'


def verify_entry(serial, trace):
    handoff = serial.find(HANDOFF)
    entries = list(ENTRY.finditer(serial, 0, handoff)) if handoff >= 0 else []
    if not entries:
        raise ValueError('DarwinBoot did not report a validated handoff')
    entry = int(entries[-1][1], 16)
    instruction = re.compile(rf'^\s*0x0*{entry:x}:\s+[0-9a-f]+\b', re.I)
    with trace.open(errors='replace') as lines:
        if not any(instruction.search(line) for line in lines):
            raise ValueError(f'QEMU trace did not reach the physical entry at {entry:#x}')
    return entry


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--core', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    esp = output / 'esp'
    boot = esp / 'EFI/BOOT'
    payloads = esp / 'EFI/UniXNU/Payloads'
    for directory in (boot, payloads):
        directory.mkdir(parents=True)
    shutil.copyfile(args.work / 'package/Build/Out/AARCH64-DEBUG/UniXNU.efi', boot / 'BOOTAA64.EFI')
    shutil.copyfile(args.work / 'tree/build/DarwinBoot/DEBUG_CLANGPDB/AARCH64/DarwinBoot.efi',
                    payloads / 'DarwinBoot.efi')
    shutil.copyfile(args.work / 'kernel/kernel.macho', payloads / 'kernel.macho')
    subprocess.run([sys.executable, args.core / 'scripts/qemu-entry/make-dt.py',
                    '--armvirt', '--armcpu', '--smp', '2', '--dram-size', '0x40000000',
                    '--owned-memory-size', '0x20000000',
                    '--output', payloads / 'kernel.macho.adt'], check=True)
    (payloads.parent / 'unixnu.toml').write_text('''version = 1
[boot]
timeout = 2
default = "xnu"
[kits]
autoload = false
[[driver]]
path = "Payloads/DarwinBoot.efi"
[[entry]]
id = "xnu"
title = "21H16 XNU entry fixture"
type = "xnu"
path = "Payloads/kernel.macho"
args = "-v serial=3 cpus=2"
''')
    qemu = shutil.which('qemu-system-aarch64')
    if not qemu:
        raise SystemExit('qemu-system-aarch64 is missing')
    helpers = runpy.run_path(str(args.core / 'package/Scripts/qemu-run.py'))
    firmware, vars_template = helpers['find_firmware'](None)
    serial, trace = output / 'serial.log', output / 'instructions.log'
    command = [qemu, '-accel', 'tcg', '-M', 'virt,gic-version=3', '-cpu', 'cortex-a72',
               '-m', '1024', '-smp', '2', '-drive',
               f'if=pflash,format=raw,readonly=on,file={firmware}']
    if vars_template:
        variables = output / 'vars.fd'
        shutil.copyfile(vars_template, variables)
        command += ['-drive', f'if=pflash,format=raw,file={variables}']
    command += ['-drive', f'if=none,id=esp,format=raw,readonly=on,file=fat:{esp}',
                '-device', 'virtio-blk-pci,drive=esp', '-device', 'ramfb',
                '-nic', 'none', '-display', 'none', '-monitor', 'none', '-no-reboot',
                '-serial', f'file:{serial}', '-d', 'in_asm', '-D', str(trace)]
    try:
        subprocess.run(command, timeout=90, check=True)
    except subprocess.TimeoutExpired:
        pass
    log = helpers['ANSI'].sub('', serial.read_text(errors='replace'))
    try:
        entry = verify_entry(log, trace)
    except ValueError as error:
        print('\n'.join(log.splitlines()[-35:]), file=sys.stderr)
        raise SystemExit(str(error)) from error
    print(f'QEMU reached the audited 21H16 XNU physical entry at {entry:#x}.')


if __name__ == '__main__':
    main()
