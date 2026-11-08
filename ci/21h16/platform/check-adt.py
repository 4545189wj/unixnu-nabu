#!/usr/bin/env python3
"""Check the nabu platform ADT taken from the CI FAT payload."""
import struct
import sys
from pathlib import Path


def read_nodes(data):
    nodes = {}

    def node(offset, parent):
        property_count, child_count = struct.unpack_from('<II', data, offset)
        offset += 8
        properties = {}
        for _ in range(property_count):
            name, length = struct.unpack_from('<32sI', data, offset)
            offset += 36
            key = name.rstrip(b'\0').decode()
            if key in properties or offset + length > len(data):
                raise ValueError(f'Invalid property {key}')
            properties[key] = data[offset:offset + length]
            offset += (length + 3) & ~3
        path = parent + '/' + properties['name'].rstrip(b'\0').decode()
        if path in nodes:
            raise ValueError(f'Duplicate node {path}')
        nodes[path] = properties
        for _ in range(child_count):
            offset = node(offset, path)
        return offset

    if node(0, '') != len(data):
        raise ValueError('Trailing bytes in ADT')
    return nodes


def main():
    adt, kernel = map(Path, sys.argv[1:])
    nodes = read_nodes(adt.read_bytes())
    root = '/device-tree'
    chosen = nodes[root + '/chosen']
    bus = root + '/arm-io'
    gic = nodes[bus + '/intc']
    _, bus_base, _ = struct.unpack('<QQQ', nodes[bus]['ranges'])
    registers = [(bus_base + offset, size) for offset, size in struct.iter_unpack('<QQ', gic['reg'])]
    assert registers == [(0x17A00000, 0x10000), (0x17A60000, 0x100000)]
    assert struct.unpack('<I', gic['virtual-timer-intid']) == (19,)
    assert struct.unpack('<Q', gic['redistributor-stride']) == (0x20000,)
    assert struct.unpack('<Q', chosen['dram-base']) == (0xC0000000,)
    assert struct.unpack('<Q', chosen['dram-size']) == (0x140000000,)
    assert struct.unpack('<Q', chosen['darwinboot-memory-size']) == (0x40000000,)
    assert 'root-matching' not in chosen
    assert nodes[root + '/psci']['method'] == b'smc\0'
    assert [key for key in nodes if key.startswith(bus + '/')] == [bus + '/intc']
    for index in range(8):
        cpu = nodes[f'{root}/cpus/cpu{index}']
        assert struct.unpack('<I', cpu['reg']) == (index * 0x100,)
        assert struct.unpack('<I', cpu['timebase-frequency']) == (19200000,)
    size = kernel.stat().st_size
    print('Nabu platform ADT verified: GICv3, timer PPI 19, eight described CPUs, 19.2 MHz, 5 GiB RAM.')
    print(f'Platform kernel size: {size} bytes ({size / (1024 * 1024):.2f} MiB).')
    if size + adt.stat().st_size >= 64 * 1024 * 1024:
        print('The kernel and ADT alone exceed the reference 64 MiB ramdisk budget.')


if __name__ == '__main__':
    main()
