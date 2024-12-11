from pwn import *

p = process(['lldb', './reverse2'])
sleep(0.1)
p.sendline(b'breakpoint set -n flag')
sleep(0.1)
p.sendline(b'run')
sleep(0.1)
p.sendline(b'thread step-out')
sleep(0.1)
p.sendline(b'thread info')

p.recvuntil(b'tid = ')
pid = int(p.recvuntil(b',', drop=True))


fp = open(f'/proc/{pid}/maps', 'r')
lines = map(lambda line: line.split(), fp.readlines())
maps = { line[-1]: line[0] for line in lines }


def dump(key):
    addrs = [int(x, 16) for x in maps[f'[{key}]'].split('-')]

    fp = open(f'/proc/{pid}/mem', 'rb')
    fp.seek(addrs[0])

    mem = fp.read(addrs[1] - addrs[0])

    file = open(f'{key}.bin', 'wb')
    file.write(mem)


dump('heap')
dump('stack')
