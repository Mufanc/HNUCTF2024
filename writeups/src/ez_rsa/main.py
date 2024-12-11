from gmpy2 import invert
from binascii import unhexlify

# 给定的参数
p = 0xED7FCFABD3C81C78E212323329DC1EE2BEB6945AB29AB51B9E3A2F9D8B0A22101E467
q = 0xAD85852F9964DA87880E48ADA5C4487480AA4023A4DE2C0321C170AD801C9
e = 65537

c = 0x863e2c635c3d0358f5a0c392ed47c9636b17179417b4549fd40d3b22d35eba77520bdee84879b3b49f734bb0d0caa2a26619d0ecaaadeab104f53ce481c919d1b4

# 计算 n 和 φ(n)
n = p * q
phi_n = (p - 1) * (q - 1)

# 计算私钥 d
d = invert(e, phi_n)

# 解密密文
m = pow(c, d, n)
plaintext = unhexlify(hex(m)[2:])

print(plaintext)
