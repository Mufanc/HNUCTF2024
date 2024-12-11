from base64 import b64decode


def caesar(ciphertext, shift):
    result = []

    for ch in ciphertext:
        if ch.isalpha():
            shift_amount = shift % 26

            if ch.islower():
                start = ord('a')
            else:
                start = ord('A')

            orig = chr(start + (ord(ch) - start - shift_amount) % 26)
            result.append(orig)
        else:
            result.append(ch)

    return ''.join(result)


cipher = open('The_buddha_say.txt').read().strip()
string = b64decode(bytes(int(x, 16) for x in cipher.split())).decode()

print(caesar(string, 4))
