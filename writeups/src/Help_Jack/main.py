import wave

handle = wave.open("Miriam.wav", mode='rb')
frames = bytearray(handle.readframes(handle.getnframes()))
lsb = [int(x & 1) for x in frames][:500]

arr = []

for i in range(0, len(lsb), 8):
    ch = int(''.join(map(str, lsb[i : i + 8])), 2)
    arr.append(ch)

print(bytes(arr))