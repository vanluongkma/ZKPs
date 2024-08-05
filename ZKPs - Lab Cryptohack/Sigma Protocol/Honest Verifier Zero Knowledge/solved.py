import json
from pwn import remote
import random


p = 0x1ed344181da88cae8dc37a08feae447ba3da7f788d271953299e5f093df7aaca987c9f653ed7e43bad576cc5d22290f61f32680736be4144642f8bea6f5bf55ef
q = 0xf69a20c0ed4465746e1bd047f57223dd1ed3fbc46938ca994cf2f849efbd5654c3e4fb29f6bf21dd6abb662e911487b0f9934039b5f20a23217c5f537adfaaf7
g = 2

f = remote('socket.cryptohack.org', 13427, level = 'debug')
f.recvline()
msg = json.loads(f.recvline().decode())
e = msg['e']
y = msg['y']
z = random.randint(1, q-1)
# Verifier checks g^z = A*h^e mod p
a = (pow(g, z, p) * pow(y, -e, p)) % p
f.sendline(json.dumps({"a": a, "z": z}))
response_data = json.loads(f.recvline().decode())
print(response_data)
f.close()
