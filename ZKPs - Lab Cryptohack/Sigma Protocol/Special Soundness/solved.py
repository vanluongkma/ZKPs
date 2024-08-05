from Crypto.Util.number import *
from sympy import mod_inverse
from pwn import *
import json

f = connect("socket.cryptohack.org", 13426, level = 'debug')
f.recvline()
msg1 = json.loads(f.recvline().decode())
a = msg1["a"]
y = msg1["y"]
print(a, y)
e1 = 1
f.sendline(json.dumps({"e": e1}))
z1 = json.loads(f.recvline().decode())["z"]
a2 = json.loads(f.recvline().decode())["a2"]

e2 = 2
f.sendline(json.dumps({"e": 2}))
z2 = json.loads(f.recvline().decode())["z2"]

p = 0x1ed344181da88cae8dc37a08feae447ba3da7f788d271953299e5f093df7aaca987c9f653ed7e43bad576cc5d22290f61f32680736be4144642f8bea6f5bf55ef
q = 0xf69a20c0ed4465746e1bd047f57223dd1ed3fbc46938ca994cf2f849efbd5654c3e4fb29f6bf21dd6abb662e911487b0f9934039b5f20a23217c5f537adfaaf7
g = 2

delta_z = (z1 - z2) % q
delta_e = (e1 - e2) % q

inv_delta_e = mod_inverse(delta_e, q)
flag = (delta_z * inv_delta_e) % q
print("Flag", long_to_bytes(flag))
