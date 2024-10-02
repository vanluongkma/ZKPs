from pwn import * 
import random

# Constants (public values)
p = 0x1ed344181da88cae8dc37a08feae447ba3da7f788d271953299e5f093df7aaca987c9f653ed7e43bad576cc5d22290f61f32680736be4144642f8bea6f5bf55ef
q = 0xf69a20c0ed4465746e1bd047f57223dd1ed3fbc46938ca994cf2f849efbd5654c3e4fb29f6bf21dd6abb662e911487b0f9934039b5f20a23217c5f537adfaaf7
g = 2

# Private values (example)
w0 = 0x5a0f15a6a725003c3f65238d5f8ae4641f6bf07ebf349705b7f1feda2c2b051475e33f6747f4c8dc13cd63b9dd9f0d0dd87e27307ef262ba68d21a238be00e83

# Remote connection
nc = remote("archive.cryptohack.org", 11840)

def solve_correctness():
    # Skip initial lines
    nc.recvline()
    nc.recvline()
    
    # Send initial values for a0 and a1
    nc.sendlineafter(b'a0', b'1')
    nc.sendlineafter(b'a1', b'1')

    # Receive and parse 's'
    s = int(nc.recvline().decode().strip().split('=')[1])
    e1 = 0
    e0 = s

    # Calculate z0 and z1
    z0 = e0 * w0 % q
    z1 = 0
    
    # Send values to the server
    nc.sendlineafter(b"e0:", str(e0).encode())
    nc.sendlineafter(b"e1:", str(e1).encode())
    nc.sendlineafter(b"z0:", str(z0).encode())
    nc.sendlineafter(b"z1:", str(z1).encode())

def solve_specialSoundness():
    # Retrieve values from the server
    nc.recvuntil(b'e0 = ')
    e0 = int(nc.recvline().strip())
    nc.recvuntil(b'z0 = ')
    z0 = int(nc.recvline().strip())
    
    nc.recvuntil(b'e0* = ')
    e2 = int(nc.recvline().strip())
    nc.recvuntil(b'z0* = ')
    z2 = int(nc.recvline().strip())
    
    # Solve for witness
    try:
        diff_e = e0 - e2
        if diff_e == 0:
            raise ValueError("Zero division error")
        
        # Calculate w
        w = (z0 - z2) * pow(diff_e, -1, q) % q
        nc.sendlineafter(b'give me a witness!', str(w).encode())
    except:
        return False

    # Check response
    if b':(' in nc.recvline():
        return False
    
    return True

def solve_SHVZK():
    # Skip initial lines and retrieve values
    nc.recvline()
    y0 = int(nc.recvline().strip().decode().split('=')[1])  # Decode bytes to string
    y1 = int(nc.recvline().strip().decode().split('=')[1])  # Decode bytes to string
    s = int(nc.recvline().strip().decode().split('=')[1])   # Decode bytes to string
    
    # Generate random values
    z0, z1, e0 = [random.randint(0, q-1) for _ in range(3)]
    e1 = s ^ e0  # XOR for e1

    # Calculate a0 and a1
    a0 = pow(g, z0, p) * pow(y0, -e0, p) % p
    a1 = pow(g, z1, p) * pow(y1, -e1, p) % p
    
    # Validate assertion
    assert pow(g, z0, p) == (a0 * pow(y0, e0, p)) % p

    # Send calculated values to the server
    nc.sendlineafter(b'a0: ', str(a0).encode())
    nc.sendlineafter(b'a1: ', str(a1).encode())
    nc.sendlineafter(b'e0: ', str(e0).encode())
    nc.sendlineafter(b'e1: ', str(e1).encode())
    nc.sendlineafter(b'z0: ', str(z0).encode())
    nc.sendlineafter(b'z1: ', str(z1).encode())

# Main loop
while True:
    solve_correctness()
    if not solve_specialSoundness():
        nc.close()
        nc = remote("archive.cryptohack.org", 11840)  # Reconnect after failure
        continue
    solve_SHVZK()
    nc.interactive()
