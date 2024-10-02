from py_ecc.optimized_bn128 import G1, G2, multiply, pairing
import ast

def verify_pairing(xG, yG, zG, expected_result):
    """
    Verify the pairing equation and compare it with the expected result.
    """
    actual_result = pairing(yG, xG)
    return actual_result == zG if expected_result == 1 else actual_result != zG

def reconstruct_flag(challenges):
    """
    Reconstruct the FLAG by checking the validity of each challenge.
    """
    flag_bits = []
    
    for chal in challenges:
        # Parse the challenge safely
        try:
            xG, yG, zG = ast.literal_eval(chal)
            # Determine if the pairing holds true or false
            bit = 1 if verify_pairing(xG, yG, zG, 1) else 0
            flag_bits.append(str(bit))
        except Exception as e:
            print(f"Error parsing challenge: {chal}")
            print(f"Exception: {e}")
            continue
    
    # Convert binary string to bytes and then decode to get the FLAG
    binary_string = ''.join(flag_bits)
    try:
        flag_hex = hex(int(binary_string, 2))[2:].zfill(len(flag_bits) // 4)
        flag = bytes.fromhex(flag_hex).decode()
    except Exception as e:
        print(f"Error converting binary string to FLAG: {binary_string}")
        print(f"Exception: {e}")
        flag = "Error"
    
    return flag

def main():
    # Read challenges from output.txt
    challenges = []
    with open("output.txt", "r") as f:
        for line in f:
            line = line.strip()
            if line:
                challenges.append(line)
    
    # Reconstruct the FLAG
    flag = reconstruct_flag(challenges)
    print(f"Reconstructed FLAG: {flag}")

if __name__ == "__main__":
    main()
