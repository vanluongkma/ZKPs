from py_ecc.optimized_bn128 import G1, G2, multiply, pairing
import ast

def verify_pairing(xG, yG, zG):
    """
    Verify the pairing equation.
    """
    actual_result = pairing(yG, xG)  # Calculate pairing
    return actual_result == zG  # Compare with zG

def flatten_challenge(chal):
    """
    Flatten the challenge into a list of tuples.
    """
    return [x for item in chal for x in (item,) if isinstance(item, tuple)] + [chal] if isinstance(chal, tuple) else []

def reconstruct_flag(challenges):
    """
    Reconstruct the FLAG by checking the validity of each challenge.
    """
    flag_bits = []
    
    for chal in challenges:
        # Parse the challenge safely
        try:
            # Ensure the challenge is a valid tuple
            parsed_chal = ast.literal_eval(chal)
            flat_chal = flatten_challenge(parsed_chal)  # Flatten the challenge
            if len(flat_chal) == 3:
                xG, yG, zG = flat_chal
                # Determine if the pairing holds true
                if verify_pairing(xG, yG, zG):
                    flag_bits.append('1')  # Pairing holds
                else:
                    flag_bits.append('0')  # Pairing does not hold
            else:
                print(f"Invalid challenge format (not a 3-tuple): {chal}")
        except Exception as e:
            print(f"Error parsing challenge: {chal}")
            print(f"Exception: {e}")
            continue
    
    # Convert binary string to bytes and then decode to get the FLAG
    binary_string = ''.join(flag_bits)
    try:
        # Check if binary_string is empty before conversion
        if not binary_string:
            raise ValueError("Binary string is empty.")
        
        # Convert binary string to hex and then to bytes
        flag_hex = hex(int(binary_string, 2))[2:].zfill(len(flag_bits) // 4)
        flag = bytes.fromhex(flag_hex).decode('utf-8')
    except Exception as e:
        print(f"Error converting binary string to FLAG: {binary_string}")
        print(f"Exception: {e}")
        flag = "Error"
    
    return flag

def main():
    # Read challenges from output.txt
    challenges = []
    try:
        with open("output.txt", "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    challenges.append(line)
    except Exception as e:
        print(f"Error reading output.txt: {e}")
        return

    # Reconstruct the FLAG
    flag = reconstruct_flag(challenges)
    print(f"Reconstructed FLAG: {flag}")

if __name__ == "__main__":
    main()
