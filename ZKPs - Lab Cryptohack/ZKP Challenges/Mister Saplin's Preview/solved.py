import socket
import hashlib
import json

# Constants
HOST = 'socket.cryptohack.org'
PORT = 13414

def sha256(data):
    return hashlib.sha256(data).digest()

def merge_nodes(a, b):
    return sha256(a + b)

def send_message(sock, message):
    sock.sendall(message.encode() + b'\n')
    response = sock.recv(4096).decode()
    return response

def request_nodes(sock, layers_needed):
    wanted_nodes = ';'.join([f"{layer},{count}" for layer, count in layers_needed.items()])
    response = send_message(sock, f'{{"option": "get_nodes", "nodes": "{wanted_nodes}"}}')
    print("Requesting nodes:", wanted_nodes)
    print("Response:", response)
    return response

def parse_nodes_response(response):
    try:
        data = json.loads(response)
        if "error" in data:
            print("Error in response:", data["error"])
            return None
        # Extract the nodes from the response
        nodes_str = data.get("msg", "[]")
        nodes = [bytes.fromhex(node) for node in nodes_str.strip("[]").replace('"', '').split(', ')]
        return nodes
    except Exception as e:
        print("Parsing error:", e)
        return None

def compute_root(nodes):
    for layer in range(len(nodes) - 1, 0, -1):
        nodes[layer - 1] = [merge_nodes(nodes[layer][i], nodes[layer][i + 1]) for i in range(0, len(nodes[layer]), 2)]
    return nodes[0][0]

def submit_proof(sock, root_hash):
    root_hex = root_hash.hex()
    response = send_message(sock, f'{{"option": "do_proof", "root": "{root_hex}"}}')
    print("Submitting proof:", root_hex)
    print("Response:", response)
    return response

def main():
    # Establish socket connection
    with socket.create_connection((HOST, PORT)) as sock:
        # Initial request to get Layer 0 nodes
        response = send_message(sock, '{"option": "get_nodes", "nodes": "0,8"}')
        print("Initial response:", response)
        nodes = parse_nodes_response(response)
        if nodes is None:
            return

        # Compute nodes for higher layers
        for layer in range(1, 3):  # 0, 1, 2 layers
            response = request_nodes(sock, {layer: len(nodes) // 2})
            nodes = parse_nodes_response(response)
            if nodes is None:
                return
        
        # Compute the root hash
        root_hash = compute_root([nodes])
        
        # Submit the proof and get the flag
        proof_response = submit_proof(sock, root_hash)
        print("Final response:", proof_response)

if __name__ == "__main__":
    main()
