from cryptography.hazmat.primitives import serialization
import hashlib
import base64
import hmac
import itertools

# 1. The Key Material
pem_data = b"""-----BEGIN EC PARAMETERS-----
BggqhkjOPQMBBw==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIC6SaKhxcT/GDHtglEHWdhuczo5CN9aUPqcvBt06nTNqoAoGCCqGSM49
AwEHoUQDQgAEOTYzQwBDZtPe22jtWJfqPf4FPwevN/s4pSMSVPStJvqpnM5CFFzi
p8JGCNEvGnj/9rhRy7Pw2fTkAjjDOTHspA==
-----END EC PRIVATE KEY-----"""

# Load the key and extract the 32-byte raw private scalar
private_key = serialization.load_pem_private_key(pem_data, password=None)
private_bytes = private_key.private_numbers().private_value.to_bytes(32, byteorder='big')

print(f"Extracted 32-byte private key (hex): {private_bytes.hex()}")
print("-" * 50)

# 2. The Row 1 Handshake Data
controller_nonce = "019ce160-3ace-723b-b181-3c71e703ae3f"
stb_nonce = "~-B}qqry15z!FbII"
raw_pairing_code = "               0 8 8"
target_authtoken = "bOe7fehKEGfODXx1a1yld33lkRhwaMFJH/xSHggW25o="

pairing_code_variations = {
    "raw": raw_pairing_code,
    "stripped": raw_pairing_code.strip(),
    "no_spaces": raw_pairing_code.replace(" ", "")
}

def check_hmac(key_bytes, message_string):
    """Creates an HMAC-SHA256 using raw bytes as the key."""
    digest = hmac.new(key_bytes, message_string.encode('utf-8'), hashlib.sha256).digest()
    b64_hash = base64.b64encode(digest).decode('utf-8')
    return b64_hash == target_authtoken

print("Testing HMAC-SHA256 permutations with the EC Private Key...\n")
match_found = False

# Test combinations of the three variables
for pc_name, pc_val in pairing_code_variations.items():
    elements = [
        ("controller_nonce", controller_nonce),
        ("stb_nonce", stb_nonce),
        (f"pairing_code ({pc_name})", pc_val)
    ]
    
    # Generate every possible concatenation order (e.g., A+B+C, C+A+B)
    for perm in itertools.permutations(elements):
        payload = "".join([item[1] for item in perm])
        formula = " + ".join([item[0] for item in perm])
        
        # Test using the raw private bytes as the HMAC key
        if check_hmac(private_bytes, payload):
            print(f"✅ CRACKED! Match Found!")
            print(f"Formula: HMAC-SHA256(Key=EC_Private_Bytes, Message={formula})")
            match_found = True
            break

if not match_found:
    print("❌ No matches found using the raw Private Key as the HMAC key.")
    print("\nCONCLUSION: This strongly points to an Elliptic Curve Diffie-Hellman (ECDH) key exchange.")
