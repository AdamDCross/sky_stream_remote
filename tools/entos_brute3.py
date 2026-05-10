import hashlib
import base64
import hmac
import itertools

# Session 3 Data
tid = "019ce160-75fa-7b59-80ef-16807cc01a02"
controller_nonce = "019ce160-75fa-7e67-bb01-7e90b0ae6314"
stb_nonce = "-z!aFmy=&2R:ym:"
target_authtoken = "VfU/xkM+URrEA5TXySUVEgVnuMtbqJNKq/QgWg8ToK4="

# Potential Keys / Salts found in memory
keys_to_test = {
    "cert_uid": b"1DJ4xS3Rv9D3VJNtJq7QDqUkzxsXkZr3ry",
    "biT43y_salt": b"biT43y",
    "empty_key": b""  # If the pairing code was supposed to be the key, it is now empty
}

# Format 1: Standard UTF-8 Strings
tid_str = tid.encode('utf-8')
cnonce_str = controller_nonce.encode('utf-8')
stb_nonce_bytes = stb_nonce.encode('utf-8')

# Format 2: Hex-decoded raw bytes (Stripping hyphens based on the "Non-hex character" error)
tid_hex = bytes.fromhex(tid.replace("-", ""))
cnonce_hex = bytes.fromhex(controller_nonce.replace("-", ""))

# Setup the permutation lists (Pairing code is omitted because it is effectively "")
string_elements = [
    ("tid_string", tid_str),
    ("cnonce_string", cnonce_str),
    ("stbnonce_string", stb_nonce_bytes)
]

hex_elements = [
    ("tid_hex_bytes", tid_hex),
    ("cnonce_hex_bytes", cnonce_hex),
    ("stbnonce_string", stb_nonce_bytes)  # STB nonce has symbols, so it stays a string
]

def check_target(digest):
    """Encodes the digest to Base64 and checks if it matches our target authtoken."""
    return base64.b64encode(digest).decode('utf-8') == target_authtoken

def test_permutations(elements, mode_name):
    for perm in itertools.permutations(elements):
        # Join the payload based on the current permutation
        payload_bytes = b"".join([item[1] for item in perm])
        formula_order = " + ".join([item[0] for item in perm])

        # Test A: Standard SHA-256
        if check_target(hashlib.sha256(payload_bytes).digest()):
            return f"✅ CRACKED (SHA-256)! Mode: {mode_name}\nFormula: SHA256({formula_order})"

        # Test B: HMAC-SHA256 testing all potential keys
        for key_name, key_bytes in keys_to_test.items():
            if check_target(hmac.new(key_bytes, payload_bytes, hashlib.sha256).digest()):
                return f"✅ CRACKED (HMAC)! Key: {key_name} | Mode: {mode_name}\nFormula: HMAC(Key={key_name}, Message={formula_order})"

    return None

print("Starting Dart Object Pool-inspired Brute-Force...\n")

# Run the string variations
print("Testing Standard Strings (Pairing Code = Empty)...")
result = test_permutations(string_elements, "Standard Strings")
if result:
    print(result)
    exit()

# Run the hex-decoded variations
print("Testing Hex-Decoded Bytes (Pairing Code = Empty)...")
result = test_permutations(hex_elements, "Hex-Decoded Bytes")
if result:
    print(result)
    exit()

print("\n❌ Still no matches.")
