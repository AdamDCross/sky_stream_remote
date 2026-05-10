import hashlib
import base64
import hmac
import itertools
import uuid

# Session 3 Data
tid = "019ce160-75fa-7b59-80ef-16807cc01a02"
controller_nonce = "019ce160-75fa-7e67-bb01-7e90b0ae6314"
stb_nonce = "-z!aFmy=&2R:ym:"
raw_pairing_code = " 8 0 0 0 8 8 0 8 0 8"
target_authtoken = "VfU/xkM+URrEA5TXySUVEgVnuMtbqJNKq/QgWg8ToK4="

# Potential Keys
cert_uid = "1DJ4xS3Rv9D3VJNtJq7QDqUkzxsXkZr3ry"
pairing_code_stripped = raw_pairing_code.strip()

# Convert UUID strings to raw 16-byte arrays (Dart optimization)
tid_bytes = uuid.UUID(tid).bytes
nonce_bytes = uuid.UUID(controller_nonce).bytes

# Define our elements in both String format and Raw Byte format
string_elements = [
    ("tid", tid.encode('utf-8')),
    ("controllernonce", controller_nonce.encode('utf-8')),
    ("stbnonce", stb_nonce.encode('utf-8')),
    ("pairingcode", raw_pairing_code.encode('utf-8'))
]

byte_elements = [
    ("tid_raw_bytes", tid_bytes),
    ("controllernonce_raw_bytes", nonce_bytes),
    ("stbnonce", stb_nonce.encode('utf-8')),
    ("pairingcode", raw_pairing_code.encode('utf-8'))
]

def test_permutations(elements, mode_name):
    for perm in itertools.permutations(elements):
        # Concatenate the bytes in the current permutation order
        payload_bytes = b"".join([item[1] for item in perm])
        formula_order = " + ".join([item[0] for item in perm])

        # 1. Standard SHA-256
        digest = hashlib.sha256(payload_bytes).digest()
        if base64.b64encode(digest).decode('utf-8') == target_authtoken:
            return f"✅ CRACKED (SHA256)! Mode: {mode_name}\nFormula: {formula_order}"

        # 2. HMAC-SHA256 using stripped pairing code as the key
        digest = hmac.new(pairing_code_stripped.encode('utf-8'), payload_bytes, hashlib.sha256).digest()
        if base64.b64encode(digest).decode('utf-8') == target_authtoken:
            return f"✅ CRACKED (HMAC - Key=PairingCode)! Mode: {mode_name}\nFormula: {formula_order}"

        # 3. HMAC-SHA256 using Cert UID as the key
        digest = hmac.new(cert_uid.encode('utf-8'), payload_bytes, hashlib.sha256).digest()
        if base64.b64encode(digest).decode('utf-8') == target_authtoken:
            return f"✅ CRACKED (HMAC - Key=CertUID)! Mode: {mode_name}\nFormula: {formula_order}"
            
    return None

print("Starting the Ultimate Dart Brute-Force...\n")

# Test 1: Standard Strings
print("Testing String Concatenations...")
result = test_permutations(string_elements, "Standard Strings")
if result:
    print(result)
    exit()

# Test 2: Raw Byte-Packed UUIDs
print("Testing Dart Byte-Packed UUIDs...")
result = test_permutations(byte_elements, "Raw Bytes")
if result:
    print(result)
    exit()

print("\n❌ No matches found. We've exhausted standard variables and data types.")
