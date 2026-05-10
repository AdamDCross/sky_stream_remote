import hashlib
import base64
import hmac
import itertools

# Data from Session 3 Log
controller_nonce = "019ce160-75fa-7e67-bb01-7e90b0ae6314"
stb_nonce = "-z!aFmy=&2R:ym:"
raw_pairing_code = " 8 0 0 0 8 8 0 8 0 8"
target_authtoken = "VfU/xkM+URrEA5TXySUVEgVnuMtbqJNKq/QgWg8ToK4="

# The UID extracted from the mTLS Client Certificate
cert_uid = "1DJ4xS3Rv9D3VJNtJq7QDqUkzxsXkZr3ry"

pairing_code_variations = {
    "raw": raw_pairing_code,
    "stripped": raw_pairing_code.strip(),
    "no_spaces": raw_pairing_code.replace(" ", "")
}

def check_hmac(key_string, message_string):
    """Creates an HMAC-SHA256 using the string as the key."""
    digest = hmac.new(key_string.encode('utf-8'), message_string.encode('utf-8'), hashlib.sha256).digest()
    return base64.b64encode(digest).decode('utf-8') == target_authtoken

def check_hash(message_string):
    """Creates a standard SHA256 hash."""
    digest = hashlib.sha256(message_string.encode('utf-8')).digest()
    return base64.b64encode(digest).decode('utf-8') == target_authtoken

print("Testing permutations with the Certificate UID...\n")
match_found = False

for pc_name, pc_val in pairing_code_variations.items():
    elements = [
        ("controller_nonce", controller_nonce),
        ("stb_nonce", stb_nonce),
        (f"pairing_code ({pc_name})", pc_val)
    ]
    
    for perm in itertools.permutations(elements):
        payload = "".join([item[1] for item in perm])
        formula_order = " + ".join([item[0] for item in perm])
        
        # Test 1: UID as the HMAC Key
        if check_hmac(cert_uid, payload):
            print(f"✅ CRACKED (HMAC)! Key=UID, Message={formula_order}")
            match_found = True
            break
            
        # Test 2: UID concatenated into a standard SHA256 hash
        # (Testing UID at the beginning and the end)
        if check_hash(cert_uid + payload):
            print(f"✅ CRACKED (SHA256)! Formula: UID + {formula_order}")
            match_found = True
            break
            
        if check_hash(payload + cert_uid):
            print(f"✅ CRACKED (SHA256)! Formula: {formula_order} + UID")
            match_found = True
            break

if not match_found:
    print("❌ No matches found using the UID.")
