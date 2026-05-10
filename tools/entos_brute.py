import hashlib
import base64
import itertools
import hmac

# The known variables from Row 1
controller_nonce = "019ce160-3ace-723b-b181-3c71e703ae3f"
stb_nonce = "~-B}qqry15z!FbII"
raw_pairing_code = "               0 8 8"
target_authtoken = "bOe7fehKEGfODXx1a1yld33lkRhwaMFJH/xSHggW25o="

# The pairing code might be manipulated before hashing. Let's test a few variations:
pairing_code_variations = {
    "raw": raw_pairing_code,
    "stripped": raw_pairing_code.strip(), # "0 8 8"
    "no_spaces": raw_pairing_code.replace(" ", "") # "088"
}

def check_hash(payload_string):
    """Hashes the payload with SHA-256, base64 encodes it, and checks against target."""
    digest = hashlib.sha256(payload_string.encode('utf-8')).digest()
    b64_hash = base64.b64encode(digest).decode('utf-8')
    return b64_hash == target_authtoken

def check_hmac(key, message):
    """Creates an HMAC-SHA256, base64 encodes it, and checks against target."""
    digest = hmac.new(key.encode('utf-8'), message.encode('utf-8'), hashlib.sha256).digest()
    b64_hash = base64.b64encode(digest).decode('utf-8')
    return b64_hash == target_authtoken

print("Starting brute-force of EntOS Authtoken...\n")
match_found = False

# Iterate through every variation of the pairing code
for pc_name, pc_val in pairing_code_variations.items():
    
    # Create a list of the three elements to permute
    elements = [
        ("controller_nonce", controller_nonce),
        ("stb_nonce", stb_nonce),
        (f"pairing_code ({pc_name})", pc_val)
    ]
    
    # 1. Test standard SHA-256 concatenations
    for perm in itertools.permutations(elements):
        # Join the values in the current permutation order
        payload = "".join([item[1] for item in perm])
        # Keep track of the order of the variable names for printing
        formula = " + ".join([item[0] for item in perm])
        
        if check_hash(payload):
            print(f"✅ MATCH FOUND (SHA-256)! Formula: {formula}")
            match_found = True
            break
            
    # 2. Test HMAC-SHA256 (treating the pairing code as the secret key)
    # The message is some combination of the nonces
    nonce_perms = [
        controller_nonce + stb_nonce,
        stb_nonce + controller_nonce,
        controller_nonce + ":" + stb_nonce # sometimes they are colon-separated
    ]
    
    for msg in nonce_perms:
        if check_hmac(key=pc_val, message=msg):
            print(f"✅ MATCH FOUND (HMAC-SHA256)! Key: {pc_name}, Message: {msg}")
            match_found = True
            break

if not match_found:
    print("❌ No matches found in basic permutations.")
    print("This means the handshake likely includes an unknown secret (like an App Certificate, PSK, or Diffie-Hellman derived key) mixed into the hash.")
