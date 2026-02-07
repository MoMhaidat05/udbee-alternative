import struct
from Crypto.Cipher import AES
from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Signature import DSS
from Crypto.Protocol.KDF import HKDF
from Crypto.Random import get_random_bytes

def encrypt_symmetric(message, master_key):
    try:
        if isinstance(message, str):
            message = message.encode("utf-8")
        elif not isinstance(message, bytes):
            message = str(message).encode("utf-8")
        
        msg_salt = get_random_bytes(16)
        message_key = HKDF(master_key, 32, msg_salt, SHA256)
        
        cipher = AES.new(message_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(message)
        
        header = struct.pack('!HH', len(cipher.nonce), len(tag))
        binary_payload = header + msg_salt + cipher.nonce + tag + ciphertext
        
        # [CHANGE] Return raw bytes, NO Base32
        return {"message": binary_payload, "success": True}
    except Exception as e:
        return {"message": "Failed to encrypt the message", "success": False, "error": str(e)}

def handshake_respond(victim_ephemeral_pub_pem, attacker_static_privkey):
    try:
        # Generate Ephemeral Key
        attacker_eph_key = ECC.generate(curve='P-256')
        attacker_eph_pub_pem = attacker_eph_key.public_key().export_key(format='PEM')
        
        # Import Victim Key (PEM string came from CVC decode)
        if isinstance(victim_ephemeral_pub_pem, bytes):
             victim_ephemeral_pub_pem = victim_ephemeral_pub_pem.decode('utf-8')
             
        victim_eph_pubkey = ECC.import_key(victim_ephemeral_pub_pem)
        
        # Shared Secret
        shared_point = attacker_eph_key.d * victim_eph_pubkey.pointQ
        shared_secret = int(shared_point.x).to_bytes(32, byteorder='big')
        
        # Derive Master Key
        master_key = HKDF(shared_secret, 32, b'handshake', SHA256)
        
        # Sign the Ephemeral Pub Key
        attacker_eph_pub_bytes = attacker_eph_pub_pem.encode('utf8')
        hash_msg = SHA256.new(attacker_eph_pub_bytes)
        signer = DSS.new(attacker_static_privkey, 'fips-186-3')
        signature = signer.sign(hash_msg)
        
        # Pack Payload: [Len][PubKey][Sig]
        header = struct.pack('!H', len(attacker_eph_pub_bytes))
        binary_payload = header + attacker_eph_pub_bytes + signature
        
        # [CHANGE] Return raw bytes
        return {"message": binary_payload, "master_key": master_key, "success": True}
        
    except Exception as e:
        return {"message": f"Handshake response failed: {str(e)}", "success": False}