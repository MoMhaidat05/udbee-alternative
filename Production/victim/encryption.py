import struct, base64
from Crypto.Cipher import AES
from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
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
        
        # Enforce Base32Hex Encoding
        # payload_text = base64.b32hexencode(binary_payload).rstrip(b'=').decode('utf8')
        
        return {"message": binary_payload, "success": True}
    except Exception as e:
        print(e)
        return {"message": "Failed to encrypt the message", "success": False, "error": str(e)}

def handshake_initiate():
    try:
        victim_eph_key = ECC.generate(curve='P-256')
        victim_eph_pub_pem = victim_eph_key.public_key().export_key(format='PEM')
        
        # [FIX] Changed from .hex() to base64.b32hexencode
        binary_pem = victim_eph_pub_pem.encode('utf-8')
        payload_text = base64.b32hexencode(binary_pem).rstrip(b'=').decode('utf8')
        
        return {"message": payload_text, "eph_priv_key": victim_eph_key, "success": True}
        
    except Exception as e:
        print(e)
        return {"message": f"Handshake init failed: {str(e)}", "success": False}