import base64, struct
from Crypto.Cipher import AES
from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Signature import DSS
from Crypto.Protocol.KDF import HKDF

def decrypt_symmetric(binary_payload, master_key):
    try:
        # NOTE: binary_payload is expected to be BYTES (already decoded from B32Hex by core)
        
        header_size = struct.calcsize('!HH')
        header = binary_payload[:header_size]
        len_nonce, len_tag = struct.unpack('!HH', header)
        
        salt_len = 16
        pos_salt_start = header_size
        pos_nonce_start = pos_salt_start + salt_len
        msg_salt = binary_payload[pos_salt_start:pos_nonce_start]
        
        message_key = HKDF(master_key, 32, msg_salt, SHA256)

        pos_tag_start = pos_nonce_start + len_nonce
        pos_cipher_start = pos_tag_start + len_tag
        
        nonce = binary_payload[pos_nonce_start:pos_tag_start]
        tag = binary_payload[pos_tag_start:pos_cipher_start]
        ciphertext = binary_payload[pos_cipher_start:]
        
        cipher = AES.new(message_key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        
        # Return raw bytes - let caller handle decoding/decompression
        return {"message": plaintext, "success": True}
        
    except ValueError as e:
        print(e, "decryption")
        return {"message": f"Tag verification failed {e}", "success": False}
    except Exception as e:
        print(e, "decryption")
        return {"message": "Failed to decrypt the message", "success": False, "error": str(e)}

def handshake_verify(response_payload, victim_eph_privkey, attacker_static_pubkey):
    try:
        # response_payload is bytes (decoded from B32Hex by core)
        
        header_size = struct.calcsize('!H')
        
        # [ADD] Safety check: If payload is too small, it's definitely not a handshake
        if len(response_payload) < header_size:
            return {"success": False}

        header = response_payload[:header_size]
        len_key, = struct.unpack('!H', header)
        
        pos_key_start = header_size
        pos_sig_start = pos_key_start + len_key
        
        # [ADD] Safety check: Avoid index out of range if random data arrives
        if len(response_payload) < pos_sig_start:
             return {"success": False}
        
        attacker_eph_pub_bytes = response_payload[pos_key_start:pos_sig_start]
        signature = response_payload[pos_sig_start:]
        
        # [FIX] Try decoding text. If it fails, this is NOT a handshake packet.
        try:
            attacker_eph_pub_pem = attacker_eph_pub_bytes.decode('utf8')
        except UnicodeDecodeError:
            # Silent fail: This is likely an AES encrypted command, so return False
            # to let core.py proceed to decrypt_symmetric().
            return {"success": False}

        hash_msg = SHA256.new(attacker_eph_pub_bytes)
        verifier = DSS.new(attacker_static_pubkey, 'fips-186-3')
        verifier.verify(hash_msg, signature)
        
        attacker_eph_pubkey = ECC.import_key(attacker_eph_pub_pem)
        
        shared_point = victim_eph_privkey.d * attacker_eph_pubkey.pointQ
        shared_secret = int(shared_point.x).to_bytes(32, byteorder='big')
        
        master_key = HKDF(shared_secret, 32, b'handshake', SHA256)

        return {"master_key": master_key, "success": True}

    except ValueError as e:
        # print(e, "decryption") # Optional: Keep silent on normal verification fails too
        return {"message": "Signature verification failed! (Man-in-the-Middle?)", "success": False}
    except Exception as e:
         # print(e, "decryption")
         return {"message": f"Handshake verification failed: {str(e)}", "success": False}