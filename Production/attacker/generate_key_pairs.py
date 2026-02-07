from Crypto.PublicKey import ECC
from log import log_success, log_error

def generate_key_pairs():
    """Generate static ECDH key pair for long-term identity"""
    # Create a new ECC key on P-256 curve (standard, secure elliptic curve)
    key = ECC.generate(curve='P-256')
    
    # Export both private and public keys in PEM format
    priv_key = key.export_key(format='PEM')
    pub_key = key.public_key().export_key(format='PEM')
    
    try:
        # Save public key - this gets sent to victim for ECDH
        with open('public_key.pem', 'wt') as file:
            file.write(pub_key)
        
        # Save private key - keep secret, used to decrypt victim's messages
        with open('private_key.pem', 'wt') as file:
            file.write(priv_key)
        
        log_success("Successfully saved private key in private_key.pem, and public key in public_key.pem, you can now initiate the tool safely!")
    except Exception as e:
        log_error(f"Failed to generate ECDH keys, error:\n{e}")