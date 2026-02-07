import secrets
import struct
import hmac
import hashlib
import random

# ---- Shared Secret (MUST match on both sides) ----
SHARED_SECRET = b'UDB33_s3cr3t_k3y_2026!'

def _derive_mask(nonce_byte: int) -> int:
    """Derive a 2-byte XOR mask from the shared secret + nonce."""
    h = hmac.new(SHARED_SECRET, bytes([nonce_byte]), hashlib.sha256).digest()
    return struct.unpack('!H', h[:2])[0]

def _compute_auth(nonce_byte: int, index: int, total: int, data: bytes) -> int:
    """Compute 1-byte auth tag: HMAC(secret, nonce||index||total||data) truncated to 1 byte.
    Covers both authenticity AND integrity (replaces separate CRC)."""
    msg = struct.pack('!BHH', nonce_byte, index, total) + data
    h = hmac.new(SHARED_SECRET, msg, hashlib.sha256).digest()
    return h[0]

def fragment_message(message_bytes, chunk_size, size_jitter=3):
    """
    Splits bytes into chunks with authenticated header:
    [Nonce(1)][Auth(1)][XOR'd Index(2)][XOR'd Total(2)] + [Data(7)]
    
    - Session ID: CSPRNG (secrets module) -- used as DNS TID
    - HMAC auth byte covers nonce+index+total+data (integrity + authenticity)
    - size_jitter: max random reduction in data bytes per chunk
    
    Returns: (session_id, chunks_list)
    """
    # CSPRNG session ID
    session_id = secrets.randbelow(65536)
    
    # Header: Nonce(1) + Auth(1) + XOR'd Index(2) + XOR'd Total(2) = 6 bytes
    header_size = 6
    data_per_chunk = chunk_size - header_size
    
    if data_per_chunk <= 0:
        raise ValueError("Chunk size too small for header")

    # Cap jitter
    max_jitter = min(size_jitter, data_per_chunk - 1)
    if max_jitter < 0:
        max_jitter = 0

    # Fragment with variable chunk sizes
    parts = []
    offset = 0
    while offset < len(message_bytes):
        jitter = random.randint(0, max_jitter)
        actual_size = data_per_chunk - jitter
        end = min(offset + actual_size, len(message_bytes))
        parts.append(message_bytes[offset:end])
        offset = end
    
    total = len(parts)
    chunks = []
    
    for i, part in enumerate(parts):
        # Per-packet random nonce (1 byte)
        nonce = secrets.randbelow(256)
        
        # Derive XOR mask from shared secret + nonce
        mask = _derive_mask(nonce)
        xored_index = i ^ mask
        xored_total = total ^ mask
        
        # Compute auth tag over header fields + data (integrity + authenticity)
        auth = _compute_auth(nonce, i, total, part)
        
        # Pack header: [Nonce(1)][Auth(1)][XOR'd Index(2)][XOR'd Total(2)]
        header = struct.pack('!BBHH', nonce, auth, xored_index, xored_total)
        
        full_chunk = header + part
        chunks.append(full_chunk)
    
    return session_id, chunks

def verify_and_unpack(raw_packet_bytes: bytes):
    """
    Verify and unpack a received chunk.
    Returns (index, total, data) on success, or None on failure.
    HMAC auth byte validates both authenticity and data integrity.
    """
    if len(raw_packet_bytes) < 7:  # 6 header + at least 1 data byte
        return None
    
    # Unpack header
    nonce, auth_received, xored_index, xored_total = struct.unpack('!BBHH', raw_packet_bytes[:6])
    
    # Derive mask and recover index/total
    mask = _derive_mask(nonce)
    index = xored_index ^ mask
    total = xored_total ^ mask
    
    # Extract data (everything after the 6-byte header)
    chunk_data = raw_packet_bytes[6:]
    
    # Verify HMAC auth tag over nonce+index+total+data (authenticity + integrity)
    expected_auth = _compute_auth(nonce, index, total, chunk_data)
    if not hmac.compare_digest(bytes([auth_received]), bytes([expected_auth])):
        return None  # Auth/integrity failed
    
    return index, total, chunk_data