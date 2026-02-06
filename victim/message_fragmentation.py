import random
import struct

def fragment_message(message_bytes, chunk_size, size_jitter=14):
    """
    Splits bytes into chunks with obfuscated binary header: [Salt][XOR'd Index][XOR'd Total][Data]
    
    - Session ID is returned separately (used as DNS Transaction ID)
    - Each chunk gets a unique random salt
    - Index and Total are XOR'd with the salt so they look different in every packet
    - size_jitter: max random reduction in data bytes per chunk (varies domain length)
    
    Returns: (session_id, chunks_list)
    """
    # Generate Session ID (will be used as DNS TID, not packed in payload)
    session_id = random.randint(0, 65535)
    
    # Header: Salt(2) + XOR'd Index(2) + XOR'd Total(2) = 6 bytes
    header_size = 6
    data_per_chunk = chunk_size - header_size
    
    if data_per_chunk <= 0:
        data_per_chunk = 1

    # Cap jitter to prevent zero-data chunks
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
        # Per-packet random salt for obfuscation
        salt = random.randint(0, 65535)
        xored_index = i ^ salt
        xored_total = total ^ salt
        
        # Pack obfuscated header (each packet looks unique)
        header = struct.pack('!HHH', salt, xored_index, xored_total)
        
        full_chunk = header + part
        chunks.append(full_chunk)
    
    return session_id, chunks