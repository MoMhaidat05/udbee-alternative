import random
import string

# --- CVC Constants ---
C_START = ['b', 'c', 'd', 'f', 'g', 'h', 'j', 'k', 'l', 'm', 'n', 'p', 'r', 's', 't', 'v', 'w', 'x', 'z']
VOWELS = ['a', 'e', 'i', 'o', 'u', 'y']
C_END = ['b', 'c', 'd', 'f', 'g', 'k', 'l', 'm', 'n', 'p', 'r', 's', 't', 'x', 'z']

# --- Domain construction ---
# Infrastructure keywords as subdomain prefix (none are valid CVC patterns)
# Safe because: 'api'/'cdn'/'www'/'auth' fail CVC vowel check,
# 'assets'/'static'/'images' are 6 chars with non-CVC triplets
INFRA_KEYWORDS = ['api', 'cdn', 'assets', 'static', 'images', 'auth', 'www']

# TLDs that are NOT valid CVC patterns (2-char or fail CVC check)
SAFE_TLDS = ['io', 'co', 'uk', 'us', 'eu', 'dev', 'app', 'org']

# Safety net: words to skip during decoding (all are non-CVC patterns)
IGNORE_WORDS = {
    'org', 'io', 'eu', 'us', 'uk', 'co', 'dev', 'app',
    'api', 'cdn', 'assets', 'static', 'images', 'auth', 'www',
}

def _value_to_syllable(value_10bit):
    """Internal: Convert 10-bit integer to CVC syllable"""
    idx_end = value_10bit % 15
    rem = value_10bit // 15
    idx_vow = rem % 6
    rem = rem // 6
    idx_start = rem % 19
    return f"{C_START[idx_start]}{VOWELS[idx_vow]}{C_END[idx_end]}"

def encode_bytes_to_domain(raw_data: bytes) -> str:
    if not raw_data: return ""
    
    # Random prefix (non-zero) at start + length byte at END
    # The random prefix makes the MSB unpredictable (varies first CVC syllable every time)
    # Length at end allows the decoder to always find it at decoded[-1]
    prefix = random.randint(1, 255)  # non-zero to preserve byte_length
    data_with_length = bytes([prefix]) + raw_data + bytes([len(raw_data)])
    
    huge_int = int.from_bytes(data_with_length, 'big')
    total_bits = len(data_with_length) * 8
    num_chunks = (total_bits + 9) // 10
    
    # Randomize MSB padding bits so the first syllable is fully random
    padding_bits = num_chunks * 10 - total_bits
    if padding_bits > 0:
        random_pad = random.randint(1 << (padding_bits - 1), (1 << padding_bits) - 1)
        huge_int |= (random_pad << total_bits)
    
    cvc_list = []
    for _ in range(num_chunks):
        chunk_val = huge_int & 0x3FF 
        cvc_list.append(_value_to_syllable(chunk_val))
        huge_int >>= 10
        
    cvc_list.reverse()
    
    # --- Dynamic label packing with hard constraints ---
    # Max 4 CVCs per label (4×3 = 12 chars, within 14-char cap)
    # Max 3 data labels (keyword + 3 data + tld = 5 labels max)
    MAX_CVC_PER_LABEL = 4
    MAX_DATA_LABELS = 3
    
    n = len(cvc_list)
    data_labels = []
    idx = 0
    labels_left = MAX_DATA_LABELS
    
    while idx < n and labels_left > 0:
        remaining_cvcs = n - idx
        if labels_left == 1:
            # Last slot: take everything remaining (capped at 4)
            take = min(remaining_cvcs, MAX_CVC_PER_LABEL)
        else:
            # Ensure remaining CVCs can still fit in remaining labels
            min_take = max(1, remaining_cvcs - (labels_left - 1) * MAX_CVC_PER_LABEL)
            max_take = min(MAX_CVC_PER_LABEL, remaining_cvcs)
            take = random.randint(min_take, max_take)
        
        label = "".join(cvc_list[idx:idx + take])
        data_labels.append(label)
        idx += take
        labels_left -= 1
    
    keyword = random.choice(INFRA_KEYWORDS)
    tld = random.choice(SAFE_TLDS)
    parts = [keyword] + data_labels + [tld]
    domain_name = ".".join(parts)

    return domain_name

# Alias
encode_packet_to_domain = encode_bytes_to_domain

def _is_valid_cvc(s: str) -> bool:
    """Check if a 3-char string is a valid CVC syllable."""
    if len(s) != 3:
        return False
    return s[0] in C_START and s[1] in VOWELS and s[2] in C_END


def decode_domain_to_bytes(domain_string: str) -> bytes:
    """
    Decodes a CVC domain back to bytes.
    Identifies data labels purely by CVC pattern matching — no delimiters needed.
    Noise labels (2-char, digits, non-CVC) are automatically filtered out.
    """
    clean_parts = domain_string.lower().split('.')
    
    syllables = []
    
    for part in clean_parts:
        # Skip ignored words (safety net)
        if part in IGNORE_WORDS:
            continue
        
        # Skip parts that aren't multiples of 3 (can't contain complete CVCs)
        if len(part) == 0 or len(part) % 3 != 0:
            continue
            
        # Extract CVC syllables from this part
        all_valid = True
        part_syllables = []
        for i in range(0, len(part), 3):
            sub = part[i:i+3]
            if _is_valid_cvc(sub) and sub not in IGNORE_WORDS:
                part_syllables.append(sub)
            else:
                all_valid = False
                break
        
        # Only include labels where ALL triplets are valid CVC
        if all_valid and part_syllables:
            syllables.extend(part_syllables)
    
    if not syllables:
        return b""

    # Reconstruct the integer from syllables
    # Syllables are in MSB-first order (encoder reversed them), so process left-to-right
    huge_int = 0
    
    for syl in syllables:  # NO reverse - domain order is already MSB first
        try:
            idx_start = C_START.index(syl[0])
            idx_vow = VOWELS.index(syl[1])
            idx_end = C_END.index(syl[2])
            val_10bit = (idx_start * 90) + (idx_vow * 15) + idx_end
            huge_int = (huge_int << 10) | val_10bit
        except ValueError:
            continue 

    # Convert integer to bytes - use minimum bytes needed (no padding)
    if huge_int == 0:
        return b""
    
    # Calculate minimum bytes needed for the integer
    byte_length = (huge_int.bit_length() + 7) // 8
    decoded_with_length = huge_int.to_bytes(byte_length, 'big')
    
    # Length byte is at the END, random prefix (+ optional padding) at the start
    if len(decoded_with_length) < 2:
        return b""
    
    original_length = decoded_with_length[-1]
    if original_length == 0 or len(decoded_with_length) < original_length + 2:
        return b""
    original_data = decoded_with_length[-(original_length + 1):-1]
    
    return original_data