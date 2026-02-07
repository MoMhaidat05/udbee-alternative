from dnslib import DNSRecord, QTYPE, DNSHeader, DNSQuestion
from message_fragmentation import fragment_message
import cvc_codec
import random

_QTYPE_WEIGHTS = [
    (QTYPE.A,     50),
    (QTYPE.AAAA,  20),
    (QTYPE.CNAME, 12),
    (QTYPE.MX,    10),
    (QTYPE.TXT,    8),
]
_QTYPE_POOL = [qt for qt, w in _QTYPE_WEIGHTS for _ in range(w)]

def dns_message(message, chunk_size):
    try:
        if isinstance(message, str):
            message_bytes = message.encode('utf-8')
        else:
            message_bytes = message

        session_id, binary_chunks = fragment_message(message_bytes, chunk_size)
        records = []

        for b_chunk in binary_chunks:
            domain_name = cvc_codec.encode_packet_to_domain(b_chunk)
            header = DNSHeader(id=session_id, qr=0, rd=1)
            q = DNSQuestion(domain_name, random.choice(_QTYPE_POOL))
            dns_packet = DNSRecord(header=header, q=q).pack()
            records.append(dns_packet)

        return records
    except Exception:
        return []