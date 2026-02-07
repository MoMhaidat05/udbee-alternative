from message_fragmentation import fragment_message
import cvc_codec

message = "hello from mohammad!".encode('utf-8')

session_id, chunks = fragment_message(message, 17)

arr = []
for chunk in chunks:
    domain_name = cvc_codec.encode_packet_to_domain(chunk)
    arr.append(domain_name)

print(arr)
