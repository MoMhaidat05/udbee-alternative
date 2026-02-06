from dnslib import DNSRecord, QTYPE, DNSHeader, DNSQuestion
# تأكد أنك تستخدم fragment_message الجديدة التي تدعم struct
from message_fragmentation import fragment_message
import cvc_codec

def dns_message(message, chunk_size):
    try:
        # --- التعديل هنا: تحويل إجباري إلى بايتات ---
        if isinstance(message, str):
            # إذا وصلتنا نص (مثل مفاتيح المصافحة)، نحولها لبايتات
            message_bytes = message.encode('utf-8')
        else:
            # إذا كانت أصلاً بايتات (مثل البيانات المشفرة)، نتركها كما هي
            message_bytes = message
        # ---------------------------------------------

        # 1. التقطيع (الآن نضمن أن المدخل بايتات)
        session_id, binary_chunks = fragment_message(message_bytes, chunk_size)
        records = []
        
        for b_chunk in binary_chunks:
            # 2. استدعاء خوارزمية CVC لتحويل البايتات لدومين
            domain_name = cvc_codec.encode_packet_to_domain(b_chunk)
            
            # 3. بناء الباكت
            # Use session_id as DNS TID (single ID, no duplication)
            header = DNSHeader(id=session_id, qr=0, rd=1)
            
            q = DNSQuestion(domain_name, QTYPE.TXT)
            
            dns_packet = DNSRecord(header=header, q=q).pack()
            
            # Debug: check packet size and domain
            if len(domain_name) > 100:
                print(f"[DNS DEBUG] domain_name length: {len(domain_name)}")
                print(f"[DNS DEBUG] dns_packet length: {len(dns_packet)}")
            
            records.append(dns_packet)
        
        return records

    except Exception as e:
        print(f"Error in dns_message: {e}")
        return []