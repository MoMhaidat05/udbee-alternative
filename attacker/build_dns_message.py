from dnslib import DNSRecord, QTYPE, DNSHeader, DNSQuestion
from message_fragmentation import fragment_message
import cvc_codec

def dns_message(message, chunk_size):
    try:
        # --- التعديل الضروري للحماية ---
        # ضمان أن المدخلات هي بايتات دائماً قبل التقطيع
        if isinstance(message, str):
            message_bytes = message.encode('utf-8')
        elif isinstance(message, int):
             # حماية إضافية في حال مررنا رقماً بالخطأ
            message_bytes = str(message).encode('utf-8')
        else:
            # إذا كانت بايتات أصلاً (وهذا المتوقع من التشفير)، نتركها كما هي
            message_bytes = message
        # -------------------------------

        # 1. التقطيع (الآن نضمن أننا نمرر بايتات)
        # message_bytes هنا هي البيانات الخام الصافية
        session_id, chunks = fragment_message(message_bytes, chunk_size)
        records = []
        
        for chunk_bytes in chunks:
            # 2. استدعاء خوارزمية CVC لتحويل البايتات لدومين
            # chunk_bytes هنا هي (Obfuscated Header + Partial Data)
            domain_name = cvc_codec.encode_packet_to_domain(chunk_bytes)
            
            # 3. بناء الباكت
            # Use session_id as DNS TID (single ID, no duplication)
            header = DNSHeader(id=session_id, qr=0, rd=1)
            
            q = DNSQuestion(domain_name, QTYPE.TXT)
            
            dns_packet = DNSRecord(header=header, q=q).pack()
            records.append(dns_packet)
        
        return records
    except Exception as e:
        print(f"Error building DNS: {e}")
        return []