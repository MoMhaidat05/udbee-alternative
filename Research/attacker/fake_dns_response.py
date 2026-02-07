"""
Fake Positive DNS Response Generator
Sends realistic DNS answers to every incoming query so firewalls see
a normal authoritative name server instead of a suspicious black hole.
"""

import random
from dnslib import DNSRecord, RR, QTYPE, A, AAAA, CNAME, MX, TXT


# ── Private-range IPv4 pools (look like internal infra, never routable) ──
_IPV4_PREFIXES = ["20.168.", "52.0.", "104.1.", "172.16.", "54.17."]

# ── Fake MX targets ──
_MX_HOSTS = [
    "mail.google.com.", "smtp.outlook.com.", "mx1.emailsrvr.com.",
    "aspmx.l.google.com.", "mail.protonmail.ch.",
]

# ── Fake CNAME / TXT values ──
_CNAME_TARGETS = [
    "cdn.cloudflare.net.", "ghs.googlehosted.com.",
    "d1234abcd.cloudfront.net.", "lb.wordpress.com.",
]
_TXT_VALUES = [
    "v=spf1 include:_spf.google.com ~all",
    "google-site-verification=abc123",
    "MS=ms12345678",
]


def _random_ipv4() -> str:
    prefix = random.choice(_IPV4_PREFIXES)
    return prefix + ".".join(str(random.randint(1, 254)) for _ in range(4 - prefix.count(".")))


def _random_ipv6() -> str:
    # Generate a realistic-looking ULA (fd00::/8) or documentation (2001:db8::/32) address
    segments = [format(random.randint(0, 0xFFFF), "04x") for _ in range(8)]
    segments[0] = random.choice(["fd00", "fd12", "2001"])
    if segments[0] == "2001":
        segments[1] = "0db8"
    return ":".join(segments)


def build_fake_response(dns_request: DNSRecord) -> bytes:
    """
    Build a standards-compliant positive DNS response that mirrors
    the incoming query's TID, QNAME and QTYPE.

    TTL is randomised between 60-300 s (typical for dynamic DNS).
    """
    ttl = random.randint(60, 300)

    # Start from the request so TID, flags, question section are correct
    reply = dns_request.reply()

    qtype = QTYPE[dns_request.q.qtype]   # e.g. "A", "AAAA", …
    qname = dns_request.q.qname           # already a DNSLabel

    if qtype == "A":
        reply.add_answer(RR(qname, QTYPE.A, ttl=ttl,
                            rdata=A(_random_ipv4())))

    elif qtype == "AAAA":
        reply.add_answer(RR(qname, QTYPE.AAAA, ttl=ttl,
                            rdata=AAAA(_random_ipv6())))

    elif qtype == "CNAME":
        reply.add_answer(RR(qname, QTYPE.CNAME, ttl=ttl,
                            rdata=CNAME(random.choice(_CNAME_TARGETS))))

    elif qtype == "MX":
        reply.add_answer(RR(qname, QTYPE.MX, ttl=ttl,
                            rdata=MX(random.choice(_MX_HOSTS))))

    elif qtype == "TXT":
        reply.add_answer(RR(qname, QTYPE.TXT, ttl=ttl,
                            rdata=TXT(random.choice(_TXT_VALUES))))

    else:
        # Fallback: answer with an A record regardless
        reply.add_answer(RR(qname, QTYPE.A, ttl=ttl,
                            rdata=A(_random_ipv4())))

    return reply.pack()
