import base64

key = b"H0t3lSt@ff0NlyK3epS3cr3t!"

cookie_raw = """
hotel_sess_state=HA==
hotel_sess_state=AA==
hotel_sess_state=BQ==
hotel_sess_state=Mw==
hotel_sess_state=Hg==
hotel_sess_state=ew==
hotel_sess_state=Og==
hotel_sess_state=fA==
hotel_sess_state=Fw==
hotel_sess_state=eQ==
hotel_sess_state=Ow==
hotel_sess_state=Fw==
hotel_sess_state=Pw==
hotel_sess_state=fA==
hotel_sess_state=PA==
hotel_sess_state=Kw==
hotel_sess_state=IA==
hotel_sess_state=eQ==
hotel_sess_state=Jg==
hotel_sess_state=Lw==
hotel_sess_state=Fw==
hotel_sess_state=eA==
hotel_sess_state=Pg==
hotel_sess_state=LQ==
hotel_sess_state=Gg==
hotel_sess_state=Fw==
hotel_sess_state=MQ==
hotel_sess_state=eA==
hotel_sess_state=PQ==
hotel_sess_state=NQ==
"""

decoded_chars = []

for line in cookie_raw.strip().splitlines():
    if not line.strip():
        continue
    b64_val = line.split("hotel_sess_state=")[-1].strip()
    enc_byte = base64.b64decode(b64_val)
    # The keylogger passes one character at a time, so each character is XOR'd with key[0] ('H')
    orig_char = bytes([enc_byte[0] ^ key[0]]).decode("utf-8", errors="ignore")
    decoded_chars.append(orig_char)

result = "".join(decoded_chars)
print(f"Decoded Output:\n{result}")
