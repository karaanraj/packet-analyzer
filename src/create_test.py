import struct

def write_pcap(filename):
    with open(filename, 'wb') as f:
        # Global header (24 bytes)
        f.write(struct.pack('<IHHIIII',
            0xa1b2c3d4,  # magic number
            2,           # version major
            4,           # version minor
            0,           # timezone
            0,           # timestamp accuracy
            65535,       # max packet length
            1            # ethernet
        ))

        sni = b"www.youtube.com"
        sni_len = len(sni)

        # TLS Client Hello payload
        tls_payload = bytearray()
        tls_payload += bytes([0x16, 0x03, 0x01, 0x00, 0x60])  # TLS record header
        tls_payload += bytes([0x01, 0x00, 0x00, 0x5c])         # Client Hello
        tls_payload += bytes([0x03, 0x03])                      # version
        tls_payload += bytes(32)                                 # random
        tls_payload += bytes([0x00])                             # session id len
        tls_payload += bytes([0x00, 0x02, 0x00, 0x2f])         # cipher suites
        tls_payload += bytes([0x01, 0x00])                      # compression

        # SNI extension
        sni_ext = bytearray()
        sni_ext += bytes([0x00, 0x00])                          # ext type = SNI
        sni_ext += struct.pack('>H', sni_len + 5)               # ext length
        sni_ext += struct.pack('>H', sni_len + 3)               # list length
        sni_ext += bytes([0x00])                                 # type = hostname
        sni_ext += struct.pack('>H', sni_len)                   # name length
        sni_ext += sni                                           # the domain!

        tls_payload += struct.pack('>H', len(sni_ext))          # extensions length
        tls_payload += sni_ext

        # TCP header (20 bytes)
        tcp = struct.pack('>HHIIBBHHH',
            54321,   # src port
            443,     # dst port
            0,       # seq num
            0,       # ack num
            0x50,    # data offset (5 * 4 = 20 bytes)
            0x02,    # SYN flag
            8192,    # window size
            0,       # checksum
            0        # urgent pointer
        )

        # IP header (20 bytes)
        total_len = 20 + len(tcp) + len(tls_payload)
        ip = struct.pack('>BBHHHBBH4s4s',
            0x45,                # version + header length
            0,                   # DSCP
            total_len,           # total length
            1,                   # identification
            0,                   # flags + fragment offset
            64,                  # TTL
            6,                   # protocol = TCP
            0,                   # checksum
            bytes([192,168,1,100]),    # src IP
            bytes([142,250,185,206])   # dst IP
        )

        # Ethernet header (14 bytes)
        eth = bytes([
            0xaa,0xbb,0xcc,0xdd,0xee,0xff,  # dst mac
            0x00,0x11,0x22,0x33,0x44,0x55,  # src mac
            0x08, 0x00                        # IPv4
        ])

        packet = eth + ip + tcp + bytes(tls_payload)

        # Packet record header
        f.write(struct.pack('<IIII',
            0,            # timestamp sec
            0,            # timestamp usec
            len(packet),  # captured length
            len(packet)   # original length
        ))
        f.write(packet)

    print(f"Created {filename} with SNI: www.youtube.com")

write_pcap("test.pcap")