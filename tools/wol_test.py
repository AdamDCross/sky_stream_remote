#!/usr/bin/env python3
"""Send Wake-on-LAN magic packets to the Sky STB."""
import socket, time

MAC = "04:B8:6A:DE:86:A3"

mac_bytes = bytes.fromhex(MAC.replace(":", ""))
magic = b"\xff" * 6 + mac_bytes * 16

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

print(f"📡 Sending WoL to {MAC}...")
for i in range(3):
    s.sendto(magic, ("255.255.255.255", 9))
    s.sendto(magic, ("192.168.69.255", 9))
    time.sleep(0.5)

s.close()
print("✅ Done — 3 packets sent on both broadcast addresses")
