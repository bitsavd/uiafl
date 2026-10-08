import socket
import time

target_ip = "192.168.0.13"
target_port = 102

pkts = [
    "0300001611e00000000100c1020100c2020101c0010a",
    "0300001902f08032010000000100080000f0000001000101e0",
    "0300001f02f080320100000002000e00000401120a10020004000184000000"
]

s = socket.socket()
s.connect((target_ip, target_port))

for p in pkts:
    s.send(bytes.fromhex(p))
    try:
        data = s.recv(1024)
        print("收到:", data)
    except:
        print("无响应")
    time.sleep(0.5)

s.close()