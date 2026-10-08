import snap7
from snap7.util import *

plc = snap7.client.Client()
plc.connect("192.168.0.13", 0, 1)

# 读取 DB1 的前4个字节
data = plc.db_read(1, 0, 4)

print(data)

plc.disconnect()