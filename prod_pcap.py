from scapy.all import *
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether

import pandas as pd

# 初始化封包列表
packets = []
timestamp = '1b3241104003'
price = '0000014500'
volume = '00000010'
level = '00'
update = '30'
entry_type = '32'
sign = '30'
path = 'data'
filename = '2024-05_MXF_remain100'
df = pd.read_csv(rf'{path}/{filename}.csv', index_col=0)
print(df)

data = []

# 分析每行數據
for index, row in df.iterrows():
    print(f"Row {index+1}:")
    for i in range(1, 6):
        bid_price = row[f'bid_price_{i}']
        bid_diff = row[f'diff_bid_vol_{i}']
        ask_price = row[f'ask_price_{i}']
        ask_diff = row[f'diff_ask_vol_{i}']
        
        # 僅當 diff 不為零時才打印
        if bid_diff != 0:
            print(f"  Bid Volume Change: Price = {bid_price}, Diff = {bid_diff}")
            data.append([row[2], bid_price, bid_diff, 1])
        if ask_diff != 0:
            print(f"  Ask Volume Change: Price = {ask_price}, Diff = {ask_diff}")
            data.append([row[2], ask_price, ask_diff, -1])
    print("")  # 添加一行空白以便於閱讀

print(data)

# 生成多個封包
timestamp = '104003706000'
current_timestamp = int(timestamp, 16)
i = 0
o = 18766
for row in data:
    print(row)
    current_timestamp += 1
    final_timestamp_hex = hex(current_timestamp)[2:].zfill(12)  # 保持固定長度
    print(final_timestamp_hex)
    index = "{:05d}".format(o + i)
    
    # 格式化價格和數量
    price = "{:010d}".format(int(row[1]))
    volume = "{:08d}".format(int(abs(row[2])))
    
    level = '00'
    update = '30'
    entry_type = '30'
    sign = '31' if row[3] == 1 else '32'
    
    # 創建 Ethernet 層
    eth = Ether(dst="01:00:5e:00:8c:8c", src="5c:45:27:79:f2:5a", type=0x0800)
    eth.time = 0  # 設置時間戳為0
    
    # 創建 IP 層
    ip = IP(src="192.168.56.126", dst="225.0.140.140", version=4, ihl=5, ttl=62, proto='udp')
    
    # 創建 UDP 層
    udp = UDP(sport=52919, dport=14000)

    # 創建 Raw 資料層
    hex_data = f'1b3241{final_timestamp_hex}000100034{index}0100394d4b464430202020202020202020202020202020000005414201{update}{sign}{entry_type}{price}{volume}{level}cb0d0a'
    print(hex_data)
    raw_load = bytes.fromhex(hex_data)
    raw = Raw(load=raw_load)
    
    # 組合封包
    packet = eth / ip / udp / raw

    # 顯示封包結構供註解
    packet.show()
    print("Packet Length:", len(packet))
    
    # 添加到列表中
    packets.append(packet)

    i += 1

# 寫入封包到 pcap 檔案
wrpcap('multiple_packets_fixed.pcap', packets)