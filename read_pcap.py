from scapy.all import rdpcap, Raw
import pandas as pd

# 讀取 pcap 檔案
packets = rdpcap('multiple_packets_fixed.pcap')

data = []

# 解析封包
for packet in packets:
    if packet.haslayer(Raw):
        raw_data = packet[Raw].load.hex()
        
        # 分析主要域
        timestamp = raw_data[6:18]
        index = raw_data[24:29]
        update = raw_data[58:60]
        sign = raw_data[60:62]
        entry_type = raw_data[62:64]
        price = int(raw_data[64:74])
        volume = int(raw_data[74:82])
        level = raw_data[82:84]
        
        # 將數據方便的記錄並加入一個列表
        data.append([timestamp, index, update, sign, entry_type, price, volume, level])

# 將數據轉換成 Pandas DataFrame
columns = ['Timestamp', 'Index', 'Update', 'Sign', 'Entry Type', 'Price', 'Volume', 'Level']
df = pd.DataFrame(data, columns=columns)

# 顯示解析的數據
print(df)

# 選擇將數據寫入 CSV 檔案
df.to_csv('parsed_pcap_data.csv', index=False)