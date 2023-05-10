import pyshark
from find_frequent_packet_sequences import *
from find_association_rules import *


# Pcap 파일 읽기

packets = pyshark.FileCapture(
    input_file='../Pcaps/ARP_42_217_X.pcapng',
    use_json=True,
    include_raw=True,
)._packets_from_tshark_sync()

# packets = pyshark.FileCapture(
#     input_file='../Pcaps/GQUIC_Q043_1392_41_O.pcapng',
#     use_json=True,
#     include_raw=True,
# )._packets_from_tshark_sync()

# packets = pyshark.FileCapture(
#     input_file='../Pcaps/TLS_85_486_O.pcapng',
#     use_json=True,
#     include_raw=True,
# )._packets_from_tshark_sync()

# packets = pyshark.FileCapture(
#     input_file='../Pcaps/802_11_TCP_1562_194_O.pcapng',
#     use_json=True,
#     include_raw=True,
# )._packets_from_tshark_sync()



hex_string_list = []
for packet in packets:
    hex_string = packet.frame_raw.value
    hex_string_list.append(hex_string)

print("입력 패킷의 수 : ", len(hex_string_list))

# 빈번한 시퀀스 매개변수 설정 (길이는 비트 단위입니다)
length = 16
min_acc = 0.8
max_acc = 1.0

# 빈번한 시퀀스 구하기
result, packet_indices_dict = find_frequent_packet_sequences(hex_string_list, min_acc, max_acc, length)
print("찾은 빈번한 시퀀스의 수 : ", len(result))

# 각 시퀀스의 Packet Indices 추가
for seq_info in result:
    seq_info["Packet Indices"] = packet_indices_dict[seq_info["The frequent sequence"]]


#빈번한 시퀀스 간 연관관계 구하기
association_rules = find_association_rules(result)
print("찾은 연관관계의 수 : ", len(association_rules))
# print("찾은 연관관계 :", association_rules)


# 성능 평가
for seq in result:
    packet_idx = seq["Packet Indices"][0]
    position = hex_string_list[packet_idx].find(seq["The frequent sequence"].lower())
    print(position)







