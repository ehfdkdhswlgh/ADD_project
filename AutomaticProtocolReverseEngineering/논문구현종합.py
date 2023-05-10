import pyshark
from find_frequent_packet_sequences import *
from filter_unique_sequences import *
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

# 빈번한 시퀀스 매개변수 설정
min_len = 16
max_len = 16
min_acc = 0.9
max_acc = 1.0

# 빈번한 시퀀스 구하기
result, packet_indices_dict = find_frequent_packet_sequences(hex_string_list, min_acc, max_acc, min_len, max_len)
print("찾은 빈번한 시퀀스의 수 : ", len(result))
frequent_sequences = [seq_info["The frequent sequence"] for seq_info in result]

# 빈번한 시퀀스 중복 제거
filtered_frequent_sequences = filter_unique_sequences(frequent_sequences)
filtered_result = []
for seq_info in result:
    if seq_info["The frequent sequence"] in filtered_frequent_sequences:
        seq_info["Packet Indices"] = packet_indices_dict[seq_info["The frequent sequence"]]
        filtered_result.append(seq_info)

print("필터링한 빈번한 시퀀스의 수 : ", len(filtered_result))
# print("필터링한 빈번한 시퀀스 : ", filtered_result)

#빈번한 시퀀스 간 연관관계 구하기
association_rules = find_association_rules(filtered_result)
print("찾은 연관관계의 수 : ", len(association_rules))
# print("찾은 연관관계 :", association_rules)