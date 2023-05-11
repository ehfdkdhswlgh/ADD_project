import pyshark
from find_frequent_packet_sequences import *
from find_association_rules import *


# Pcap 파일 읽기

# packets = pyshark.FileCapture(
#     input_file='../Pcaps/ARP_42_217_X.pcapng',
#     use_json=True,
#     include_raw=True,
# )._packets_from_tshark_sync()
# payload_idx = 218 # ARP (페이로드가 없으므로 항상 100%임)


# packets = pyshark.FileCapture(
#     input_file='../Pcaps/GQUIC_Q043_1392_38_O.pcapng',
#     use_json=True,
#     include_raw=True,
# )._packets_from_tshark_sync()
# payload_idx = 105 #Q043


# packets = pyshark.FileCapture(
#     input_file='../Pcaps/TLS_85_486_O.pcapng',
#     use_json=True,
#     include_raw=True,
# )._packets_from_tshark_sync()
# payload_idx = 119 # TLS


packets = pyshark.FileCapture(
    input_file='../Pcaps/UDP_74_183_O.pcapng',
    use_json=True,
    include_raw=True,
)._packets_from_tshark_sync()
payload_idx = 85 # UDP



hex_string_list = []
for packet in packets:
    hex_string = packet.frame_raw.value
    hex_string_list.append(hex_string)

print("입력 패킷의 수 : ", len(hex_string_list))

# 빈번한 시퀀스 매개변수 설정 (길이는 비트 단위입니다)
length = 16
min_acc = 0.3
max_acc = 1.0

# 빈번한 시퀀스 구하기
result, packet_indices_dict = find_frequent_packet_sequences(hex_string_list, min_acc, max_acc, length)
print("찾은 빈번한 시퀀스의 수 : ", len(result))

# 각 시퀀스의 Packet Indices 추가
for seq_info in result:
    seq_info["Packet Indices"] = packet_indices_dict[seq_info["The frequent sequence"]]


# 시퀀스를 합쳐서 긴 시퀀스를 만드는경우 빈도율이랑 패킷 인덱스가 갱신이 안되는 문제가 발생하기 때문에 이를 다시 갱신하는 작업 필요
def update_result(hex_string_list, result):
    for seq_info in result:
        seq = seq_info["The frequent sequence"]
        seq = seq.lower()
        indices = []
        count = 0
        for i, hex_string in enumerate(hex_string_list):
            if seq in hex_string:
                indices.append(i)
                count += 1
        seq_info["Packet Indices"] = indices
        seq_info["Frequency"] = f'{count / len(hex_string_list) * 100:.1f}%'


# Update Packet Indices and Frequency in result
update_result(hex_string_list, result)


#빈번한 시퀀스 간 연관관계 구하기
association_rules = find_association_rules(result)
print("찾은 연관관계의 수 : ", len(association_rules))
# print("찾은 연관관계 :", association_rules)


# 빈번한 시퀀스 성능 평가
true_count = 0
total_count = 0

for seq in result:
    packet_idx = seq["Packet Indices"][0]
    position = hex_string_list[packet_idx].find(seq["The frequent sequence"].lower())

    if position <= payload_idx:
        true_count += 1
    total_count += 1

true_ratio = (true_count / total_count) * 100
print(f"빈번한 시퀀스 정확도 : {true_ratio}%")





