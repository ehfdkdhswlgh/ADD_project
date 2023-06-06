import pyshark
from find_frequent_packet_sequences import *
from draw_graph import *


# Pcap 파일 읽기

packets = pyshark.FileCapture(
    input_file='../Pcaps/ARP_42_217_X.pcapng',
    use_json=True,
    include_raw=True,
)._packets_from_tshark_sync()
protocol_name = "ARP Protocol"


# packets = pyshark.FileCapture(
#     input_file='../Pcaps/GQUIC_Q043_1392_38_O.pcapng',
#     use_json=True,
#     include_raw=True,
# )._packets_from_tshark_sync()
# protocol_name = "GQUIC-Q043 Protocol"


# packets = pyshark.FileCapture(
#     input_file='../Pcaps/TLS_85_486_O.pcapng',
#     use_json=True,
#     include_raw=True,
# )._packets_from_tshark_sync()
# protocol_name = "TLS Protocol"


# packets = pyshark.FileCapture(
#     input_file='../Pcaps/UDP_74_183_O.pcapng',
#     use_json=True,
#     include_raw=True,
# )._packets_from_tshark_sync()
# protocol_name = "UDP Protocol"


hex_string_list = []
for packet in packets:
    hex_string = packet.frame_raw.value
    hex_string_list.append(hex_string)

print("입력 패킷의 수 : ", len(hex_string_list))
print("입력 패킷의 길이 : ", len(hex_string_list[0]))

# 빈번한 시퀀스 매개변수 설정 (길이는 비트 단위입니다)
length = 16
min_acc = 0.6
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

        # Find the starting index of "The frequent sequence" in the first packet
        first_index = indices[0]
        first_hex_string = hex_string_list[first_index]
        start_at = first_hex_string.find(seq)

        # Add the starting index to the seq_info dictionary
        seq_info["startAt"] = start_at



# Update Packet Indices and Frequency in result
update_result(hex_string_list, result)


for i in result:
    print(i)


# 빈번한 시퀀스 그래프 출력
draw_graph(hex_string_list, result, protocol_name)

print("")

