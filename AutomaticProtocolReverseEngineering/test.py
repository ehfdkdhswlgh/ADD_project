import pyshark
from find_frequent_packet_sequences import *
from draw_graph import *
import math

# packets = pyshark.FileCapture(
#     input_file='../Pcaps/ARP_42_217_X.pcapng',
#     use_json=True,
#     include_raw=True,
# )._packets_from_tshark_sync()
# protocol_name = "ARP Protocol"
#
# packets = pyshark.FileCapture(
#     input_file='../Pcaps/TLS_85_486_O.pcapng',
#     use_json=True,
#     include_raw=True,
# )._packets_from_tshark_sync()
# protocol_name = "TLS Protocol"
#
#
# packets = pyshark.FileCapture(
#     input_file='../Pcaps/ANCP_88_24.pcapng',
#     use_json=True,
#     include_raw=True,
# )._packets_from_tshark_sync()
# protocol_name = "ANCP Protocol"
#
#
# packets = pyshark.FileCapture(
#     input_file='../Pcaps/BGP_85_60.pcapng',
#     use_json=True,
#     include_raw=True,
# )._packets_from_tshark_sync()
# protocol_name = "BGP Protocol"
#
#
# packets = pyshark.FileCapture(
#     input_file='../Pcaps/SMB_88_24.pcapng',
#     use_json=True,
#     include_raw=True,
# )._packets_from_tshark_sync()
# protocol_name = "SMB Protocol"
#
# packets = pyshark.FileCapture(
#     input_file='../Pcaps/MANOLITOProtocol(SearchQuery)_81_605.pcapng',
#     use_json=True,
#     include_raw=True,
# )._packets_from_tshark_sync()
# protocol_name = "MANOLITO Protocol(SearchQuery)"
#
# packets = pyshark.FileCapture(
#     input_file='../Pcaps/MANOLITOProtocol(Ping)_61_144.pcapng',
#     use_json=True,
#     include_raw=True,
# )._packets_from_tshark_sync()
# protocol_name = "MANOLITO Protocol(Ping)"

packets = pyshark.FileCapture(
    input_file='./tcppackets.pcap',
    use_json=True,
    include_raw=True,
)._packets_from_tshark_sync()
protocol_name = "TCP Protocol"



hex_string_list = []
for index, packet in enumerate(packets): # 속도가 너무 느려 100개만 사용
    # if index >= 100:
    #     break
    hex_string = packet.frame_raw.value
    hex_string_list.append(hex_string)



# hex_string_list에서 10%의 위치를 계산합니다.
split_index = math.ceil(len(hex_string_list) * 0.1)

# 리스트를 두 부분으로 분리합니다.
tmp_hex_string_list = hex_string_list[:split_index] # 총 데이터셋의 10% 저장
hex_string_list = hex_string_list[split_index:] # 총 데이터셋의 90% 저장

















from collections import defaultdict

def find_frequent_packet_sequences(hex_string_list, min_acc, max_acc, length):
    bit_stream_list = [bytearray_to_bin(bytearray.fromhex(hex_string)) for hex_string in hex_string_list]
    n = len(bit_stream_list)
    state_tree = defaultdict(int)

    for bit_stream in bit_stream_list:
        local_state_tree = defaultdict(int)
        for i in range(len(bit_stream) - length + 1):
            sequence = bit_stream[i:i + length]
            increment_counter(local_state_tree, sequence)
        for sequence, count in local_state_tree.items():
            if count > 0:
                state_tree[sequence] += 1

    # supp_min = (n - length + 1) / (2 ** length) * min_acc
    D = []
    seen_sequences = set()

    # Initialize a dictionary to store the indices of packets containing each frequent sequence
    packet_indices_dict = defaultdict(list)

    for sequence, count in state_tree.items():
        hex_sequence = f"{int(sequence, 2):0{length // 4}X}"
        if hex_sequence not in seen_sequences:
            # Find the indices of packets containing the frequent sequence
            packet_indices = [i for i, hex_string in enumerate(hex_string_list) if hex_sequence.lower() in hex_string.lower()]
            packet_indices_dict[hex_sequence] = packet_indices

            # Calculate the new frequency percentage based on the actual packet occurrences
            freq_percentage = (len(packet_indices) / n) * 100
            if min_acc * 100 <= freq_percentage <= max_acc * 100:
                # Check if the current sequence can be merged with the previous sequence
                if D and can_be_merged(D[-1]["The frequent sequence"], hex_sequence, hex_string_list):
                    merged_sequence = merge_sequences(D[-1]["The frequent sequence"], hex_sequence)
                    D[-1]["The frequent sequence"] = merged_sequence
                    D[-1]["length"] = len(merged_sequence) * 4
                    # Update Packet Indices for the merged sequence
                    D[-1]["Packet Indices"] = list(set(D[-1]["Packet Indices"]).union(packet_indices))
                else:
                    D.append({
                        "length": length,
                        "The frequent sequence": hex_sequence,
                        "Frequency": f"{freq_percentage:.1f}%",
                        "Packet Indices": packet_indices,
                    })
                seen_sequences.add(hex_sequence)

    return D, packet_indices_dict


def can_be_merged(prev_sequence, curr_sequence, hex_string_list):
    merged_sequence = merge_sequences(prev_sequence, curr_sequence)
    merged_count = sum(1 for hex_string in hex_string_list if merged_sequence.lower() in hex_string.lower())

    prev_count = sum(1 for hex_string in hex_string_list if prev_sequence.lower() in hex_string.lower())
    curr_count = sum(1 for hex_string in hex_string_list if curr_sequence.lower() in hex_string.lower())

    n = len(hex_string_list)
    merged_freq = (merged_count / n) * 100
    prev_freq = (prev_count / n) * 100
    curr_freq = (curr_count / n) * 100

    return prev_freq >= merged_freq >= curr_freq


def merge_sequences(seq1, seq2):
    overlap = 0
    for i in range(len(seq1)):
        if seq1[i:] == seq2[:len(seq1) - i]:
            overlap = len(seq1) - i
            break
    return seq1 + seq2[overlap:]


def bytearray_to_bin(byte_array):
    return ''.join(format(byte, '08b') for byte in byte_array)


def increment_counter(state_tree, sequence):
    state_tree[sequence] += 1
    return state_tree

print("입력 프레임의 수 : ", len(hex_string_list))
print("입력 프레임의 길이 : ", len(hex_string_list[0]))


def find_all_frequent_packet_sequences(hex_string_list, min_acc, max_acc, lengths):
    all_results = []
    all_packet_indices_dict = {}
    for length in lengths:
        result, packet_indices_dict = find_frequent_packet_sequences(hex_string_list, min_acc, max_acc, length)
        all_results.extend(result)
        all_packet_indices_dict.update(packet_indices_dict)

    return all_results, all_packet_indices_dict



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


def filter_sequences(result):
    # Group sequences by 'startAt' and 'Frequency'
    groups = defaultdict(list)
    for seq_info in result:
        key = (seq_info['startAt'], seq_info['Frequency'])
        groups[key].append(seq_info)

    # Select the sequence with the longest length from each group
    filtered_result = []
    for group in groups.values():
        longest_seq = max(group, key=lambda x: x['length'])
        filtered_result.append(longest_seq)

    return filtered_result


def filter_same_suffix_and_frequency(result):
    # Group sequences by the last 4 digits and 'Frequency'
    groups = defaultdict(list)
    for seq_info in result:
        # Extract the last 4 digits from 'The frequent sequence'
        last_four_digits = seq_info['The frequent sequence'][-4:]
        key = (last_four_digits, seq_info['Frequency'])
        groups[key].append(seq_info)

    # Select the sequence with the longest length from each group
    filtered_result = []
    for group in groups.values():
        longest_seq = max(group, key=lambda x: x['length'])
        filtered_result.append(longest_seq)

    return filtered_result


def filter_subset_sequences(result):
    # Create a list to hold the final results
    filtered_result = []

    # Sort the sequences in descending order of length
    sorted_result = sorted(result, key=lambda x: x['length'], reverse=True)

    for i, seq_info in enumerate(sorted_result):
        # Get the current sequence and frequency
        curr_sequence = seq_info['The frequent sequence']
        curr_freq = seq_info['Frequency']

        # Check if the current sequence is a subset of any longer sequence with the same frequency
        if not any(curr_sequence in other['The frequent sequence'] and curr_freq == other['Frequency'] for other in sorted_result[:i]):
            # If not, add the current sequence to the filtered results
            filtered_result.append(seq_info)

    return filtered_result







#빈도율 30%으로 실행  (페이로드 구분용!!)

# 인조 TCP 같은경우 실제로 173위치부터 페이로드 시작함 (주의 : 패킷 제네레이터 돌릴때마다 값이 달라질 수 있음!!)
tmp_min_acc = 0.3
tmp_max_acc = 1.0

tmp_lengths = [16,20,24,28,32,36,40,44,48,52,56,60]  # 최소길이 ~ 최대길이
tmp_result, tmp_packet_indices_dict = find_all_frequent_packet_sequences(tmp_hex_string_list, tmp_min_acc, tmp_max_acc, tmp_lengths)
update_result(tmp_hex_string_list, tmp_result)

tmp_filtered_result = filter_sequences(tmp_result)
tmp_filtered_result = filter_same_suffix_and_frequency(tmp_filtered_result)
tmp_filtered_result = filter_subset_sequences(tmp_filtered_result)


payload_startAt = 0

for i in tmp_filtered_result:
    if(i["startAt"] + (i["length"] / 4) > payload_startAt):
        payload_startAt = i["startAt"] + (i["length"] / 4)

payload_startAt = int(payload_startAt)

if payload_startAt % 2 == 0:
    payload_startAt = payload_startAt + 1

print("페이로드 시작점 : ", payload_startAt)


hex_string_list = [s[:payload_startAt - 1] for s in hex_string_list]







#페이로드 제거한 영역으로 실행

min_acc = 0.5
max_acc = 1.0

lengths = [8,12,16,20,24,28,32,36,40,44,48]  # 최소길이 ~ 최대길이
result, packet_indices_dict = find_all_frequent_packet_sequences(hex_string_list, min_acc, max_acc, lengths)
update_result(hex_string_list, result)

min_acc2 = 0.6
max_acc2 = 1.0
result2, packet_indices_dict2 = find_all_frequent_packet_sequences(hex_string_list, min_acc2, max_acc2, lengths)
update_result(hex_string_list, result2)

sum_result = result2 + result




filtered_result = filter_sequences(sum_result)
filtered_result = filter_same_suffix_and_frequency(filtered_result)
filtered_result = filter_subset_sequences(filtered_result)





for i in filtered_result:
    print(i["The frequent sequence"] + ", Frequency : " + i["Frequency"] + ", startAt : " + str(i["startAt"]))


def draw_graph(hex_string_list, filtered_result, protocol_name):
    # 가로축과 세로축의 크기 설정
    width = len(hex_string_list[0])
    height = len(hex_string_list)

    # 그래프를 흰색으로 초기화
    graph = np.ones((height, width, 3))

    # 모든 가능한 색상을 가져와서 랜덤하게 섞기. 흰색과 가까운 색은 제외
    white_rgb = np.array([1, 1, 1])
    threshold = 0.7  # 이 값은 흰색에 가까운 색상을 어느 정도로 정의할 것인지를 결정. 값이 작을수록 흰색에 더 가까운 색상을 제외.
    all_colors = [color for color in mcolors.CSS4_COLORS.keys()
                  if np.linalg.norm(white_rgb - np.array(mcolors.to_rgb(color))) > threshold]
    random.shuffle(all_colors)

    # 빈번한 시퀀스를 그래프에 색칠하기
    for seq_num, seq_info in enumerate(filtered_result):
        # 빈번한 시퀀스마다 랜덤한 색상 선택
        color = mcolors.to_rgb(all_colors[seq_num % len(all_colors)])

        length = (seq_info["length"] // 4) - 1
        for packet_idx in seq_info["Packet Indices"]:
            start_at = seq_info["startAt"]
            end_at = start_at + length

            for pos in range(start_at, end_at):
                graph[packet_idx, pos] = color  # 랜덤 색상으로 칠하기

    # 그래프 출력
    plt.imshow(graph, aspect='auto')
    plt.xlabel('Frame Length')
    plt.ylabel('Frame Index')
    plt.title(protocol_name)
    plt.show()

draw_graph(hex_string_list, filtered_result, protocol_name)

