from collections import defaultdict
import pyshark
import Levenshtein


packets = pyshark.FileCapture(
    input_file='../Pcaps/ARP.pcapng',
    use_json=True,
    include_raw=True,
    display_filter="eth.dst.ig == 1",  # 브로드캐스트 패킷
)._packets_from_tshark_sync()
hex_string_list = []
for packet in packets:
    hex_string = packet.frame_raw.value
    hex_string_list.append(hex_string)

print("입력 패킷의 수")
print(len(hex_string_list))




def bytearray_to_bin(byte_array):
    return ''.join(format(byte, '08b') for byte in byte_array)

def increment_counter(state_tree, sequence):
    state_tree[sequence] += 1
    return state_tree

def improved_ac_algorithm(hex_string_list, min_acc, max_acc, min_len, max_len):
    bit_stream_list = [bytearray_to_bin(bytearray.fromhex(hex_string)) for hex_string in hex_string_list]
    n = len(bit_stream_list)
    state_tree = defaultdict(int)

    for bit_stream in bit_stream_list:
        local_state_tree = defaultdict(int)
        for length in range(min_len, min(max_len + 1, len(bit_stream) + 1)):
            for i in range(len(bit_stream) - length + 1):
                sequence = bit_stream[i:i + length]
                increment_counter(local_state_tree, sequence)
        for sequence, count in local_state_tree.items():
            if count > 0:
                state_tree[sequence] += 1

    supp_min = {length: (n - length + 1) / (2 ** length) * min_acc for length in range(min_len, max_len + 1)}
    D = []
    seen_sequences = set()
    for sequence, count in state_tree.items():
        freq_percentage = (count / n) * 100
        if count > supp_min[len(sequence)] and min_acc * 100 <= freq_percentage <= max_acc * 100:
            hex_sequence = f"{int(sequence, 2):0{len(sequence) // 4}X}"
            if hex_sequence not in seen_sequences:
                D.append({
                    "length": len(sequence),
                    "The frequent sequence": hex_sequence,
                    "Frequency": f"{freq_percentage:.1f}%",
                })
                seen_sequences.add(hex_sequence)

    return D


min_len = 16
max_len = 160
min_acc = 0.7
max_acc = 0.75

result = improved_ac_algorithm(hex_string_list, min_acc, max_acc, min_len, max_len)
print("The frequent sequences set D:", len(result))


def edit_distance(x, y):
    return Levenshtein.distance(x, y)

def similarity(x, y):
    ed = edit_distance(x, y)
    length = (len(x) + len(y)) / 2
    sim = (length - ed) / length
    return sim

def is_unique_sequence(seq, other_sequences, max_edit_distance):
    for other_seq in other_sequences:
        if seq != other_seq:
            ed = edit_distance(seq, other_seq)
            if ed <= max_edit_distance:
                return False
    return True

def parallel_filter_sequences_by_edit_distance(sequences, max_edit_distance):
    sorted_sequences = sorted(sequences, key=len)

    filtered_sequences = []
    for seq in sorted_sequences:
        is_unique = True
        for other_seq in filtered_sequences:
            ed = edit_distance(seq, other_seq)
            if ed <= max_edit_distance:
                is_unique = False
                break
        if is_unique:
            filtered_sequences.append(seq)

    return filtered_sequences


def remove_subsequences(sequences):
    sequences = sorted(sequences, key=lambda x: len(x))
    filtered_sequences = []

    for seq in sequences:
        is_subsequence = False
        for longer_seq in filtered_sequences:
            if seq in longer_seq:
                is_subsequence = True
                break
        if not is_subsequence:
            filtered_sequences.append(seq)

    return filtered_sequences

# improved_ac_algorithm 결과값인 result를 사용합니다.
frequent_sequences = [seq_info["The frequent sequence"] for seq_info in result]

# 필터링할 때 최대 허용 편집 거리를 설정합니다.
max_edit_distance = 5

filtered_frequent_sequences = parallel_filter_sequences_by_edit_distance(frequent_sequences, max_edit_distance)
filtered_frequent_sequences = remove_subsequences(filtered_frequent_sequences)

filtered_result = []
for seq_info in result:
    if seq_info["The frequent sequence"] in filtered_frequent_sequences:
        filtered_result.append(seq_info)

print("Filtered frequent sequences set D:", len(filtered_result))
print("Filtered frequent sequences set D:", filtered_result)





from itertools import chain, combinations

def find_packets_with_sequence(hex_string_list, sequence):
    return [packet for packet in hex_string_list if sequence in packet]

def find_relationships(filtered_frequent_sequences, hex_string_list):
    sequence_packets = {seq: find_packets_with_sequence(hex_string_list, seq) for seq in filtered_frequent_sequences}

    relationships = []

    for seq, packets in sequence_packets.items():
        for other_seq, other_packets in sequence_packets.items():
            if seq != other_seq:
                if set(packets) <= set(other_packets):
                    relationships.append(f"{seq} ⇒ {other_seq}")

    for seq_comb in chain.from_iterable(combinations(filtered_frequent_sequences, r) for r in range(2, len(filtered_frequent_sequences) + 1)):
        intersection = set.intersection(*(set(sequence_packets[seq]) for seq in seq_comb))
        for seq, packets in sequence_packets.items():
            if seq not in seq_comb and intersection <= set(packets):
                relationships.append(f"{','.join(seq_comb)} ⇒ {seq}")

    return relationships

relationships = find_relationships(filtered_frequent_sequences, hex_string_list)
print(relationships)
