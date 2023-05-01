import random
from collections import defaultdict

def bytearray_to_bin(byte_array):
    return ''.join(format(byte, '08b') for byte in byte_array)

def generate_bytearray_sequences(num_sequences, sequence_length):
    sequences = []
    for _ in range(num_sequences):
        sequence = bytearray(random.getrandbits(8) for _ in range(sequence_length))
        sequences.append(sequence)
    return sequences

def increment_counter(state_tree, sequence):
    state_tree[sequence] += 1
    return state_tree

def improved_ac_algorithm(byte_array_list, threshold, min_len, max_len):
    bit_stream_list = [bytearray_to_bin(byte_array) for byte_array in byte_array_list]
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

    supp_min = {length: (n - length + 1) / (2 ** length) * threshold for length in range(min_len, max_len + 1)}
    D = []
    seen_sequences = set()
    for sequence, count in state_tree.items():
        if count > supp_min[len(sequence)] and (count / n) * 100 >= threshold * 100:
            hex_sequence = f"0x{int(sequence, 2):0{len(sequence) // 4}X}"
            if hex_sequence not in seen_sequences:
                D.append({
                    "length": len(sequence),
                    "The frequent sequence": hex_sequence,
                    "Frequency": f"{(count / n) * 100:.1f}%",
                })
                seen_sequences.add(hex_sequence)

    return D




import pyshark
packets = pyshark.FileCapture(
            input_file='../Pcaps/ARP.pcapng',
            use_json=True,
            include_raw=True,
            display_filter="eth.dst.ig == 1",
          )._packets_from_tshark_sync()
byte_array_list = []
for packet in packets:
    hex = packet.frame_raw.value
    byte_array_list.append(bytearray.fromhex(hex))



threshold = 0.3
#0.3 : 빈도수 30% 이상
#0.8 : 빈도수 80% 이상,

min_len = 16
max_len = 200

result = improved_ac_algorithm(byte_array_list, threshold, min_len, max_len)
print("The frequent sequences set D:", len(result))














import Levenshtein

def edit_distance(x, y):
    return Levenshtein.distance(x, y)



def similarity(x, y):
    ed = edit_distance(x, y)
    length = (len(x) + len(y)) / 2
    sim = (length - ed) / length
    return sim





import concurrent.futures

def is_unique_sequence(seq, other_sequences, max_edit_distance):
    for other_seq in other_sequences:
        if seq != other_seq:
            ed = edit_distance(seq, other_seq)
            if ed <= max_edit_distance:
                return False
    return True

import functools
import bisect

def parallel_filter_sequences_by_edit_distance(sequences, max_edit_distance):
    sorted_sequences = sorted(sequences, key=len)

    filtered_sequences = []
    for seq in sorted_sequences:
        index = bisect.bisect_left(filtered_sequences, seq)
        if index == 0 or edit_distance(seq, filtered_sequences[index - 1]) > max_edit_distance:
            bisect.insort(filtered_sequences, seq)

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
max_edit_distance = 50

filtered_frequent_sequences = parallel_filter_sequences_by_edit_distance(frequent_sequences, max_edit_distance)
filtered_frequent_sequences = remove_subsequences(filtered_frequent_sequences)


filtered_result = []
for seq_info in result:
    if seq_info["The frequent sequence"] in filtered_frequent_sequences:
        filtered_result.append(seq_info)

print("Filtered frequent sequences set D:", len(filtered_result))
print("Filtered frequent sequences set D:", filtered_result)
