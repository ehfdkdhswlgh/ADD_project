from collections import defaultdict
import matplotlib.ticker as ticker
import numpy as np
from matplotlib import colors as mcolors
import matplotlib.pyplot as plt
import random
import math

# 사용자 설정 매개 변수
payload_min_acc = 0.33
payload_max_acc = 1.0
payload_lengths = [16,20,24,28,32,36,40,44,48,52,56,60]  # 최소길이 ~ 최대길이

min_acc = 0.5
max_acc = 1.0
min_acc2 = 0.6
max_acc2 = 1.0
lengths = [8,12,16,20,24,28,32,36,40,44,48]


def find_frequent_sequence_algorithm(hex_string_list):
    result, packet_indices_dict = find_all_frequent_packet_sequences(hex_string_list, min_acc, max_acc, lengths)
    update_result(hex_string_list, result)
    result2, packet_indices_dict2 = find_all_frequent_packet_sequences(hex_string_list, min_acc2, max_acc2, lengths)
    update_result(hex_string_list, result2)

    sum_result = result2 + result

    filtered_result = sum_result;
    filtered_result = filter_sequences(sum_result)
    filtered_result = filter_same_suffix_and_frequency(filtered_result)
    filtered_result = filter_subset_sequences(filtered_result)

    filtered_result.sort(key=lambda x: (x['startAt'], -float(x['Frequency'][:-1])))

    # Group data based on length and frequency
    groups = {}
    for item in filtered_result:
        key = (item['length'], item['Frequency'])
        if key not in groups:
            groups[key] = []
        groups[key].append(item)

    # Process groups according to your criteria
    result = []
    for key, group in groups.items():
        if group[0]['Frequency'] == '100.0%':
            group.sort(key=lambda x: x['startAt'])
            sequence = group[0]['The frequent sequence']
            for i in range(1, len(group)):
                if group[i]['startAt'] == group[i - 1]['startAt'] + 1:
                    sequence += group[i]['The frequent sequence'][-1]
            result.append({
                'length': len(sequence) * 4,
                'The frequent sequence': sequence,
                'Frequency': group[0]['Frequency'],
                'startAt': group[0]['startAt'],
                'Packet Indices': group[0]['Packet Indices'],
            })
        else:
            result.append(min(group, key=lambda x: x['startAt']))

    for i in result:
        print(i["The frequent sequence"] + ", Frequency : " + i["Frequency"] + ", startAt : " + str(i["startAt"]))

    draw_graph(hex_string_list, result)


def identify_payload_area(hex_string_list_10, hex_string_list):
    payload_result, payload_packet_indices_dict = find_all_frequent_packet_sequences_for_payload(hex_string_list_10, payload_min_acc, payload_max_acc, payload_lengths)
    update_result(hex_string_list_10, payload_result)

    payload_filtered_result = filter_sequences(payload_result)
    payload_filtered_result = filter_same_suffix_and_frequency(payload_filtered_result)
    payload_filtered_result = filter_subset_sequences(payload_filtered_result)

    payload_startAt = 0

    for i in payload_filtered_result:
        if (i["startAt"] + (i["length"] / 4) > payload_startAt):
            payload_startAt = i["startAt"] + (i["length"] / 4)

    payload_startAt = int(payload_startAt)

    # draw_graph(hex_string_list[:20], payload_filtered_result)

    if payload_startAt % 2 == 0:
        payload_startAt = payload_startAt + 1

    if (payload_startAt >= len(hex_string_list[0])):
        print("\n<< 페이로드 영역이 없는 것으로 추정됨 >>\n")
    else:
        print("\n<< 페이로드 추정 시작점 : ", payload_startAt, " >>\n")
        hex_string_list = [s[:payload_startAt + 1] for s in hex_string_list]


    return payload_startAt, hex_string_list



def split_frames(hex_string_list):
    split_index = math.ceil(len(hex_string_list) * 0.1)

    hex_string_list_10 = hex_string_list[:split_index]

    return hex_string_list_10


def find_frequent_packet_sequences_for_payload(hex_string_list, min_acc, max_acc, length):
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

    D = []
    seen_sequences = set()

    packet_indices_dict = defaultdict(list)

    for sequence, count in state_tree.items():
        hex_sequence = f"{int(sequence, 2):0{length // 4}X}"
        if hex_sequence not in seen_sequences:

            packet_indices = [i for i, hex_string in enumerate(hex_string_list) if hex_sequence.lower() in hex_string.lower()]
            packet_indices_dict[hex_sequence] = packet_indices


            freq_percentage = (len(packet_indices) / n) * 100
            if min_acc * 100 <= freq_percentage <= max_acc * 100:

                if D and can_be_merged(D[-1]["The frequent sequence"], hex_sequence, hex_string_list):
                    merged_sequence = merge_sequences(D[-1]["The frequent sequence"], hex_sequence)
                    D[-1]["The frequent sequence"] = merged_sequence
                    D[-1]["length"] = len(merged_sequence) * 4

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

    D = []
    seen_sequences = set()


    packet_indices_dict = defaultdict(list)

    for sequence, count in state_tree.items():
        hex_sequence = f"{int(sequence, 2):0{length // 4}X}"
        if hex_sequence not in seen_sequences:

            packet_indices = [i for i, hex_string in enumerate(hex_string_list) if hex_sequence.lower() in hex_string.lower()]
            packet_indices_dict[hex_sequence] = packet_indices


            freq_percentage = (len(packet_indices) / n) * 100
            if min_acc * 100 <= freq_percentage <= max_acc * 100:
                D.append({
                    "length": length,
                    "The frequent sequence": hex_sequence,
                    "Frequency": f"{freq_percentage:.1f}%",
                    "Packet Indices": packet_indices,
                })
                seen_sequences.add(hex_sequence)

            for sub_length in range(length - 4, 3, -4):
                sub_sequence = sequence[:sub_length]
                sub_hex_sequence = f"{int(sub_sequence, 2):0{sub_length // 4}X}"
                if sub_hex_sequence not in seen_sequences:

                    sub_packet_indices = [i for i, hex_string in enumerate(hex_string_list) if sub_hex_sequence.lower() in hex_string.lower()]
                    sub_freq_percentage = (len(sub_packet_indices) / n) * 100
                    if min_acc * 100 <= sub_freq_percentage <= max_acc * 100:
                        D.append({
                            "length": sub_length,
                            "The frequent sequence": sub_hex_sequence,
                            "Frequency": f"{sub_freq_percentage:.1f}%",
                            "Packet Indices": sub_packet_indices,
                        })
                        seen_sequences.add(sub_hex_sequence)
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


def find_all_frequent_packet_sequences_for_payload(hex_string_list, min_acc, max_acc, lengths):
    all_results = []
    all_packet_indices_dict = {}
    for length in lengths:
        result, packet_indices_dict = find_frequent_packet_sequences_for_payload(hex_string_list, min_acc, max_acc, length)
        all_results.extend(result)
        all_packet_indices_dict.update(packet_indices_dict)

    return all_results, all_packet_indices_dict


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


        first_index = indices[0]
        first_hex_string = hex_string_list[first_index]
        start_at = first_hex_string.find(seq)


        seq_info["startAt"] = start_at


def filter_sequences(result):

    groups = defaultdict(list)
    for seq_info in result:
        key = (seq_info['startAt'], seq_info['Frequency'])
        groups[key].append(seq_info)


    filtered_result = []
    for group in groups.values():
        longest_seq = max(group, key=lambda x: x['length'])
        filtered_result.append(longest_seq)

    return filtered_result


def filter_same_suffix_and_frequency(result):

    groups = defaultdict(list)
    for seq_info in result:

        last_four_digits = seq_info['The frequent sequence'][-4:]
        key = (last_four_digits, seq_info['Frequency'])
        groups[key].append(seq_info)


    filtered_result = []
    for group in groups.values():
        longest_seq = max(group, key=lambda x: x['length'])
        filtered_result.append(longest_seq)

    return filtered_result


def filter_subset_sequences(result):

    filtered_result = []


    sorted_result = sorted(result, key=lambda x: x['length'], reverse=True)

    for i, seq_info in enumerate(sorted_result):

        curr_sequence = seq_info['The frequent sequence']
        curr_freq = seq_info['Frequency']


        if not any(curr_sequence in other['The frequent sequence'] and curr_freq == other['Frequency'] for other in sorted_result[:i]):

            filtered_result.append(seq_info)

    return filtered_result


def draw_graph(hex_string_list, filtered_result):

    plt.rcParams.update({'font.size': 20})

    width = len(hex_string_list[0])
    height = len(hex_string_list)

    graph = np.ones((height, width, 3))

    white_rgb = np.array([1, 1, 1])
    threshold = 0.7
    all_colors = [color for color in mcolors.CSS4_COLORS.keys()
                  if np.linalg.norm(white_rgb - np.array(mcolors.to_rgb(color))) > threshold]
    random.shuffle(all_colors)

    for seq_num, seq_info in enumerate(filtered_result):
        # 빈번한 시퀀스마다 랜덤한 색상 선택
        color = mcolors.to_rgb(all_colors[seq_num % len(all_colors)])

        length = (seq_info["length"] // 4) - 1
        for packet_idx in seq_info["Packet Indices"]:
            start_at = seq_info["startAt"]
            end_at = start_at + length

            for pos in range(start_at, end_at):
                graph[packet_idx, pos] = color

    fig, ax = plt.subplots()  # Create a figure and an axes.
    ax.xaxis.set_major_locator(ticker.MaxNLocator(integer=True))
    ax.yaxis.set_major_locator(ticker.MaxNLocator(integer=True))

    ax.imshow(graph, aspect='auto')  # Display data as an image.
    ax.set_xlabel('Frame Length', fontsize=28)
    ax.set_ylabel('Frame Index', fontsize=28)
    plt.show()