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

    supp_min = (n - length + 1) / (2 ** length) * min_acc
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




