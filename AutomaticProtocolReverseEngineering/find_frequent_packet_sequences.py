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
                D.append({
                    "length": length,
                    "The frequent sequence": hex_sequence,
                    "Frequency": f"{freq_percentage:.1f}%",
                })
                seen_sequences.add(hex_sequence)

    return D, packet_indices_dict


def bytearray_to_bin(byte_array):
    return ''.join(format(byte, '08b') for byte in byte_array)


def increment_counter(state_tree, sequence):
    state_tree[sequence] += 1
    return state_tree

