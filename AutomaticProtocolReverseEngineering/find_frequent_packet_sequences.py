from collections import defaultdict

def find_frequent_packet_sequences(hex_string_list, min_acc, max_acc, min_len, max_len):
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

    # Initialize a dictionary to store the indices of packets containing each frequent sequence
    packet_indices_dict = defaultdict(list)

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

                # Find the indices of packets containing the frequent sequence
                for i, bit_stream in enumerate(bit_stream_list):
                    if sequence in bit_stream:
                        packet_indices_dict[hex_sequence].append(i)

    return D, packet_indices_dict


def bytearray_to_bin(byte_array):
    return ''.join(format(byte, '08b') for byte in byte_array)


def increment_counter(state_tree, sequence):
    state_tree[sequence] += 1
    return state_tree