def improved_ac_algorithm(bit_stream_list, threshold, min_len, max_len):
    def build_state_tree(length):
        tree = {}
        for i in range(2**length):
            tree[format(i, f'0{length}b')] = 0
        return tree

    def increment_counter(state_tree, sequence):
        if sequence in state_tree:
            state_tree[sequence] += 1
        return state_tree

    n = sum(len(bit_stream) for bit_stream in bit_stream_list)
    state_trees = [build_state_tree(len_) for len_ in range(min_len, max_len + 1)]

    buffers = [[] for _ in range(max_len)]

    for bit_stream in bit_stream_list:
        for i, data in enumerate(bit_stream):
            for buffer_idx, buffer in enumerate(buffers[:i+1]):
                buffer.append(bit_stream[i - buffer_idx:i + 1])

                if buffer_idx + 1 >= min_len:
                    state_tree_idx = buffer_idx - min_len + 1
                    state_trees[state_tree_idx] = increment_counter(state_trees[state_tree_idx], buffer[-1])

    D = []
    for len_, state_tree in zip(range(min_len, max_len + 1), state_trees):
        supp_min = (n - len_ + 1) / (2 * len_) * threshold
        D.extend([{"length": len_ * 4,
                   "The frequent sequences": f"0x{int(sequence, 2):X}",
                   "Frequency": f"{(count / n) * 100:.1f}%"}
                  for sequence, count in state_tree.items() if count > supp_min])

    return D


import random

# 입력 예제
def generate_bit_sequences(num_sequences, sequence_length):
    sequences = []
    for _ in range(num_sequences):
        sequence = ''.join([str(random.randint(0, 1)) for _ in range(sequence_length)])
        sequences.append(sequence)
    return sequences

num_sequences = 100
sequence_length = 100
Str_example = generate_bit_sequences(num_sequences, sequence_length)

threshold = 0.5
min_len = 4
max_len = 8

# 실행
result = improved_ac_algorithm(Str_example, threshold, min_len, max_len)
print("The frequent sequences set D:", result)