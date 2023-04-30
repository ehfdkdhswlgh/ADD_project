def improved_AC_algorithm(Str, threshold):
    n = len(Str)
    Len = 8

    # Step 3: Build a 1 → Len bit sequences tree State.Tree by enumerating its node
    State_Tree = {}
    for i in range(2 ** Len):
        State_Tree[format(i, f'0{Len}b')] = 0

    # Step 9-18: Set a counter for each four-bit state
    for data in Str:
        for i in range(1, Len + 1):
            key = data[-i:]
            if key in State_Tree:
                State_Tree[key] += 1

    # Step 20: Calculate Suppmin
    Suppmin = ((n - Len + 1) / (2 ** Len)) * threshold

    # Step 22: Write corresponding sequence into D
    D = [k for k, v in State_Tree.items() if v > Suppmin]

    return D

import random

def generate_bit_sequences(num_sequences, sequence_length):
    sequences = []
    for _ in range(num_sequences):
        sequence = ''.join([str(random.randint(0, 1)) for _ in range(sequence_length)])
        sequences.append(sequence)
    return sequences

num_sequences = 100
sequence_length = 100
Str_example = generate_bit_sequences(num_sequences, sequence_length)

threshold = 0.8

# 실행
result = improved_AC_algorithm(Str_example, threshold)
print(result)
print(len(result))