def filter_unique_sequences(sequences):
    filtered_sequences = sequences.copy()

    for seq in sequences:
        for other_seq in sequences:
            if seq != other_seq and seq in other_seq:
                if other_seq in filtered_sequences:
                    filtered_sequences.remove(other_seq)

    return filtered_sequences