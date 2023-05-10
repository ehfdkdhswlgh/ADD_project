def find_association_rules(filtered_result):
    rules = []
    for i, seq_info1 in enumerate(filtered_result):
        for j, seq_info2 in enumerate(filtered_result):
            if i != j:
                seq1_indices = set(seq_info1["Packet Indices"])
                seq2_indices = set(seq_info2["Packet Indices"])

                if seq1_indices.issubset(seq2_indices):
                    rule = f"{seq_info1['The frequent sequence']} ⇒ {seq_info2['The frequent sequence']}"
                    if rule not in rules:
                        rules.append(rule)
                elif seq2_indices.issubset(seq1_indices):
                    rule = f"{seq_info2['The frequent sequence']} ⇒ {seq_info1['The frequent sequence']}"
                    if rule not in rules:
                        rules.append(rule)

    return rules