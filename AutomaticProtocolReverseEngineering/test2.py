from collections import defaultdict


def find_frequent_sequences(hex_string_list, minLen, minAcc):
    sequence_info = defaultdict(list)

    # Sequence generation and frequency calculation
    for i, s in enumerate(hex_string_list):
        for start in range(len(s)):
            for end in range(start + minLen, len(s) + 1):
                seq = s[start:end]
                if seq not in sequence_info:
                    sequence_info[seq].append({'indices': [i], 'startAt': start})
                else:
                    sequence_info[seq][-1]['indices'].append(i)

    result = []

    # Frequency thresholding and sequence length comparison
    for seq, infos in sequence_info.items():
        for info in infos:
            frequency = len(info['indices']) / len(hex_string_list)
            if frequency >= minAcc:
                result.append({
                    'Frequent sequence': seq,
                    'Length': len(seq),
                    'Frequency': f'{frequency * 100}%',
                    'Indices': ','.join(map(str, info['indices'])),
                    'StartAt': info['startAt']
                })

    # Order by length descending, then by frequency descending, then by startAt ascending
    result.sort(key=lambda x: (-x['Length'], -float(x['Frequency'][:-1]), x['StartAt']))

    # Only retain the longest sequence among sequences with the same frequency and startAt
    final_result = []
    for i in range(len(result)):
        if i > 0 and result[i]['Frequency'] == result[i - 1]['Frequency'] and result[i]['StartAt'] == result[i - 1][
            'StartAt']:
            continue
        final_result.append(result[i])

    return final_result


hex_string_list = ['fffffffff1234fffggv', 'fffffffff7777fff675', 'fffffffff1234fffggv', 'fffffffff7777fffggv',
                   'fffffffff1234fgvggv']
minLen = 3
minAcc = 0.5
result = find_frequent_sequences(hex_string_list, minLen, minAcc)
print(result)
