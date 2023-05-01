import math
import itertools
from collections import defaultdict
from typing import List

def calculate_entropy(data: List[bytes]) -> List[float]:
    byte_freqs = defaultdict(int)

    for byte in data:
        byte_freqs[byte] += 1

    total_bytes = len(data)
    entropy = 0

    for byte, count in byte_freqs.items():
        p = count / total_bytes
        entropy += -p * math.log2(p)

    return entropy

def find_entropy_based_split_position(packet_list: List[bytes], min_entropy: float) -> int:
    byte_columns = zip(*packet_list)
    entropies = [calculate_entropy(column) for column in byte_columns]

    for i, entropy in enumerate(entropies):
        if entropy > min_entropy:
            return i
    return len(entropies)

def find_repeating_patterns(packet_list: List[bytes], min_pattern_length: int) -> List[List[int]]:
    patterns = defaultdict(list)

    for packet in packet_list:
        for i in range(len(packet) - min_pattern_length + 1):
            pattern = packet[i:i + min_pattern_length]
            patterns[pattern].append(i)

    return [indices for indices in patterns.values() if len(indices) > 1]

def find_common_subsequence_indices(packet_list: List[bytes], patterns: List[List[int]], max_distance: int) -> List[List[int]]:
    common_subsequence_indices = []

    for pattern_indices in patterns:
        common_subsequences = []
        for index_combination in itertools.combinations(pattern_indices, 2):
            distance = abs(index_combination[0] - index_combination[1])
            if distance <= max_distance:
                common_subsequences.append(list(index_combination))

        if common_subsequences:
            common_subsequence_indices.append(common_subsequences)

    return common_subsequence_indices

def identify_fields(packet_list: List[bytes], min_entropy: float, min_pattern_length: int, max_distance: int):
    split_position = find_entropy_based_split_position(packet_list, min_entropy)

    headers = [packet[:split_position] for packet in packet_list]
    payloads = [packet[split_position:] for packet in packet_list]

    repeating_patterns = find_repeating_patterns(headers, min_pattern_length)
    common_subsequence_indices = find_common_subsequence_indices(headers, repeating_patterns, max_distance)

    return common_subsequence_indices








# 알고리즘 실행
min_entropy = 1.5         # 엔트로피 기반 분할 위치를 찾기 위한 최소 엔트로피 값
min_pattern_length = 2    # 반복되는 패턴에서 찾을 최소 패턴 길이
max_distance = 3          # 최대 공통 부분 문자열 간의 최대 허용 거리






import numpy as np
from scipy.cluster.hierarchy import linkage, fcluster
from sklearn.preprocessing import MinMaxScaler

def packet_to_vector(packet, length):
    vector = np.zeros(length, dtype=np.uint8)
    vector[:min(len(packet), length)] = packet[:length]
    return vector

# 패킷 데이터를 고정 길이 벡터로 변환
min_length = min(len(packet) for packet in packet_list)
max_length = max(len(packet) for packet in packet_list)
vector_length = (min_length + max_length) // 2

packet_vectors = np.array([packet_to_vector(packet, vector_length) for packet in packet_list])

# 정규화
scaler = MinMaxScaler()
normalized_vectors = scaler.fit_transform(packet_vectors)

# 계층적 군집화 수행
Z = linkage(normalized_vectors, method='ward')

# 클러스터 레이블 결정
distance_threshold = 1.5
labels = fcluster(Z, distance_threshold, criterion='distance')

# 클러스터별로 패킷 분류
n_clusters = np.unique(labels).size
clusters = [[] for _ in range(n_clusters)]
for i, label in enumerate(labels):
    clusters[label - 1].append(packet_list[i])

# 각 클러스터에 대해 필드 식별 알고리즘 실행
for i, cluster_packets in enumerate(clusters):
    print(f"Cluster {i + 1}:")
    field_indices = identify_fields(cluster_packets, min_entropy, min_pattern_length, max_distance)
    print(field_indices)
    print()
