import pyshark
from clustering import *
from frequent_sequence_mining import *

hex_string_list = []

# PCAP 파일 입력
capture = pyshark.FileCapture(
    input_file='pcap_example.pcap',
    use_json=True,
    include_raw=True,
)

packets = capture._packets_from_tshark_sync()

# raw frame data 추출
for packet in packets:
    hex_string = packet.frame_raw.value
    hex_string_list.append(hex_string)

capture.close()

# 입력 데이터 전처리
result_list = preprocessing(hex_string_list)

# 최적의 군집의 수 선택
optimal_k = select_optimal_number_of_clusters(result_list)

# 계층적 군집화 수행
cluster_labels = perform_hierarchical_clustering(result_list, optimal_k)

# 같은 군집끼리 그룹화 수행
cluster_groups = group_by_cluster_labels(hex_string_list, cluster_labels)

# 각 그룹별로 '빈번한 시퀀스 탐색 알고리즘' 수행
for counter, hex_string_list in enumerate(cluster_groups, start=1):

    print("\n\n[[[ ", counter, "번째 그룹에 대한 빈번한 시퀀스탐색 알고리즘 수행", " ]]]\n")

    # 전체 프레임의 10%를 추출 (페이로드 식별용으로 사용)
    hex_string_list_10 = split_frames(hex_string_list)

    print("입력 프레임의 수 : ", len(hex_string_list))
    print("입력 프레임의 길이 : ", len(hex_string_list[0]))

    # 페이로드 영역 식별 및 제거
    payload_startAt, hex_string_list = identify_payload_area(hex_string_list_10, hex_string_list)

    # 빈번한 시퀀스 탐색 알고리즘 수행
    find_frequent_sequence_algorithm(hex_string_list)




