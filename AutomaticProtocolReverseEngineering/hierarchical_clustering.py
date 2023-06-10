import pyshark

hex_string_list = []
answer = []

# Pcap 파일 읽기
capture1 = pyshark.FileCapture(
    input_file='../Pcaps/ARP_42_217_X.pcapng',
    use_json=True,
    include_raw=True,
)
packets1 = capture1._packets_from_tshark_sync()

for packet in packets1:
    hex_string = packet.frame_raw.value
    hex_string_list.append(hex_string)
    answer.append(4)

capture1.close()





capture2 = pyshark.FileCapture(
    input_file='../Pcaps/TLS_85_486_O.pcapng',
    use_json=True,
    include_raw=True,
)

packets2 = capture2._packets_from_tshark_sync()

for packet in packets2:
    hex_string = packet.frame_raw.value
    hex_string_list.append(hex_string)
    answer.append(0)

capture2.close()








capture3 = pyshark.FileCapture(
    input_file='../Pcaps/ANCP_88_24.pcapng',
    use_json=True,
    include_raw=True,
)

packets3 = capture3._packets_from_tshark_sync()

for packet in packets3:
    hex_string = packet.frame_raw.value
    hex_string_list.append(hex_string)
    answer.append(2)


capture3.close()






capture4 = pyshark.FileCapture(
    input_file='../Pcaps/BGP_85_60.pcapng',
    use_json=True,
    include_raw=True,
)

packets4 = capture4._packets_from_tshark_sync()

for packet in packets4:
    hex_string = packet.frame_raw.value
    hex_string_list.append(hex_string)
    answer.append(3)


capture4.close()







capture5 = pyshark.FileCapture(
    input_file='../Pcaps/MANOLITOProtocol(SearchQuery)_81_605.pcapng',
    use_json=True,
    include_raw=True,
)

packets5 = capture5._packets_from_tshark_sync()


for packet in packets5:
    hex_string = packet.frame_raw.value
    hex_string_list.append(hex_string)
    answer.append(1)

capture5.close()








result_list = []
#입력 데이터 2개씩 짤라서 다시 저장하기

# 입력 문자열 배열에서 각 문자열마다 2자리씩 나누기
for input_string in hex_string_list:
    string_result = []  # 각 문자열에서 추출된 10진수를 저장할 리스트
    for i in range(0, len(input_string), 2):
        hex_str = input_string[i:i+2]  # 16진수 문자열 추출
        dec_num = int(hex_str, 16)     # 16진수 문자열을 10진수로 변환
        string_result.append(dec_num)
    result_list.append(string_result)  # 각 문자열에서 추출된 10진수 리스트를 전체 결과 리스트에 추가



import matplotlib.pyplot as plt
# 문자열 길이 분포 계산
lengths = [len(s) for s in result_list]

# 히스토그램 시각화
plt.hist(range(len(result_list)), bins=len(result_list), align='left', weights=lengths)
plt.xlabel('Index of Strings')
plt.ylabel('Length of Strings')
plt.show()


def find_average_length(arrays): #배열의 평균 길이 탐색
    total_length = sum(len(array) for array in arrays)
    average_length = total_length / len(arrays)
    return average_length


avg_len = int(find_average_length(result_list))
print("패킷들의 평균 길이 : ",avg_len)

def adjust_array_lengths(arrays,avg_len):# 배열 평균 길이에 맞춰서 자르기 및 0으로 padding 하기
    # 배열 길이 수정
    for i in range(len(arrays)):
        if len(arrays[i]) >= avg_len:
            arrays[i] = arrays[i][:int(avg_len)]
        else:
            arrays[i] = arrays[i] + [0] * (int(avg_len) - len(arrays[i]))

    return arrays

result_list = adjust_array_lengths(result_list, avg_len)




#계층적 군집화 수행
from sklearn.cluster import AgglomerativeClustering
import numpy as np

# 배열들을 하나의 행렬로 합치기
X = np.array(result_list)

# 계층적 군집화 수행
clustering = AgglomerativeClustering(n_clusters=5).fit(X)

# 클러스터 라벨 출력
cluster_labels = clustering.labels_
print(cluster_labels)

for i in cluster_labels:
    print(i)




import numpy as np
from scipy.cluster.hierarchy import dendrogram, linkage
import matplotlib.pyplot as plt

# 입력 데이터 생성
# 배열들을 하나의 행렬로 합치기
X = np.array(result_list)

# 유클리드 거리를 이용한 병합 군집화 수행
Z = linkage(X, 'ward')

# 덴드로그램을 이용한 클러스터 시각화
plt.figure(figsize=(10, 5))
dendrogram(Z)
plt.show()






#성능 평가

def calculate_match_percentage(answer, cluster_labels):
    unique_values = set(answer)
    match_percentage = {}

    for value in unique_values:
        answer_count = answer.count(value)
        result_count = sum([1 for i, x in enumerate(cluster_labels) if x == value and answer[i] == value])
        percentage = (result_count / answer_count) * 100
        match_percentage[value] = f'{percentage:.2f}%'

    return match_percentage

match_percentage = calculate_match_percentage(answer, cluster_labels)
print(match_percentage)


