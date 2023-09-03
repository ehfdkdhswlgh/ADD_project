from sklearn.metrics import silhouette_score
from sklearn.cluster import AgglomerativeClustering
from scipy.cluster.hierarchy import dendrogram, linkage
import numpy as np
import pandas as pd


def convert_hex_strings_to_dec_list(hex_string_list):
    result_list = []

    # 입력 문자열 배열에서 각 문자열마다 2자리씩 나누기
    for input_string in hex_string_list:
        string_result = []  # 각 문자열에서 추출된 10진수를 저장할 리스트
        for i in range(0, len(input_string), 2):
            hex_str = input_string[i:i+2]  # 16진수 문자열 추출
            dec_num = int(hex_str, 16)     # 16진수 문자열을 10진수로 변환
            string_result.append(dec_num)
        result_list.append(string_result)  # 각 문자열에서 추출된 10진수 리스트를 전체 결과 리스트에 추가

    return result_list


def adjust_array_lengths(arrays,avg_len): # 배열 평균 길이에 맞춰서 자르기 및 0으로 padding 하기
    # 배열 길이 수정
    for i in range(len(arrays)):
        if len(arrays[i]) >= avg_len:
            arrays[i] = arrays[i][:int(avg_len)]
        else:
            arrays[i] = arrays[i] + [0] * (int(avg_len) - len(arrays[i]))

    return arrays


def find_average_length(arrays): # 배열의 평균 길이 탐색
    total_length = sum(len(array) for array in arrays)
    average_length = total_length / len(arrays)
    return average_length


# 입력 데이터 전처리
def preprocessing(hex_string_list):
    result_list = convert_hex_strings_to_dec_list(hex_string_list)

    avg_len = int(find_average_length(result_list))
    print("패킷들의 평균 길이 : ", avg_len)

    result_list = adjust_array_lengths(result_list, avg_len)

    return result_list


# 최적의 군집의 수 선택
def select_optimal_number_of_clusters(result_list):
    k_range = range(2, 11)
    k_silhouette_df = pd.DataFrame(k_range, columns=['k'])
    k_silhouette = []

    for k in k_range:
        clustering = AgglomerativeClustering(n_clusters=k, linkage='single')
        clusters = clustering.fit_predict(result_list)
        score = silhouette_score(result_list, clusters)

        print('k :', k, 'score :', score)
        k_silhouette.append([score])

    score_df = pd.DataFrame(k_silhouette, columns=['single_score'])
    k_silhouette_df = pd.concat([k_silhouette_df, score_df], axis=1)

    # 가장 높은 스코어를 가진 k 값을 찾아 변수에 저장
    optimal_k = k_silhouette_df.loc[k_silhouette_df['single_score'].idxmax()]['k']
    print("최적의 군집의 수 : " + str(int(optimal_k)))

    return int(optimal_k)


# 계층적 군집화 수행
def perform_hierarchical_clustering(result_list, k):
    X = np.array(result_list)

    # 계층적 군집화 수행
    clustering = AgglomerativeClustering(n_clusters=k).fit(X)

    # 클러스터 라벨 출력
    cluster_labels = clustering.labels_
    print(cluster_labels)

    # 유클리드 거리를 이용한 병합 군집화 수행
    Z = linkage(X, 'ward')

    # 덴드로그램을 이용한 클러스터 시각화
    # plt.figure(figsize=(10, 5))
    # dendrogram(Z)
    # plt.show()

    return cluster_labels


# 같은 군집끼리 그룹화 수행
def group_by_cluster_labels(hex_string_list, cluster_labels):
    # 군집의 수를 자동으로 판단
    num_clusters = max(cluster_labels) + 1

    cluster_groups = [[] for _ in range(num_clusters)]

    for label, hex_string in zip(cluster_labels, hex_string_list):
        cluster_groups[label].append(hex_string)

    return cluster_groups