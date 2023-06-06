import numpy as np
from matplotlib import colors as mcolors
import matplotlib.pyplot as plt
import random

def draw_graph(hex_string_list, result, protocol_name):
    # 가로축과 세로축의 크기 설정
    width = len(hex_string_list[0])
    height = len(hex_string_list)

    # 그래프를 흰색으로 초기화
    graph = np.ones((height, width, 3))

    # 모든 가능한 색상을 가져와서 랜덤하게 섞기. 흰색과 가까운 색은 제외
    white_rgb = np.array([1, 1, 1])
    threshold = 0.7  # 이 값은 흰색에 가까운 색상을 어느 정도로 정의할 것인지를 결정. 값이 작을수록 흰색에 더 가까운 색상을 제외.
    all_colors = [color for color in mcolors.CSS4_COLORS.keys()
                  if np.linalg.norm(white_rgb - np.array(mcolors.to_rgb(color))) > threshold]
    random.shuffle(all_colors)

    # 빈번한 시퀀스를 그래프에 색칠하기
    for seq_num, seq_info in enumerate(result):
        # 빈번한 시퀀스마다 랜덤한 색상 선택
        color = mcolors.to_rgb(all_colors[seq_num % len(all_colors)])

        length = (seq_info["length"] // 4) - 1
        for packet_idx in seq_info["Packet Indices"]:
            start_at = seq_info["startAt"]
            end_at = start_at + length

            for pos in range(start_at, end_at):
                graph[packet_idx, pos] = color  # 랜덤 색상으로 칠하기

    # 그래프 출력
    plt.imshow(graph, aspect='auto')
    plt.xlabel('Frame Length')
    plt.ylabel('Frame Index')
    plt.title(protocol_name)
    plt.show()


