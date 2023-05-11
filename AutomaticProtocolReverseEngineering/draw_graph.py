import matplotlib.pyplot as plt
import numpy as np

def draw_graph(hex_string_list, result, protocol_name):
    # 가로축과 세로축의 크기 설정
    width = len(hex_string_list[0])
    height = len(hex_string_list)

    # 그래프를 흰색으로 초기화
    graph = np.ones((height, width))

    # 빈번한 시퀀스를 그래프에 색칠하기
    for seq_info in result:
        length = (seq_info["length"] // 4) - 1
        for packet_idx in seq_info["Packet Indices"]:
            start_at = seq_info["startAt"]
            end_at = start_at + length

            for pos in range(start_at, end_at):
                graph[packet_idx, pos] = 0  # 검정색으로 칠하기

    # 그래프 출력
    plt.imshow(graph, cmap='gray', aspect='auto')
    plt.xlabel('Frequent Sequences Position in Packet')
    plt.ylabel('Packet Index')
    plt.title(protocol_name)
    plt.show()