from scapy.all import *

int_lists = []

for packet in PcapReader('./802_11.pcap'):

    # pcap 파일에서 byte 문자열 추출
    byte_arr = bytes_hex(packet)
    byte_str = byte_arr.decode()

    # 2자리씩 끊어서 저장
    hex_list = [byte_str[j:j+2] for j in range(0, len(byte_str), 2)]

    # int형으로 변환
    int_list = []
    for j in range(len(hex_list)):
        int_list.append(int(hex_list[j], 16))
    int_lists.append(int_list)

#결과 = int_lists 사용하기



