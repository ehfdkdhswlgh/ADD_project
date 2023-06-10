from scapy.all import *
import random
import string

packets = []  # 패킷을 저장할 리스트 생성

for i in range(200):  # 200개 패킷 생성

    dst = random.choices(["ff:ff:ff:ff:ff:ff", "ff:43:10:44:fa:29"], weights=[0.7, 0.3], k=1)[0]
    src = random.choices(["1d:5d:25:92:3f:31", "16:22:3f:4d:9a:34"], weights=[0.3, 0.7], k=1)[0]
    # 이더넷 헤더 생성
    ether = Ether(
        dst=dst,  # 목적지 MAC 주소
        src=src,  # 출발지 MAC 주소
    )

    op = random.choices([1, 2], weights=[0.7, 0.3], k=1)[0]
    hwsrc = random.choices(["54:3f:2d:39:1a:2d", "34:5f:3d:aa:9a:34"], weights=[0.3, 0.7], k=1)[0]  # 's'를 'd'로 수정
    psrc = random.choices(["120.50.19.41", "112.192.60.96"], weights=[0.7, 0.3], k=1)[0]
    hwdst = random.choices(["7f:2a:34:9f:11:55", "22:22:22:4d:9a:34"], weights=[0.3, 0.7], k=1)[0]
    pdst = random.choices(["56.30.168.22", "118.70.192.38"], weights=[0.7, 0.3], k=1)[0]

    # ARP 패킷 생성
    arp = ARP(
        op=op,  # 작업 유형 (1은 요청, 2는 응답)
        hwsrc=hwsrc,  # 소스 MAC 주소
        psrc=psrc,  # 소스 IP 주소
        hwdst=hwdst,  # 대상 MAC 주소
        pdst=pdst  # 대상 IP 주소
    )

    # 패킷 생성
    packet = ether/arp #여기서 정의한 프로토콜을 쌓아서 패킷을 만들면 됨
    packets.append(packet)  # 패킷 리스트에 추가

# 패킷 리스트를 pcap 파일로 저장
wrpcap("arppackets.pcap", packets)





