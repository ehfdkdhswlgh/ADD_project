from scapy.all import *
import random
import string
from random import randint

packets = []  # 패킷을 저장할 리스트 생성

for i in range(200):  # 200개 패킷 생성



    dst = random.choices(["00:13:46:0b:22:ba", "3d:10:ce:8b:6e:40"], weights=[0.7, 0.3], k=1)[0]
    src = random.choices(["40:16:ce:6e:8b:24", "13:2d:4f:44:9a:1f"], weights=[0.3, 0.7], k=1)[0]

    # 이더넷 헤더 생성
    ether = Ether(
        dst=dst,  # 목적지 MAC 주소
        src=src,  # 출발지 MAC 주소
        type=0x0800  # Ethernet 타입 (IP는 0x0800)
    )


    src = random.choices(["192.168.0.114", "72.14.207.99"], weights=[0.7, 0.3], k=1)[0]
    dst = random.choices(["63.220.201.91", "24.119.29.190"], weights=[0.3, 0.7], k=1)[0]
    ttl = random.choices([250, 72], weights=[0.8, 0.2], k=1)[0]

    # IP 헤더 생성
    ip = IP(
        version=4,  # IP 버전 (IPv4는 4)
        tos=0,  # 타입 오브 서비스 (0은 일반 서비스)
        id=randint(1, 65535),  # 패킷 ID
        flags='DF',  # 플래그 (DF는 Don't Fragment를 의미)
        frag=0,  # 프래그먼트 오프셋
        ttl=ttl,  # 시간-종료 (TTL)
        proto='icmp',  # 프로토콜 (ICMP)
        src=src,  # 출발지 IP 주소
        dst=dst  # 목적지 IP 주소
    )

    type = random.choices([8, 0], weights=[0.75, 0.25], k=1)[0]
    id = random.choices([768, 59240], weights=[0.28, 0.72], k=1)[0]

    # ICMP 패킷 생성
    icmp = ICMP(
        type=type,  # ICMP 타입 (8은 Echo Request를 의미)
        code=0,  # ICMP 코드 (Echo Request의 경우 0)
        id=id,
        seq=randint(1, 65535)  # Sequence Number, 패킷마다 고유한 값
    )

    # 페이로드 생성 (100byte 길이의 랜덤한 문자열)
    data = ''.join(random.choices(string.ascii_uppercase + string.ascii_lowercase + string.digits, k=100))


    # 패킷 생성 (이더넷 헤더 + IP 헤더 + ICMP 패킷)
    packet = ether/ip/icmp/str.encode(data) #여기서 정의한 프로토콜을 쌓아서 패킷을 만들면 됨
    packets.append(packet)  # 패킷 리스트에 추가

# 패킷 리스트를 pcap 파일로 저장
wrpcap("icmppackets.pcap", packets)
