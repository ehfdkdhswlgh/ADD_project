from scapy.all import *
from scapy.layers.dot11 import Dot11, RadioTap
from scapy.layers.l2 import LLC, SNAP
from random import randint
from scapy.layers.dot11 import Dot11QoS
import random
import string

packets = []  # 패킷을 저장할 리스트 생성

for i in range(200):  # 200개 패킷 생성



    Rate = random.choices([2, 9], weights=[0.7, 0.3], k=1)[0]
    dBm_AntSignal = random.choices([-50, -80], weights=[0.3, 0.7], k=1)[0]
    Antenna = random.choices([1, 3], weights=[0.7, 0.3], k=1)[0]
    Flags = random.choices([0x10, 2], weights=[0.3, 0.7], k=1)[0]

    # RadioTap 헤더 생성
    radio = RadioTap(present='Flags+Rate+dBm_AntSignal+Antenna',
                     Flags=Flags,  # short preamble flag
                     Rate=Rate,  # 1 Mbps
                     dBm_AntSignal=dBm_AntSignal,  # -50 dBm
                     Antenna=Antenna)  # Antenna index


    # 확률에 따른 MAC 주소 선택
    addr1 = random.choices(["ac:14:20:4f:31:29", "ff:43:10:44:fa:29"], weights=[0.7, 0.3], k=1)[0]
    addr2 = random.choices(["4d:2e:aa:23:05:ff", "15:22:50:b2:cc:ab"], weights=[0.3, 0.7], k=1)[0]
    addr3 = random.choices(["f2:33:62:ab:bc:3d", "50:34:ad:22:ad:cf"], weights=[0.7, 0.3], k=1)[0]

    # Duration/ID 필드인데 4100, 44 으로 설정하자
    ID = random.choices([4100, 44], weights=[0.3, 0.7], k=1)[0]


    # 802.11 헤더 생성
    dot11 = Dot11(type=2,
                  subtype=8,  # 데이터 프레임
                   addr1=addr1,  # STA address, Receiver address, Destination address
                   addr2=addr2,  # Transmitter address
                   addr3=addr3,  # Source address
                    ID=ID,
                  )

    #Frame Control Field 설정
    dot11.FCfield = random.choices([0x8821, 0x8800], weights=[0.7, 0.3], k=1)[0]


    # QoS 헤더 추가 (Qos Control)

    TID = random.choices([0x0005, 0x0000], weights=[0.3, 0.7], k=1)[0]
    qos = Dot11QoS(TID=TID)  # Qos Control 필드 ( 0x0005 또는 0x0000)


    # LLC/SNAP 헤더 생성 (Logical-Link Control)  <------- 모두 동일한 값을 가진 프로토콜
    llc = LLC(dsap=0xaa, ssap=0xaa, ctrl=3)
    snap = SNAP(OUI=0x000000, code=0x0800)


    # IP 헤더 생성. 'id' 필드에 랜덤한 값 설정

    src = random.choices(["112.29.38.223", "44.129.20.35"], weights=[0.7, 0.3], k=1)[0]
    dst = random.choices(["75.125.30.22", "80.119.29.190"], weights=[0.3, 0.7], k=1)[0]
    ttl = random.choices([48, 128], weights=[0.7, 0.3], k=1)[0]

    ip = IP(src=src, dst=dst,
            version=4, ihl=5, flags='DF', frag=0, ttl=ttl, id=randint(1, 65535))
    #FLAGS, FLAG, ihl(헤더의 길이), : 고정값



    flags = random.choices(['A', 'S'], weights=[0.7, 0.3], k=1)[0]
    window = random.choices([6412, 16123], weights=[0.3, 0.7], k=1)[0]


    # TCP 헤더 생성
    tcp = TCP(sport=12345, dport=80, seq=1000, ack=1000,
              dataofs=5, reserved=0, flags=flags, window=window,
              urgptr=0, options=[])

    # 페이로드 생성 (100byte 길이의 랜덤한 문자열)
    payload = ''.join(random.choices(string.ascii_uppercase + string.ascii_lowercase + string.digits, k=100))

    # 패킷 생성
    packet = radio/dot11/qos/llc/snap/ip/tcp/str.encode(payload)  #여기서 정의한 프로토콜을 쌓아서 패킷을 만들면 됨
    packets.append(packet)  # 패킷 리스트에 추가

# 패킷 리스트를 pcap 파일로 저장
wrpcap("tcppackets.pcap", packets)































# RadioTap():
    # present: RadioTap 헤더에 포함된 필드들을 나타냅니다.
    # Flags: 특정 조건을 나타내는 플래그입니다.
    # Rate: 데이터 전송 속도를 500 kbps 단위로 나타냅니다.
    # dBm_AntSignal: 안테나 신호 강도를 dBm 단위로 나타냅니다.
    # Antenna: 안테나 인덱스를 나타냅니다.
# Dot11():
    # type: 802.11 프레임의 유형입니다. 가능한 값은 관리(0), 제어(1), 데이터(2)입니다.
    # subtype: 프레임의 세부 유형입니다. 각 유형의 서브타입은 IEEE 802.11 사양에서 찾을 수 있습니다.
    # addr1, addr2, addr3: 각각 목적지 MAC 주소, 출발지 MAC 주소, BSSID를 나타냅니다. 일반적으로 MAC 주소 형식을 따릅니다.
# LLC():
    # dsap, ssap: 이것들은 각각 목적지 서비스 액세스 포인트와 소스 서비스 액세스 포인트를 나타냅니다. 이 값들은 일반적으로 0xaa입니다.
    # ctrl: 제어 필드를 나타냅니다. 일반적으로 0x03입니다.
# SNAP():
    # OUI: 조직 고유 식별자를 나타냅니다. IP를 나타내기 위해선 0x000000을 사용합니다.
    # code: 프로토콜 유형을 나타냅니다. IP를 나타내기 위해선 0x0800을 사용합니다.
# IP():
    # version: IP 버전을 나타냅니다. 보통 4(IPv4) 또는 6(IPv6)입니다.
    # ihl: IP 헤더 길이를 나타냅니다. 기본 값은 5입니다.
    # tos: 서비스 유형을 나타냅니다. 보통 0x00을 사용합니다.
    # flags: 플래그 필드입니다. 'DF'는 조각화 금지를, 'MF'는 더 많은 프래그먼트를 나타냅니다.
    # frag: 조각 위치를 나타냅니다. 조각화가 없는 경우 0을 사용합니다.
    # ttl: 시간 대기(생존) 시간을 나타냅니다. 보통 64 또는 128을 사용합니다.
# TCP():
    # sport, dport: 출발지 및 목적지 포트 번호입니다.
    # seq: 시퀀스 번호입니다.
    # ack: ACK(응답) 번호입니다.
    # dataofs: 데이터 오프셋을 나타냅니다. 기본 값은 5입니다.
    # reserved: 예약 필드입니다. 기본 값은 0입니다.
    # flags: 플래그 필드입니다. 'S'(SYN), 'A'(ACK), 'F'(FIN), 'R'(RST), 'P'(PSH), 'U'(URG) 등이 포함될 수 있습니다.
    # window: 윈도우 크기를 나타냅니다.
    # urgptr: 긴급 포인터입니다. 일반적으로 0입니다.
    # options: TCP 옵션을 나타냅니다. 빈 리스트([])는 옵션이 없음을 의미합니다.


# TCP FLAG 설명
    # FIN: 이 플래그는 TCP 연결의 종료를 나타냅니다. 송신자가 더 이상 데이터를 보낼 것이 없음을 나타내는데 사용됩니다.
    # SYN: 이 플래그는 TCP 연결의 시작을 나타냅니다. TCP 3-웨이 핸드셰이크의 일부로 사용됩니다. 최초에 클라이언트가 서버로 SYN 패킷을 보내 연결을 요청합니다.
    # RST: 이 플래그는 TCP 연결을 즉시 재설정하는 데 사용됩니다. 문제가 발생했을 때 연결을 중단하고 다시 시작하는데 사용됩니다.
    # PSH: 이 플래그는 TCP 버퍼에 데이터를 즉시 전달하도록 요청합니다. 데이터를 즉시 전달해야 하는 경우에 사용됩니다.
    # ACK: 이 플래그는 패킷이 성공적으로 수신되었음을 확인하는 데 사용됩니다. TCP 연결에서 모든 패킷은 결국 ACK가 되어야 합니다.
    # URG: 이 플래그는 패킷에 긴급 데이터가 포함되어 있음을 나타냅니다. 긴급 데이터는 TCP 스트림에서 다른 데이터보다 우선순위가 높습니다.
    # ECE, CWR: 이 플래그들은 TCP의 Explicit Congestion Notification(ECN) 메커니즘에 사용되며, 네트워크 혼잡 상황을 알리는데 사용됩니다.
    # 플래그 값을 설정할 때는 문자열로 표현하며, 여러 플래그를 동시에 설정할 때는 각각의 첫 글자를 붙여서 표현합니다. 예를 들어, SYN과 ACK 플래그를 동시에 설정하려면 flags='SA'와 같이 설정합니다.