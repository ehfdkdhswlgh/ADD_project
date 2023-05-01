from collections import defaultdict

def longest_common_substring(s1, s2):
    m = len(s1)
    n = len(s2)
    result = 0
    length = [[0] * (n + 1) for _ in range(m + 1)]

    for i in range(m + 1):
        for j in range(n + 1):
            if i == 0 or j == 0:
                length[i][j] = 0
            elif s1[i - 1] == s2[j - 1]:
                length[i][j] = length[i - 1][j - 1] + 1
                result = max(result, length[i][j])
            else:
                length[i][j] = 0
    return result



def analyze_byte_frequencies(packet_list):
    byte_frequencies = defaultdict(int)

    for packet in packet_list:
        for byte in packet:
            byte_frequencies[byte] += 1

    total_bytes = sum(byte_frequencies.values())
    for byte, count in byte_frequencies.items():
        byte_frequencies[byte] = count / total_bytes

    return byte_frequencies

def find_header_patterns(packet_list, header_length):
    header_patterns = defaultdict(int)

    for packet in packet_list:
        header = packet[:header_length]
        header_patterns[header] += 1

    return header_patterns

def extract_header_and_payload(packet_list, header_length):
    headers = [packet[:header_length] for packet in packet_list]
    payloads = [packet[header_length:] for packet in packet_list]

    return headers, payloads







#캡쳐파일 불러오기 불러오기
import pyshark
packets = pyshark.FileCapture(
            input_file='../Pcaps/802_11.pcap',
            use_json=True,
            include_raw=True,
          )._packets_from_tshark_sync()

byte_array_list = []

for packet in packets:
    hex = packet.frame_raw.value
    byte_array_list.append(bytearray.fromhex(hex))



# 패킷 리스트 생성
packet_list = [bytes(byte_array) for byte_array in byte_array_list]

# Step 1: 패킷 집합 간의 최대 공통 부분문자열 찾기
max_common_substring = 0
sample_size = 10  # 패킷 집합의 일부를 사용하여 헤더 길이를 추정

for i in range(sample_size):
    for j in range(i + 1, sample_size):
        common_substring = longest_common_substring(packet_list[i], packet_list[j])
        max_common_substring = max(max_common_substring, common_substring)

# Step 2: 패킷 집합에서 각 바이트의 빈도 분석하기
byte_frequencies = analyze_byte_frequencies(packet_list)

# Step 3: 고정 길이의 패킷 헤더를 가정하고, 길이를 변경해 가며 헤더와 페이로드를 구분하기
header_length = max_common_substring

# Step 4: 각 패킷의 헤더와 페이로드를 비교하여 패턴을 찾기
headers, payloads = extract_header_and_payload(packet_list, header_length)

header_patterns = find_header_patterns(headers, header_length)

# 최대 빈도 찾기 (최대 빈도수의 10% 이상인 값만 출력)
max_frequency = 0
for count in header_patterns.values():
    max_frequency = max(max_frequency, count)

# 최소 빈도 설정
min_frequency = int(max_frequency * 0.01)

# 높은 빈도를 보이는 패턴 출력
for pattern, count in header_patterns.items():
    if count > min_frequency:
        print(f"헤더 패턴 후보 : {pattern}, 빈도: {count}, 길이: {len(pattern)}")
