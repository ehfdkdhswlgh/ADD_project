import pyshark


##### display_filter="eth.dst.ig == 1" 는 브로드캐스트 패킷만 가져올 수 있고
##### display_filter="eth.dst.ig != 1" 는 유니캐스트 패킷만 가져올 수 있다

packets = pyshark.FileCapture(
            input_file='../Pcaps/ARP.pcapng',
            use_json=True,
            include_raw=True,
            display_filter="eth.dst.ig == 1",
          )._packets_from_tshark_sync() 

# hex_packet = packets.__next__().frame_raw.value
# print(hex_packet)
#
# binary_packet = bytearray.fromhex(hex_packet)
# print(binary_packet)

byte_array_list = []

#'ffffffffffff1005cabf9fe0080600010800060400014edc8e03a79c00000000ffffffffffff00000000' 형태로 저장하는 방식
# for packet in packets:
#     byte_array_list.append(packet.frame_raw.value)

# bytearray(b'\xff\xff\xff\xff\xff\xff\x10\x05\xca\xbf\x9f\xe0\x08\x06\x00\x01\x08\x00 형태로 저장하는 방식
for packet in packets:
    hex = packet.frame_raw.value
    byte_array_list.append(bytearray.fromhex(hex))


print(len(byte_array_list))
