import pyshark


capture = pyshark.LiveCapture(interface='Wi-Fi', use_json=True, include_raw=True)
capture.sniff(packet_count=1)



# for packet in capture.sniff_continuously(packet_count=5):
#     print(packet)
#
# for packet in capture:
#     print(packet)
#
#
# for raw_data in capture.sniff_continuously():
#     analysis_data(raw_data.get_raw_packet())
