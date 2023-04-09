
import pyshark
from io import StringIO
import pandas as pd


capture = pyshark.FileCapture('./802_11.pcap', use_json=True, include_raw=True)
my_packet = capture[0]

b_arr = my_packet.get_raw_packet()

print(b_arr)

