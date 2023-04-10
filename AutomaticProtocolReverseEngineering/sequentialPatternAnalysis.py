from prefixspan import PrefixSpan
from collections import Counter


packets = [
    'd850e6449bd88c8590794fe608004500004215bb0000401192fbc0a801664a7dc569da7501bb002e78710ca089fa845f8b2dd1022678c9b2f4d11abe7cee813640021532020201000106010003b30601',
    'd850e6449bd88c8590794fe6080045000042d3c500004011d4f0c0a801664a7dc569da7501bb002e40150ca089fa845f8b2dd108774af0ba127a75dbb81d8cbf7ec361f10fac3c92564dd4f5b418589f',
    'd850e6449bd88c8590794fe6080045000042715d000040113759c0a801664a7dc569da7501bb002e1cb80ca089fa845f8b2dd109cc7da16929c75283fa7248593a50994e601d4a978a9a2cbcb613a4c6',
    'd850e6449bd88c8590794fe6080045000042d87e00004011d037c0a801664a7dc569da7501bb002ee8f70ca089fa845f8b2dd10ada63562163814072528333b15c0d98e3c56387274e5991203a733b2b',
    'd850e6449bd88c8590794fe6080045000042ba5200004011ee63c0a801664a7dc569da7501bb002eabff0ca089fa845f8b2dd10ba3a1bb5ff7e6c28af963f045a56c61ac5e144edaf8a6667e78dd9f11',
    'd850e6449bd88c8590794fe608004500004265c90000401142edc0a801664a7dc569da7501bb002e20100ca089fa845f8b2dd10cc6529b75413d96d366613bdbe876adf1a98c5809bbd67de0e13a2b21',
    'd850e6449bd88c8590794fe6080045000042bb4600004011ed6fc0a801664a7dc569da7501bb002efe870ca089fa845f8b2dd10d060cea689bd38b808aeed2192ffce8caf8280655bea9e766ed3cbc4a',
    'd850e6449bd88c8590794fe6080045000042020800004011a6aec0a801664a7dc569da7501bb002eb2df0ca089fa845f8b2dd11143f2cda6c67fa0542086fd9b531b6613140b89c2edc8d7ddbe16b609',
    'd850e6449bd88c8590794fe6080045000042555700004011535fc0a801664a7dc569da7501bb002e013d0ca089fa845f8b2dd1125d42ef9b37f80f91f97ba9dba5e653062c03e98060ec06786e10bd4f',
    'd850e6449bd88c8590794fe60800450000428ca1000040111c15c0a801664a7dc569da7501bb002e2fdc0ca089fa845f8b2dd1170bcaace54bf70a42941d7c8cd232fb6820862efd2c9c50d7453eaaec',
    'd850e6449bd88c8590794fe60800450000421440000040119476c0a801664a7dc569da7501bb002ecde80ca089fa845f8b2dd118f61e27086498f1e1b465436be9596c4627e26a2ae5e0f37bb679294d',
    'd850e6449bd88c8590794fe60800450000423db2000040116b04c0a801664a7dc569da7501bb002ee01e0ca089fa845f8b2dd10ec15cf93ceb19466cf2b588b978ff1f0b5142a8bc6fd3d24023909ad9',
    'd850e6449bd88c8590794fe608004500004212d50000401195e1c0a801664a7dc569da7501bb002e41f00ca089fa845f8b2dd110792d823c2edb2887108269bd85b1e0f48649f323240783b731311234',
    'd850e6449bd88c8590794fe6080045000042c61c00004011e299c0a801664a7dc569da7501bb002e76ac0ca089fa845f8b2dd113561df78482bd56759040bb3db51fec558b11be2bde63f08b0d212a6d',
    'd850e6449bd88c8590794fe6080045000042e6e500004011c1d0c0a801664a7dc569da7501bb002e4e460ca089fa845f8b2dd1148a6ea01475b7ab14648cfc9c258d666745ef8b8008c930ba4a66fe22',
    'd850e6449bd88c8590794fe6080045000042c72b00004011e18ac0a801664a7dc569da7501bb002e4bcb0ca089fa845f8b2dd115888eca7bf750e931e0c3eec77384b542cbc8b2d540b3b159daf116e6',
    'd850e6449bd88c8590794fe6080045000042014000004011a776c0a801664a7dc569da7501bb002ee9f60ca089fa845f8b2dd1169f4f27fceeeaa91afe5d86938e762f3886bbf411fd96deeff43302bd'
]


# #2자리씩 끊어서 저장
hex_lists = []
for i in range(len(packets)):
    hex_list = [packets[i][j:j+2] for j in range(0, len(packets[i]), 2)]
    hex_lists.append(hex_list)




#int형 리스트로 변환
int_lists = []
for i in range(len(hex_lists)):
    int_list = []
    for j in range(len(hex_lists[i])):
        int_list.append(int(hex_lists[i][j], 16))
    int_lists.append(int_list)


data = int_lists

ps = PrefixSpan(data)

ps.minlen = 2
b = ps.topk(100) #패킷 길이에 맞게 설정해줘야함

s = []
for i in range(len(b)):
    for j in range(len(b[i][1])):
        s.append(b[i][1][j])


list = []
for v in s:
    if v not in list:
        list.append(v)

print(list)

point = []
index = [[] for i in range(len(list))]

for j in range(len(list)):
    for i in range(len(data)):
        for p in enumerate(data[i]):
            if(p[1] == list[j]):
                index[j].append(p[0])
    point.append(Counter(index[j]).most_common(1)[0][0])

point = sorted(point)
print(point)