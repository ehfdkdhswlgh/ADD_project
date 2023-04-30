import random

# generate a random bit stream file with length 10000
with open('sample.txt', 'w') as f:
    for i in range(10000):
        bit = str(random.randint(0, 1))
        f.write(bit)