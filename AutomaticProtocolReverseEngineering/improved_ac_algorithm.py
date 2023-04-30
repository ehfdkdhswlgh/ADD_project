def improved_ac_algorithm(Str, threshold, Suppmin):
    n = len(Str)
    buffer1, buffer2, buffer3, buffer4 = [], [], [], []
    StateTree = {}  # dictionary to store the frequent sequences
    Len = 4

    # build a 1 -> Len bit sequences tree State.T ree by enumerating its nodes
    for i in range(2 ** Len):
        sequence = format(i, 'b').zfill(Len)
        StateTree[sequence] = 0

    # build the root node
    root = {'0': None, '1': None}

    # build the child sequence node Qm
    for m in range(Len):
        curr_node = root
        for j in range(m):
            curr_node = curr_node['0']
        curr_node['0'] = {'0': None, '1': None}
        curr_node['1'] = {'0': None, '1': None}

    # set a counter for each four-bit state
    Data = Str[0]
    for i in range(1, n):
        if i % 1000 == 0:  # print progress every 1000 bits
            print("Processed", i, "bits out of", n)
        if i <= 3:
            buffer1.append(Data)
            buffer2.append(Data)
            buffer3.append(Data)
        else:
            buffer1.append(Data)
            buffer2.append(buffer1[-2])
            buffer3.append(buffer1[-3])
            buffer4.append(buffer1[-4])

            # read buffer4[] and traverse the StateTree to get the state
            state = "".join(buffer4)
            curr_node = StateTree
            for bit in state:
                curr_node = curr_node[bit]
            curr_node += 1

        Data = Str[i]

    # write corresponding sequences into D
    D = set()
    Suppmin = ((n - Len + 1) / (2 ** Len)) * threshold
    for state, count in StateTree.items():
        if count > Suppmin:
            for i in range(n - Len + 1):
                if Str[i:i + Len] == state:
                    D.add(state)

    return D
