#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'xianglin'

import SampleFunction
import PreprocessingFunc
import minHash
import time

INF = 0x3fffffff
EPS = 1e-10


def dfs(now, depth=0):
    global n, m, w, lx, ly, vx, vy, delta, aim
    vx[now] = True
    for i in range(m):
        if not vy[i]:
            if abs(lx[now] + ly[i] - w[now][i]) < EPS:
                vy[i] = True
                if aim[i] == -1 or dfs(aim[i], depth+1):
                    aim[i] = now
                    return True
            else:
                delta = min(lx[now] + ly[i] - w[now][i], delta)
    return False


# max cost match
def km(weight):
    global n, m, w, lx, ly, vx, vy, delta, aim
    n = len(weight)
    m = len(weight[0])
    if n < m:
        transpose = False
        w = [list(line) for line in weight]
    else:
        transpose = True
        n, m = m, n
        w = [[0] * m for _ in range(n)]
        for i in range(n):
            for j in range(m):
                w[i][j] = weight[j][i]

    lx = [0] * n
    ly = [0] * m
    aim = [-1] * m
    for i in range(n):
        lx[i] = max(w[i])

    for k in range(n):
        while True:
            vx = [False] * n
            vy = [False] * m
            delta = INF
            if dfs(k):
                break
            for i in range(n):
                if vx[i]:
                    lx[i] -= delta
            for i in range(m):
                if vy[i]:
                    ly[i] += delta

    match = []
    ans = 0
    for i in range(m):
        if aim[i] != -1:
            ans += w[aim[i]][i]
            if transpose:
                match.append((i, aim[i]))
            else:
                match.append((aim[i], i))
    return ans, match


def count_weight(bin1, func1, bin2, func2):
    t0 = time.time()
    print("strat to processing "+func1+"...")
    p1 = SampleFunction.sample_func(bin1, func1)
    q1 = PreprocessingFunc.func_io_to_checksum(p1)
    t1 = time.time()
    w1 = [q1[k] for k in q1.keys()]
    print("strat to processing " + func2 + "...")
    p2 = SampleFunction.sample_func(bin2, func2)
    q2 = PreprocessingFunc.func_io_to_checksum(p2)
    w2 = [q2[k] for k in q2.keys()]
    t2 = time.time()
    
    init_row = [0.0] * len(w2)
    weight = [init_row[:] for i in range(len(w1))]
    for i in range(len(w1)):
        for j in range(len(w2)):
            weight[i][j] = minHash.compare_two_bb_4times(w1[i], w2[j])
    t3 = time.time()
    return [t0, t1, t2, t3], weight


def main():
    path = "/home/xianglin/Graduation/graduation/testcase/2423496af35d94a87156b063ea5cedffc10a70a1/vmlinux"
    path2 = "/home/xianglin/Graduation/executables/add_O0"
    path3 = "/home/xianglin/Graduation/executables/add_O1"
    func1 = "dccp_rcv_state_process"
    func2 = "show_stat"
    func3 = "fill_tso_desc"
    func4 = "ip_forward_options"
    t0 = time.time()
    time_used, weight = count_weight(path2, "add1", path3, "add1")
    t1 = time.time()
    ans, match = km(weight)
    t2 = time.time()
    s = ans / min(len(weight), len(weight[0]))  # range : (0,1)
    print("The similarity between two function is {}".format(s))
    print('time cost for preprocessing func1 {} s'.format(time_used[1] - time_used[0]))
    print('time cost for preprocessing func2 {} s'.format(time_used[2] - time_used[1]))
    print('time cost for count weight {} s'.format(time_used[3] - time_used[2]))
    print('time cost for km algorithm {} s'.format(t2 - t1))
    print('time cost total {} s'.format(t2 - t0))


if __name__ == '__main__':
    main()



