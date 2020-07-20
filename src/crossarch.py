#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
import km
import time
import os
import json

def compare_two_funcs(bin1, func1, bin2, func2):
    t0 = time.time()
    try:
        time_used, weight = km.count_weight(bin1, func1, bin2, func2)
        t1 = time.time()
        ans, match = km.km(weight)
        t2 = time.time()
        sim = ans / min(len(weight), len(weight[0]))
    except:
        sim = 'Error!'
    f = open('exec_result', 'a+')    
    f.write('-----------------------------------------------\n')
    f.write('func1 : {}@{}\n'.format(bin1, func1))
    f.write('func2 : {}@{}\n'.format(bin2, func2))
    f.write("The similarity between two function is {}\n".format(sim))
    f.write('time cost for preprocessing func1 {} s\n'.format(time_used[1] - time_used[0]))
    f.write('time cost for preprocessing func2 {} s\n'.format(time_used[2] - time_used[1]))
    f.write('time cost for count weight {} s\n'.format(time_used[3] - time_used[2]))
    f.write('time cost for km algorithm {} s\n'.format(t2 - t1))
    f.write('time cost total {} s\n'.format(t2 - t0))
    f.close()
    return sim


def get_func():
    f = open("/home/codesim/xl/config/func_list")
    funcs = []
    for line in f.readlines():
        func = line.split("\n")[0]
        funcs.append(func)
    return funcs

if __name__ == '__main__':
    # all_func = get_func() # a list of func names
    
    # some simple test

    # same function in different version with same optimization class (O2)
    bin1 = '/mnt/panda/kernel/arm64-new/32a4e169039927bfb6ee9f0ccbbe3a8aaf13a4bc/14e1e38e484cf24cdfc19179ea7a5e71b11d3dd1/vmlinux'
    bin2 = '/mnt/panda/kernel/arm64-new/8ba8682107ee2ca3347354e018865d8e1967c5f4/a9a400b73ffb498d47a6cb59404e278d227d22e3/vmlinux'
    check_func_list = ['environ_read', 'get_task_ioprio']
    
    for func in check_func_list:
        sim = compare_two_funcs(bin1, func,  bin2, func) # similarity of two funcs, between 0 and 1 





