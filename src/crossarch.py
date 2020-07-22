#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
import km
import time
import os
import json
import multiprocessing as mp

o1 = lambda commit: os.path.join("/mnt", "panda", "kernel", "arm64-testcase-new", commit.split('/')[0], "out_dir", "O1", "vmlinux")
o2 = lambda commit: os.path.join("/mnt", "panda", "kernel", "arm64-testcase", commit, "vmlinux")
o3 = lambda commit: os.path.join("/mnt", "panda", "kernel", "arm64-testcase-new", commit.split('/')[0], "out_dir", "O1", "vmlinux")

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
    f = open('exec_record', 'a+')    
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

    dic = {}
    subdic = {}
    subdic['sim'] = sim
    subdic['timeuse'] = t2-t0
    dic[''.join((bin1, "@", func1, ":", bin2, "@", func2))] = subdic
    return sim, dic


def get_funcs():
    f = open("../config/func_list")
    funcs = []
    for line in f.readlines():
        func = line.split("\n")[0]
        funcs.append(func)
    return funcs


def get_commits():
    f = open("../config/commit_list")
    commits = []
    for line in f.readlines():
        commit = line.split("\n")[0]
        commits.append(commit)
    return commits

def list_average(sim_list):
    available_count = 0
    sum = 0
    for i in sim_list:
        if not isinstance(i, str):
            sum += i
            available_count += 1
    return sum/available_count



if __name__ == '__main__':
    funcs = get_funcs()
    commits = get_commits()
    funcs = funcs[0:5]
    commits = commits[0:5]

    sim_data = {}
    # different funcs
    sim_list = []
    pool = mp.Pool(5)
    result = [pool.apply_async(compare_two_funcs, args=(o1(commits[t]), funcs[i], o1(commits[t]), funcs[j]))
        for t in range(5) for i in range(5) for j in range(i+1, 5)]
    pool.close()
    for p in result:
        res = p.get()
        sim_list.append(res[0])
        sim_data = {**sim_data, **res[1]}
    # sim_list += [p.get() for p in result]
    average_sim = list_average(sim_list)
    print('average similarity among different funcs: {}'.format(average_sim))
    with open('conclusion', 'a+') as f:
        f.write('average similarity among different funcs: {}\n'.format(average_sim))
    
    # same func in different commits
    sim_list = []
    pool = mp.Pool(5)
    result = [pool.apply_async(compare_two_funcs, args=(o1(commits[i]), funcs[t], o1(commits[j]), funcs[t]))
        for t in range(5) for i in range(5) for j in range(i+1, 5)]
    pool.close()
    for p in result:
        res = p.get()
        sim_list.append(res[0])
        sim_data = {**sim_data, **res[1]}
    average_sim = list_average(sim_list)
    print('average similarity among same func different commits with optimization in O1: {}'.format(average_sim))
    with open('conclusion', 'a+') as f:
        f.write('average similarity among same func different commits with optimization in O1: {}\n'.format(average_sim))

    # same func in same commit with different optimizations
    # o1 vs o2
    sim_list = []
    pool = mp.Pool(5)
    result = [pool.apply_async(compare_two_funcs, args=(o1(commits[i]), funcs[j], o2(commits[i]), funcs[j]))
        for i in range(5) for j in range(5)]
    pool.close()
    for p in result:
        res = p.get()
        sim_list.append(res[0])
        sim_data = {**sim_data, **res[1]}
    # sim_list += [p.get() for p in result]

    # o1 vs o3
    pool = mp.Pool(5)
    result = [pool.apply_async(compare_two_funcs, args=(o1(commits[i]), funcs[j], o3(commits[i]), funcs[j]))
        for i in range(5) for j in range(5)]
    pool.close()
    for p in result:
        res = p.get()
        sim_list.append(res[0])
        sim_data = {**sim_data, **res[1]}
    # sim_list += [p.get() for p in result]

    # o2 vs o3
    pool = mp.Pool(5)
    result = [pool.apply_async(compare_two_funcs, args=(o2(commits[i]), funcs[j], o3(commits[i]), funcs[j]))
        for i in range(5) for j in range(5)]
    pool.close()
    for p in result:
        res = p.get()
        sim_list.append(res[0])
        sim_data = {**sim_data, **res[1]}
    # sim_list += [p.get() for p in result]

    average_sim = list_average(sim_list)
    print('average similarity among same func in same commit with different optimizations: {}'.format(average_sim))
    with open('conclusion', 'a+') as f:
        f.write('average similarity among same func in same commit with different optimizations: {}\n'.format(average_sim))
        f.write('---------------------------------------------------------')
    with open('exec_result.json', 'a+') as f:
        json.dump(sim_data, f)

    


