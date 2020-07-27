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
o3 = lambda commit: os.path.join("/mnt", "panda", "kernel", "arm64-testcase-new", commit.split('/')[0], "out_dir", "O3", "vmlinux")

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
    if sim!='Error!':
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
    funcs = funcs[0:10]
    '''
    dccp_rcv_state_process
    ext4_collapse_range
    ext4_insert_range
    ext4_page_mkwrite
    ext4_punch_hole
    ext4_setattr
    init_once
    follow_page_pte
    hmac_create
    ion_ioctl
    '''
    commits = commits[0:10]
    # take the first function in first commit as an example
    sim_data = {}
    threads = 20
    choosen_func = 0
    choosen_commit = 0
    choosen_opt = o2
    optlist = [o1, o2, o3]

    ## optimization
    # compare one func among different optimization
    for opt in optlist:
        sim_list = []
        pool = mp.Pool(threads)
        result = [pool.apply_async(compare_two_funcs, args=(choosen_opt(commits[choosen_commit]), funcs[choosen_func],
                                                            opt(commits[choosen_commit]), funcs[choosen_func]))]
        pool.close()
        for p in result:
            res = p.get()
            sim_list.append(res[0])
            sim_data = {**sim_data, **res[1]}
        # sim_list += [p.get() for p in result]
        average_sim = list_average(sim_list)
        with open('conclusion', 'a+') as f:
            f.write('similarity of one func between 2 opt is {}\n'.format(average_sim))




    # different funcs
    # compare the first func with other funcs
    for opt in optlist: # compare them in 3 optimizations
        sim_list = []
        pool = mp.Pool(threads)
        result = [pool.apply_async(compare_two_funcs, args=(choosen_opt(commits[choosen_commit]), funcs[choosen_func], 
                                                            opt(commits[choosen_commit]), funcs[i]))
                                                            for i in range(10) if i!=choosen_func]
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
    

    ## commits
    # same func in different commits
    
    sim_list = []
    pool = mp.Pool(threads)
    result = [pool.apply_async(compare_two_funcs, args=(choosen_opt(commits[choosen_commit]), funcs[choosen_func], 
                                                        choosen_opt(commits[t]), funcs[choosen_func]))
                                                        for t in range(10) if t!=choosen_commit]
    pool.close()
    for p in result:
        res = p.get()
        sim_list.append(res[0])
        sim_data = {**sim_data, **res[1]}
    average_sim = list_average(sim_list)
    print('average similarity among same func different commits with optimization in O2: {}'.format(average_sim))
    with open('conclusion', 'a+') as f:
        f.write('average similarity among same func different commits with optimization in O2: {}\n'.format(average_sim))

    # different commits different funcs

    sim_list = []
    pool = mp.Pool(threads)
    result = [pool.apply_async(compare_two_funcs, args=(choosen_opt(commits[choosen_commit]), funcs[choosen_func], 
                                                        choosen_opt(commits[i]), funcs[j]))
                                                        for i in range(5) for j in range(10)
                                                        if i!=choosen_commit or j!=choosen_func]
    pool.close()
    for p in result:
        res = p.get()
        sim_list.append(res[0])
        sim_data = {**sim_data, **res[1]}
    # sim_list += [p.get() for p in result]

    average_sim = list_average(sim_list)
    print('average similarity among different funcs in different commits with optimization as O2: {}'.format(average_sim))
    with open('conclusion', 'a+') as f:
        f.write('average similarity among different funcs in different commits with optimization as O2: {}\n'.format(average_sim))
        f.write('---------------------------------------------------------')
    
    with open('exec_result.json', 'a+') as f:
        json.dump(sim_data, f)
