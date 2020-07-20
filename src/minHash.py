#!/home/xianglin/.virtualenvs/angr/bin/ python
# -*- coding: utf-8 -*-
__Auther__ = 'xianglin'

from datasketch import MinHash


def compare_two_group(crc_list1, crc_list2):
    """
    return the jaccard similarity of two list, based on MinHash

    Args:
        crc_list1(list):a list contains of crc values
        crc_list2

    Returns:
        similarity: the similarity between two lists, range [0, 1]
    """
    m1, m2 = MinHash(num_perm=800), MinHash(num_perm=800)
    for crc in crc_list1:
        m1.update(crc.encode('utf8'))
    for crc in crc_list2:
        m2.update(crc.encode('utf8'))
    similarity = m1.jaccard(m2)
    return similarity


def compare_two_bb(bb1, bb2):
    """
    compare the similarity of two bb

    Args:
        bb1(dict): a dict mapping from input_length to a list of chechsums
        bb2(dict)

    Returns:
        similarity(float): the similarity between two basic blocks
    """
    if bb1 == {} and bb2 == {}:
        return 1
    if bb1 == {} or bb2 == {}:
        return 0
    weight_sim = 0
    weight = 0.0
    for input_length in range(5):
        if input_length in bb1.keys() and input_length in bb2.keys():
            w_i = len(bb1[input_length])
            w_i2 = len(bb2[input_length])
            weight = weight + w_i + w_i2
            sim = compare_two_group(bb1[input_length], bb2[input_length])
            weight_sim = weight_sim + sim * (w_i + w_i2)
        elif input_length in bb1.keys() and input_length not in bb2.keys():
            w_i = len(bb1[input_length])
            w_i2 = 0
            weight = weight + w_i + w_i2
        elif input_length not in bb1.keys() and input_length  in bb2.keys():
            w_i = len(bb2[input_length])
            w_i2 = 0
            weight = weight + w_i + w_i2
        else:
            continue
    return weight_sim / weight


def compare_two_bb_4times(bb1, bb2):
    """
    compare all 4 times of sampling of bb

    Args:
        bb1(list): each element is a dict mapping from input_length to a list of chechsums
        bb2(list)

    Returns:
        similarity(float): the average similarity of 4 times of sampling
    """
    sim = 0.0
    for i in range(4):
        sim = sim + compare_two_bb(bb1[i], bb2[i])
    sim = sim / 4
    return sim


if __name__ == "__main__":
    data1 = ['minhash', 'is', 'a', 'probabilistic', 'data', 'structure', 'for',
             'estimating', 'the', 'similarity', 'between', 'datasets']
    data2 = ['minhash', 'is', 'a', 'probability', 'data', 'structure', 'for',
             'estimating', 'the', 'similarity', 'between', 'documents']
    s = compare_two_group(data1, data2)
    print(s)

