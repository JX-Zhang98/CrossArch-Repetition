#!/home/xianglin/.virtualenvs/angr/bin/ python
# -*- coding: utf-8 -*-
__Auther__ = 'xianglin'

from crc64iso.crc64iso import crc64


def io_tuple_to_checksum(io_tuple):
    """
    turn one IO pair to checksum

    Args:
        io_tuple: two list of input and output values, (input_list, output_list)

    Returns:
        io_checksum: the 64 bit crc check sum of input_length, input values, output values
    """
    input = io_tuple[0]
    output = io_tuple[1]
    input_length = len(input)
    s = str(input_length)
    for i in input:
        s = s + str(i)
    for i in output:
        s = s + str(i)
    io_checksum = crc64(s)
    return io_checksum


def bb_io_crcgroup_by_input_length(io_dict):
    """
    turn a BB of one round of sample values to checksum group by its input_length

    Args:
        io_dict: a dict mapping from addr to io_tuple
        for example:
        {0x203748982:([1,2],[3])}

    Returns:
        crc_group(dict): a dict mapping from input_length to chechksum list
        for example:
        {1:[crc1,crc2],2:[crc3, crc4]...}
        we observe that normally the keys would be less than 5, which means range is [0,4]
    """
    crc_group = {}
    for addr in io_dict.keys():
        input_list = io_dict[addr][0]
        input_length = len(input_list)
        if input_length not in crc_group.keys():
            crc_group[input_length] = []
        io_checksum = io_tuple_to_checksum(io_dict[addr])
        crc_group[input_length].append(io_checksum)
    return crc_group


def bb_all_io_to_checksum(io_list):
    """
    turn every round of sample value of a bb to checksum groups

    Args:
        io_list: a list of 4 dict, each dict is one round of sample value

    Returns:
        checksum_list: a list of 4 dict, which is crc_group(dict): a dict mapping from input_length to chechksum list
    """
    checksum_list = []
    for io_dict in io_list:
        bb_io_checksum = bb_io_crcgroup_by_input_length(io_dict)
        checksum_list. append(bb_io_checksum)
    return checksum_list


def func_io_to_checksum(func_sample_result):
    """
    turn the IO pairs in func sample result to checksum and group them by the input length

    Args:
        func_sample_result:

    Returns:
        func_sample_checksum(dict): mapping from bb addr to its sample result,
                                    sample_result(list): each element is one round of sampling result
                                    each sampling result is a dict mapping from input_length to a list of checksums
    """
    func_sample_checksum = {}
    for bb_addr in func_sample_result.keys():
        func_sample_checksum[bb_addr] = bb_all_io_to_checksum(func_sample_result[bb_addr])
    return func_sample_checksum
