#!/home/xianglin/.virtualenvs/angr/bin/ python
# -*- coding: utf-8 -*-
__Auther__ = 'xianglin'

import subprocess
import angr
import os
import pickle
import IPython
import claripy
import pyvex
import math


from tools.image import Image
from tools.util.asm import is_jump
from tools.util.log import logging

logging.basicConfig(level=logging.ERROR)

# TODO: useful
def print_io_pair(inputTmp, outputTmp):
    """
    print one io pair

    Args:
        inputTmp: a list of input tmp num(str)
        outputTmp: a list of output tmo num(str)

    Returns:
        None
    """
    print("Input Tmp :")
    for input in inputTmp:
        print("t"+input, end=", ")
    print("")
    print("Output Tmp :")
    for output in outputTmp:
        print("t"+output, end=", ")
    print("")


def get_io_from_one_instruction(statements, start, last):
    """
    get input and output tmp num list from one instruction

    Args:
        statements: statements from one block, (block.vex.statements)
        start: the index of start statement for the analyzed instruction
        last: the index after the last statement for the analyzed instruction

    Returns:
        statements[start].addr: the analyzed instruction addr
        input_tmp_list: a list of input tmp num(str)
        output_tmp_list: a list of putput tmp num(str)
    """
    print("-Instruction addr at "+hex(statements[start].addr)+" -")
    print("IRSB")
    for i in range(start, last):
        statements[i].pp()
    print("IO")
    input_tmp_list = []
    curr_tmp_set = set()
    output_tmp_list = []
    curr_tmp = ""
    for i in range(start+1, last):
        if statements[i].tag == "Ist_Put" or statements[i].tag == "Ist_PutI":
            if statements[i].data.tag == 'Iex_RdTmp':
                if str(statements[i].data.tmp) not in output_tmp_list:
                    output_tmp_list.append(str(statements[i].data.tmp))
                if str(statements[i].data.tmp) not in curr_tmp_set:
                    if str(statements[i].data.tmp) not in input_tmp_list:
                        input_tmp_list.append(str(statements[i].data.tmp))
        elif statements[i].tag == "Ist_Store":
            if statements[i].data.tag == "Iex_RdTmp":
                if str(statements[i].data.tmp) not in output_tmp_list:
                    output_tmp_list.append(str(statements[i].data.tmp))
            if statements[i].addr.tag == "Iex_RdTmp":
                if str(statements[i].addr.tmp) not in output_tmp_list:
                    output_tmp_list.append(str(statements[i].addr.tmp))
        elif statements[i].tag == "Ist_WrTmp":
            curr_tmp = str(statements[i].tmp)
            curr_tmp_set.add(curr_tmp)
            # assignment
            # Unop
            # Binop
            # const
            data = statements[i].data
            if data.tag == 'Iex_Get':
                if str(statements[i].tmp) not in input_tmp_list:
                    input_tmp_list.append(str(statements[i].tmp))
            elif data.tag == 'Iex_Load':
                if str(statements[i].tmp) not in input_tmp_list:
                    input_tmp_list.append(str(statements[i].tmp))
            elif data.tag == 'Iex_Unop':
                args = data.args[0]
                if args.tag == "Iex_RdTmp":
                    if str(args.tmp) not in curr_tmp_set and str(args.tmp) not in input_tmp_list:
                        input_tmp_list.append(str(args.tmp))
            elif data.tag == 'Iex_Binop':
                args1 = data.args[0]
                args2 = data.args[1]
                if args1.tag == 'Iex_RdTmp':
                    if str(args1.tmp) not in curr_tmp_set and str(args1.tmp) not in input_tmp_list:
                        input_tmp_list.append(str(args1.tmp))
                if args2.tag == 'Iex_RdTmp':
                    if str(args2.tmp) not in curr_tmp_set and str(args2.tmp) not in input_tmp_list:
                        input_tmp_list.append(str(args2.tmp))
            elif data.tag == 'Iex_RdTmp':
                if str(data.tmp) not in curr_tmp_set and str(data.tmp) not in input_tmp_list:
                    input_tmp_list.append(str(data.tmp))
            elif data.tag == 'Iex_Triop':
                args1 = data.args[0]
                args2 = data.args[1]
                args3 = data.args[2]
                if args1.tag == 'Iex_RdTmp':
                    if str(args1.tmp) not in curr_tmp_set and str(args1.tmp) not in input_tmp_list:
                        input_tmp_list.append(str(args1.tmp))
                if args2.tag == 'Iex_RdTmp':
                    if str(args2.tmp) not in curr_tmp_set and str(args2.tmp) not in input_tmp_list:
                        input_tmp_list.append(str(args2.tmp))
                if args3.tag == 'Iex_RdTmp':
                    if str(args3.tmp) not in curr_tmp_set and str(args3.tmp) not in input_tmp_list:
                        input_tmp_list.append(str(args3.tmp))
            elif data.tag == 'Iex_Qop':
                args1 = data.args[0]
                args2 = data.args[1]
                args3 = data.args[2]
                args4 = data.args[3]
                if args1.tag == 'Iex_RdTmp':
                    if str(args1.tmp) not in curr_tmp_set and str(args1.tmp) not in input_tmp_list:
                        input_tmp_list.append(str(args1.tmp))
                if args2.tag == 'Iex_RdTmp':
                    if str(args2.tmp) not in curr_tmp_set and str(args2.tmp) not in input_tmp_list:
                        input_tmp_list.append(str(args2.tmp))
                if args3.tag == 'Iex_RdTmp':
                    if str(args3.tmp) not in curr_tmp_set and str(args3.tmp) not in input_tmp_list:
                        input_tmp_list.append(str(args3.tmp))
                if args4.tag == 'Iex_RdTmp':
                    if str(args4.tmp) not in curr_tmp_set and str(args4.tmp) not in input_tmp_list:
                        input_tmp_list.append(str(args4.tmp))
            else:
                # TODO fill up all the possible operation
                # Iex_Const
                # Iex_ITE
                # Iex_CCall
                print("Unimplemented Operation!")
        elif statements[i].tag == "Ist_Exit":
            if str(statements[i].guard.tmp) not in output_tmp_list:
                output_tmp_list.append(str(statements[i].guard.tmp))
        elif statements[i].tag == "Ist_NoOp":
            pass
        else:
            # TODO
            # 'Ist_AbiHint'
            # 'Ist_CAS'
            # 'Ist_LLSC'
            # 'Ist_MBE'
            # 'Ist_Dirty'
            # 'Ist_LoadG'
            # 'Ist_StoreG'
            print("Unimplemented Operation!")

    if len(output_tmp_list) == 0 and curr_tmp != "":
        output_tmp_list.append(curr_tmp)

    return statements[start].addr, input_tmp_list, output_tmp_list


def get_io_var_from_block(targeted_block):
    """
    get input and output tmp num from a block

    Args:
        targeted_block

    Returns:
        in_var: a dict mapping instruction addr to input tmp num list
        out_var: a dict mapping instruction addr to output tmp num list

        For example:
        in_var      {0x8930482:['2','4']}
        out_var     {0x8930482:['5']}
    """
    vex = targeted_block.vex
    start = 0
    statements = vex.statements
    in_var = {}
    out_var = {}
    for last in range(1,len(statements)):
        if statements[last].tag == "Ist_IMark":
            addr, input_tmp_list, output_tmp_list = get_io_from_one_instruction(statements, start, last)
            in_var[addr] = list(input_tmp_list)
            out_var[addr] = list(output_tmp_list)
            start = last
    addr, input_tmp_list, output_tmp_list = get_io_from_one_instruction(statements, start, len(statements))
    in_var[addr] = list(input_tmp_list)
    out_var[addr] = list(output_tmp_list)

    return in_var, out_var


def get_block_list(path, func_name):
    """
    get block list of a specific function

    Args:
        path: a str, the path of analyzed binary
        func_name: a str, the name of targeted function name

    Returns:
        all_blocks: the block list of input function, sorted by the order of addr
    """
    img = Image(path)
    entry_base = img.get_symbol_addr(func_name)
    # if not entry_base:
    #     return
    func_cfg = img.get_cfg(func_name)
    func_cfg.normalize()
    all_nodes = []

    for n in func_cfg.nodes():
        if n.function_address == entry_base:
            all_nodes.append(n)
    all_nodes.sort(key=lambda CFGNodeA: CFGNodeA.addr)

    all_blocks = []
    for n in all_nodes:
        # n.block.pp()
        all_blocks.append(n.block)

    return all_blocks


if __name__ == "__main__":
    debug_vmlinux = "../testcase/2423496af35d94a87156b063ea5cedffc10a70a1/vmlinux"
    function_name = "dccp_rcv_state_process"
    blockList = get_block_list(debug_vmlinux, function_name)
    for block in blockList:
        print("---block addr at "+str(block.addr)+" ---")
        get_io_var_from_block(block)
        print("")
        block.vex.pp()


