#!/home/xianglin/.virtualenvs/angr/bin/ python
# -*- coding: utf-8 -*-
__Auther__ = 'JX_Zhang', 'xianglin'

import angr
import claripy
import BlockParser
import SampleValues
import PreprocessingFunc
import time


TOTAL_SAMPLE_TIMES = 4
sample_values = SampleValues.SampleValues.sample_example
indata = {}
outdata = {}
invar = {}
outvar = {}
sample_times = 1


def analysis_IR(block):
    """
    analysis the vex of a block, give out the input tmp and output tmp corresponding to every instruction

    Args:
        block: an block to be analysis

    Returns:
        invar: dict, mapping addr to input var
        outvar: dict, mapping addr to output var

        Two dicts mapping addrs to the corresponding input and output var.
        For example:
        invar: ({0x8048522:['44'], 0x8048525:[], 0x8048527:['45'], 0x804852a:['44', '8'], ...},
        outvar: {0x8048522:['45'], 0x8048525:[], 0x8048527:['4'], ...})

        the tmp in each example is listed according to the order of appearance

    """
    input_tmp, output_tmp = BlockParser.get_io_var_from_block(block)
    return input_tmp, output_tmp


def init_state(bin, block_addr):
    """
    init state to do dynamic analysis, it's a blank state
    we sample value while executing

    Args:
        bin: an angr project
        block_addr: the addr of the block that we are going to analysis

    Returns:
        state: a blank state
    """
    inited_state = bin.factory.blank_state(addr=block_addr)
    return inited_state


def change_tmp_value_before_write(state):
    """
    change the tmp value before being written, wo we can decide what value to be written to a specific tmp

    Args:
        state: the state in execution

    Global Args:
        outvar: a dict mapping from addr to a list of output tmp num(str)
        invar: a dict mapping from addr to a list of input tmp num(str)
        sample_values:
        sample_times: a integer, the ith time for sampling, which is used for looking for the right sample value

    Returns:
        None

        We record the true value in indata and outdata
        Two dicts mapping addrs to the corresponding input and output value.
        For example:
        in_data: ({0x8048522:[55], 0x8048525:[], 0x8048527:['379], 0x804852a:[44, 8], ...},
        out_data: {0x8048522:[47], 0x8048525:[], 0x8048527:[10], ...})
    """
    if state.inspect.instruction is None:
        return
    global outvar
    global invar
    global sample_values
    global sample_times
    addr = state.inspect.instruction
    # print("tmp write at " + hex(addr))

    # if tmp in input then change its value to sample value
    if addr in invar.keys() and str(state.inspect.tmp_write_num) in invar[addr]:
        if addr not in indata:
            indata[addr] = []
        input_length = len(invar[addr])
        input_index = invar[addr].index(str(state.inspect.tmp_write_num))
        input_value = sample_values[sample_times-1][input_length - 1][input_index]
        tmp_length = state.inspect.tmp_write_expr.length
        state.inspect.tmp_write_expr = claripy.BVV(input_value, tmp_length)
        # print("t"+str(state.inspect.tmp_write_num)+" belongs to input var")
        # print("set input t"+str(state.inspect.tmp_write_num)+" to value {}".format(hex(input_value)))
        if len(indata[addr]) == input_index:
            indata[addr].append(state.solver.eval(state.inspect.tmp_write_expr))

    if addr in outvar.keys() and str(state.inspect.tmp_write_num) in outvar[addr]:
        if addr not in outdata:
            outdata[addr] = [0 for n in range(len(outvar[addr]))]
        if str(state.inspect.tmp_write_num) in invar[addr]:
            input_length = len(invar[addr])
            input_index = invar[addr].index(str(state.inspect.tmp_write_num))
            input_value = sample_values[sample_times - 1][input_length - 1][input_index]
            output_index = outvar[addr].index(str(state.inspect.tmp_write_num))
            outdata[addr][output_index] = input_value
        else:
            output_index = outvar[addr].index(str(state.inspect.tmp_write_num))
            outdata[addr][output_index] = state.solver.eval(state.inspect.tmp_write_expr)

    # print("Write ", state.inspect.tmp_write_expr, end="")
    # print(" to ", "t" + str(state.inspect.tmp_write_num))

    return


def change_tmp_value_after_read(state):
    """
        change the tmp value after being read, wo we can decide what value to be read from a specific tmp

        Args:
            state: the state in execution

        Global Args:
            indata: a dict mapping from addr to true input value
            outdata: a dict mapping from addr to true output value
            sample_values: a list of sample values
            sample_times: integer, the ith time of sampling, which is used for looking for sample value

        Returns:
            None

            We record the true value in indata and outdata
            Two dicts mapping addrs to the corresponding input and output value.
            For example:
            in_data: ({0x8048522:[55], 0x8048525:[], 0x8048527:['379], 0x804852a:[44, 8], ...},
            out_data: {0x8048522:[47], 0x8048525:[], 0x8048527:[10], ...})
        """
    if state.inspect.instruction is None:
        return
    global outdata
    global indata
    global sample_values
    global sample_times
    addr = state.inspect.instruction
    # print("tmp read at " + hex(addr))

    if addr in invar.keys() and str(state.inspect.tmp_read_num) in invar[addr]:
        if addr not in indata:
            indata[addr] = []
        # if tmp in input then change its value to sample value
        input_length = len(invar[addr])
        input_index = invar[addr].index(str(state.inspect.tmp_read_num))
        input_value = sample_values[sample_times-1][input_length - 1][input_index]
        tmp_length = state.inspect.tmp_read_expr.length
        state.inspect.tmp_read_expr = claripy.BVV(input_value, tmp_length)
        # print("t"+str(state.inspect.tmp_read_num)+" belong to input var")
        # print("set input t"+str(state.inspect.tmp_read_num)+" to value {}".format(hex(input_value)))
        if len(indata[addr]) == input_index:
            indata[addr].append(state.solver.eval(state.inspect.tmp_read_expr))

    if addr in outvar.keys() and str(state.inspect.tmp_read_num) in outvar[addr]:
        if addr not in outdata:
            outdata[addr] = [0 for n in range(len(outvar[addr]))]
        if str(state.inspect.tmp_read_num) in invar[addr]:
            input_length = len(invar[addr])
            input_index = invar[addr].index(str(state.inspect.tmp_read_num))
            input_value = sample_values[sample_times - 1][input_length - 1][input_index]
            output_index = outvar[addr].index(str(state.inspect.tmp_read_num))
            outdata[addr][output_index] = input_value
        else:
            output_index = outvar[addr].index(str(state.inspect.tmp_read_num))
            outdata[addr][output_index] = state.solver.eval(state.inspect.tmp_read_expr)

    # print("read ", state.inspect.tmp_read_expr, end="")
    # print(" from ", "t" + str(state.inspect.tmp_read_num))

    return


def sim_run_block(state):
    """
    dynamic run a block,

    Args:
        state: the init state
    Returns:
        pair: dict, mapping addrs to a tuple with 2 lists, which consists of values of input and output

        For example:
        pair{0x820394:([22,36,5],[12])}
    """
    global outdata
    global indata
    state.inspect.b("tmp_write", when=angr.BP_BEFORE, action=change_tmp_value_before_write)
    state.inspect.b("tmp_read", when=angr.BP_AFTER, action=change_tmp_value_after_read)
    state.step()
    pair = {}
    for addr in indata:
        if addr not in outdata.keys():
            outdata[addr] = []
        pair[addr] = (indata[addr], outdata[addr])
    return pair


def init_block_paramenters():
    """
    for every block before execution, init all the relevant parameters
    """
    global indata, outdata
    indata = {}
    outdata = {}


def sample_func(path, func_name):
    """
    sample a function from a binary

    Args:
        path: string, the path to a binary
        func_name: str, a function name to be sampled

    Global Args:
        sample_values: a list of value
        indata: a dict mapping from addr to  a list of true value of input tmp
        outdata: a dict mapping from addr to a list of true value of output tmp
        invar: a dict mapping from addr to a list of input tmp num(str)
        outvar: a dict mapping from addr to a list of output tmp num(str)
        sample_times: the ith round of sampling

    Returns:
        func_sample_result: a dict mapping from addr to a list of each sample round result

        the key-set is all the addr of every BB in this function
        the values-set is all the sample results for each block
        each value is a list of 4 dict, representing the 4 round of sampling
        each dict represent a round of sampling,  mapping from instruction addr to I/O pairs

        For example:
            {0x89237402:[{addr1:([1,2,3],[1,2,3]),addr2:([2],[3,4])},{},{},{}],
            0x829349023:[{},{},{},{}]}
        if the block has no I/O, it gives out addr:[{},{},{],{}]
    """
    global sample_values, indata, outdata, invar, outvar, sample_times

    # t0 = time.time()

    bin = angr.Project(path)
    block_list = BlockParser.get_block_list(path, func_name)

    # t1 = time.time()

    func_sample_result = {}
    for block in block_list:
        invar, outvar = analysis_IR(block)  # dictionary
        bb_sample_list = []
        # generate io pair
        for i in range(TOTAL_SAMPLE_TIMES):
            sample_times = i + 1
            init_block_paramenters()
            state = init_state(bin, block.addr)
            # print("block at addr:", str(block.addr), "start sampling in {} round... ".format(sample_times))
            io_pair = sim_run_block(state)
            bb_sample_list.append(io_pair)
            # print(io_pair)
        # print('one block done...')
        func_sample_result[block.addr] = bb_sample_list
    # print(func_sample_result)
    print("one function done...")

    # t2 = time.time()
    return func_sample_result


# if __name__ == "__main__":
    path = "/home/xianglin/Graduation/graduation/testcase/2423496af35d94a87156b063ea5cedffc10a70a1/vmlinux"
    # func = "dccp_rcv_state_process"
    # func = "snd_pcm_status"
    func = "show_stat"
    p = sample_func(path, func)
    # t0 = time.time()
    q = PreprocessingFunc.func_io_to_checksum(p)
    # t1 = time.time()
    # print("the time to load a function and sort all block is {} s".format(ti[1]-ti[0]))
    # print("the time to sample a function is {} s".format(ti[2] - ti[1]))
    # print("the time to turn io pairs to checksums of a function is {} s".format(t1-t0))

