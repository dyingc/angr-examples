import angr
from angr.storage.file import SimPackets
import claripy

proj = angr.Project('./yolomolo', auto_load_libs=False)

# 创建 20 字节的符号输入
buff = claripy.BVS('buff', 8 * 20)

buf_addr = 0x606000

state = proj.factory.call_state(
    0x400646, # GoHomeOrGoCrazy 函数的入口点
    buf_addr,
    add_options={
        angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
        angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
        angr.options.LAZY_SOLVES
    }
)

state.memory.store(buf_addr, buff)

# Hook ptrace 使其总是返回 -1 (表示失败)
class PtraceSuccess(angr.SimProcedure):
    def run(self, request, pid, addr, data):
        return -1

proj.hook_symbol('ptrace', PtraceSuccess())

def should_avoid(state):
    return b"NOPE" in state.posix.dumps(1)

simgr = proj.factory.simulation_manager(state)

simgr.explore(find=0x405a6e, avoid=should_avoid)

if simgr.found:
    solution = simgr.found[0].solver.eval(buff, cast_to=bytes)
    print(f"找到解: {solution}")
else:
    print("未找到解")