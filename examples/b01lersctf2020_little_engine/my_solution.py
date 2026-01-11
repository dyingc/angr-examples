import angr
import claripy
from angr.sim_state import SimState
from angr.storage.file import SimPackets, SimFile
from claripy.ast.bv import BV
from typing import List, Tuple
import time

def break_point_function(s: SimState):
    interested_addresses = [0x188f, 0x1a60]
    if s.addr in [s.project.loader.main_object.mapped_base + addr for addr in interested_addresses]:
        print(f"\n\nHit breakpoint at address: {hex(s.addr)}")
        # Output the current timestamp
        print(f"Timestamp: {time.time()}")

        # Output the major registers for debugging
        print("EAX: ", s.regs.eax, "Symbolic: " , s.solver.symbolic(s.regs.eax))
        print("EBX: ", s.regs.ebx, "Symbolic: " , s.solver.symbolic(s.regs.ebx))
        print("ECX: ", s.regs.ecx, "Symbolic: " , s.solver.symbolic(s.regs.ecx))
        print("RDX: ", s.regs.rdx, "Symbolic: " , s.solver.symbolic(s.regs.rdx))
        print("ESP: ", s.regs.esp, "Symbolic: " , s.solver.symbolic(s.regs.esp))
        print("EBP: ", s.regs.ebp, "Symbolic: " , s.solver.symbolic(s.regs.ebp))
        print("RSI: ", s.regs.rsi, "Symbolic: " , s.solver.symbolic(s.regs.rsi))
        # Output the contents in [RBP + 0X8] for debugging
        rbp_plus_8 = s.memory.load(s.regs.ebp + 0x8, 8)
        print("Memory at [EBP + 0x8]: ", rbp_plus_8, "Symbolic: ", s.solver.symbolic(rbp_plus_8))
# 打印 angr 的基本块信息
def trace_blocks(s):
    block = s.project.factory.block(s.addr)
    print(f"Block at {hex(s.addr)}: size={block.size}, instructions={block.instructions}")

def hook_check_input_char(s: SimState):
    # read one byte from stdin
    c = s.posix.stdin.read(pos=0, size=1)[0]
    # Constraint the character is visible
    s.solver.add(
        claripy.And(c >= 0x20, c <= 0x7e),  # Printable ASCII
    )
    return

class OperatorNewHook(angr.SimProcedure):
    def run(self, size):
        # Allocate a symbolic buffer of the requested size
        ptr = self.state.heap.allocate(size)
        ptr = self.state.solver.eval(ptr) # Get concrete address
        print("Allocated memory (size: {} bytes) at address: {}".format(size, hex(ptr)))
        return ptr

class CinOperatorHook(angr.SimProcedure):
    def run(self, istream_ptr, string_ptr):
        # 读取符号输入
        state = self.state

        # 模拟 std::cin >> str 的行为
        # 1. 从 stdin 读取数据
        input_data = state.posix.stdin.read_from(0, self.state.libc.max_str_len)

        # 2. 设置 string 对象的字段
        # string 结构: {char* _M_dataplus, size_t _M_length, ...}
        # 假设输入长度是符号化的
        input_len = state.solver.BVS('input_len', 64)
        state.solver.add(input_len == len(input_data))

        # 写入 string->_M_dataplus (指向数据的指针)
        # 写入 string->_M_length (长度)
        state.memory.store(string_ptr + 8, input_len, endness='Iend_LE')

        # 返回 istream&
        return istream_ptr

def install_hooks(project: angr.Project):
    # Hook the function that checks input characters
    check_input_char_addr = project.loader.main_object.mapped_base + 0x16b0
    project.hook(check_input_char_addr, hook_check_input_char, length=0xa1)

    # Hook the operator.new function to allocate concrete memory
    operator_new_symbol_name = "_Znwm"  # mangled name for operator new
    project.hook_symbol(operator_new_symbol_name, OperatorNewHook())

    # Hook the std::cin >> std::string operator
    cin_operator_symbol_name = "_ZSt3cin"  # mangled name for std::cin
    project.hook_symbol(cin_operator_symbol_name, CinOperatorHook())

def main():
    # Create a sim file which will be used as stdin
    input_size = 0x200
    input_variable = claripy.BVS('input_variable', input_size * 8)
    input = angr.SimFile('/dev/stdin', content=input_variable)

    # Load the binary into an angr project
    binary_path = './engine'
    project = angr.Project(binary_path, auto_load_libs=True)

    # Get the base address of the binary
    base_address = project.loader.main_object.mapped_base
    print(f"Base address of the binary: {hex(base_address)}")

    # Create an initial state with the symbolic input
    initial_state = project.factory.full_init_state(
        args=[binary_path],
        # addr=base_address + 0x12f0,
        stdin=input,
        add_options={
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
        }
    )

    # Inspect the breakpoint function
    initial_state.inspect.b('instruction', when=angr.BP_BEFORE, action=break_point_function)

    # Install hooks
    # install_hooks(project)

    # Create a simulation manager
    simgr = project.factory.simulation_manager(initial_state)

    # # Explore the binary to find a state that reaches the success address
    # addr = base_address + 0x132d
    # simgr.explore(find=addr)

    simgr.run()

    if simgr.found:
        found_state = simgr.found[0]
        solution = found_state.solver.eval(input_variable, cast_to=bytes)
        print(f"Solution found: {solution}")
    else:
        print("No solution found.")

if __name__ == '__main__':
    main()
