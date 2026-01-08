import angr
import claripy
from angr.sim_state import SimState
from angr.storage.file import SimPackets, SimFile
from claripy.ast.bv import BV
from typing import List, Tuple
import time

def break_point_function(s: SimState):
    interested_addresses = [0x1321, 0x1329,    0x15e5, 0x162b, 0x1638, 0x163a]
    if s.addr in [s.project.loader.main_object.mapped_base + addr for addr in interested_addresses]:
        print(f"Hit breakpoint at address: {hex(s.addr)}")
        # Output the current timestamp
        print(f"Timestamp: {time.time()}")

        # Output the major registers for debugging
        print("EAX: ", s.regs.eax.concrete_value)
        print("EBX: ", s.regs.ebx.concrete_value)
        print("ECX: ", s.regs.ecx.concrete_value)
        print("EDX: ", s.regs.edx.concrete_value)
        print("ESP: ", s.regs.esp.concrete_value)
        print("EBP: ", s.regs.ebp.concrete_value)

def hook_check_input_char(s: SimState):
    # read one byte from stdin
    c = s.posix.stdin.read(pos=0, size=1)[0]
    # Constraint the character is visible
    s.solver.add(
        claripy.And(c >= 0x20, c <= 0x7e),  # Printable ASCII
    )
    return

def install_hooks(project: angr.Project):
    # Hook the function that checks input characters
    check_input_char_addr = project.loader.main_object.mapped_base + 0x16b0
    project.hook(check_input_char_addr, hook_check_input_char, length=0xa1)

def main():
    # Create a sim file which will be used as stdin
    input_size = 0x20
    input_variable = claripy.BVS('input_variable', input_size * 8)
    input = angr.SimFile('/dev/stdin', content=input_variable)

    # Load the binary into an angr project
    binary_path = './engine'
    project = angr.Project(binary_path, auto_load_libs=False)

    # Get the base address of the binary
    base_address = project.loader.main_object.mapped_base
    print(f"Base address of the binary: {hex(base_address)}")

    # Create an initial state with the symbolic input
    initial_state = project.factory.entry_state(
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
    install_hooks(project)

    # Create a simulation manager
    simgr = project.factory.simulation_manager(initial_state)

    # Explore the binary to find a state that reaches the success address
    addr = base_address + 0x132d
    simgr.explore(find=addr)

    if simgr.found:
        found_state = simgr.found[0]
        solution = found_state.solver.eval(input_variable, cast_to=bytes)
        print(f"Solution found: {solution}")
    else:
        print("No solution found.")

if __name__ == '__main__':
    main()
