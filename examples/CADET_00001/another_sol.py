import angr
import claripy
from angr.sim_state import SimState
from angr.storage.file import SimPackets, SimFile
from claripy.ast.bv import BV
from typing import List, Tuple

def inspect_function(s: SimState):
    if s.addr != 0x08048676:
        return # Only interested in the "read" call as it won't return
    # As x86-32 uses cdecl, the first argument is at ESP + 4
    fd = s.mem[s.regs.esp].uint32_t.resolved
    buf = s.mem[s.regs.esp + 4].uint32_t.resolved
    count = s.mem[s.regs.esp + 8].uint32_t.resolved
    # Output the arguments for debugging
    print(f"read() called with fd={fd}, buf={buf}, count={count}")
    # Check if any of the arguments are symbolic
    if s.solver.symbolic(fd) or s.solver.symbolic(buf) or s.solver.symbolic(count):
        print("read() called with symbolic arguments, skipping execution to avoid overconstraining.")
        s.skip_function()

def main():
    # Load the binary into an angr project
    project = angr.Project('./CADET_00001.adapted', auto_load_libs=False)

    # Create a symbolic bitvector for input
    input_size = 100 # Adjust size as needed
    input_variable = claripy.BVS('input_variable', input_size * 8)
    input = angr.SimFile('/dev/stdin', content=input_variable)

    # Create an initial state with the symbolic input
    initial_state = project.factory.entry_state(
        args=['./CADET_00001.adapted'],
        stdin=input,
        add_options={
            angr.options.UNDER_CONSTRAINED_SYMEXEC,
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
        }
    )

    # Inspect the "read" function
    initial_state.inspect.b('instruction', when=angr.BP_BEFORE, action=inspect_function)

    # Constraint input to be printable characters or null bytes
    for byte in input_variable.chop(8):
        initial_state.solver.add(
            claripy.Or(
                claripy.And(byte >= 0x20, byte <= 0x7e),  # Printable ASCII
                byte == 0x30  # Null byte
            )
        )

    # Create a simulation manager
    simgr = project.factory.simulation_manager(initial_state)

    # Explore the binary to find a state that reaches the success address
    avoid_addresses = [0x804875a, 0x804877f, 0x804879b, 0x80487a4]
    success_address = [0x80487f7, 0x80488f4]  # 0x80487f7:Final suc; 0x80488f4: easter egg

    # addr = 0x8048808 # entered check func
    # addr = 0x804885a # ready to call receive_delim
    # addr = 0x804885f # after receive_delim - unreachable
    # addr = 0x80485c3 # ready to call receive
    # addr = 0x80485c8 # after receive - unreachable
    # addr = 0x8048676 # before calling read
    # addr = 0x804867b # after read - unreachable
    # success_address.append(addr)

    simgr.explore(find=success_address, avoid=avoid_addresses)

    if simgr.found:
        state = simgr.found[0]
        import sys
        # solution = state.posix.dumps(sys.stdin.fileno())
        # Alternatively, evaluate the symbolic inputs directly
        solution = state.solver.eval(input_variable, cast_to=bytes)
        print(f'Solution found: {solution}')
    elif simgr.unconstrained:
        unconstrained_state = simgr.unconstrained[0]
        solution = unconstrained_state.solver.eval(input_variable, cast_to=bytes)
        print(f'[WARNING!!!] Solution found in unconstrained state: {solution}')
    else:
        print('No solution found.')

if __name__ == '__main__':
    main()