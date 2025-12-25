import angr
import claripy
from angr.sim_state import SimState
from angr.storage.file import SimPackets

def main():
    # Load the binary into an angr project
    project = angr.Project('./CADET_00001.adapted', auto_load_libs=False)

    # Create a symbolic bitvector for input
    input_size = 100  # Adjust size as needed
    symbolic_input = claripy.BVS('symbolic_input', input_size * 8)
    input = SimPackets(name='input', content=[(symbolic_input, input_size)])

    # Create an initial state with the symbolic input
    initial_state = project.factory.entry_state(
        args=['./CADET_00001.adapted', symbolic_input],
        stdin=input
    )

    # Constraint input to be printable characters or null bytes
    for byte in symbolic_input.chop(8):
        initial_state.solver.add(
            claripy.Or(
                claripy.And(byte >= 0x20, byte <= 0x7e),  # Printable characters
                byte == 0x00  # Null byte
            )
        )

    # Create a simulation manager
    simgr = project.factory.simulation_manager(initial_state)

    # Explore the binary to find a state that reaches the success address
    avoid_addresses = [0x804875a, 0x804877f, 0x804879b, 0x80487a4]
    success_address = [0x80487f7, 0x80488f4]  # 0x80487f7:Final suc; 0x80488f4: easter egg

    addr = 0x8048808 # entered check fun
    addr = 0x804885a # ready to call receive_delim
    addr = 0x804885f # after receive_delim - unreachable
    success_address.append(addr)

    simgr.explore(find=success_address, avoid=avoid_addresses)

    if simgr.found:
        found_state = simgr.found[0]
        solution = found_state.solver.eval(symbolic_input, cast_to=bytes)
        print(f'Solution found: {solution}')
    elif simgr.unconstrained:
        unconstrained_state = simgr.unconstrained[0]
        solution = unconstrained_state.solver.eval(symbolic_input, cast_to=bytes)
        print(f'[WARNING!!!] Solution found in unconstrained state: {solution}')
    else:
        print('No solution found.')

if __name__ == '__main__':
    main()