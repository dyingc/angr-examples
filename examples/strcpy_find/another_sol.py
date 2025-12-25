import angr
from angr.storage.file import SimPackets
import claripy
from angr.sim_state import SimState

# open the binary
binary_path = "./strcpy_test"
project = angr.Project(binary_path, auto_load_libs=False)

# Create two symbolic buffers
pwd = claripy.BVS("pwd", 27 * 8)  # symbolic buffer for password
msg = claripy.BVS("msg", (0x38 + 2) * 8)  # symbolic buffer for message
pwd_input = SimPackets(name='pwd_input', content=[pwd, msg])

# Create the initial state
initial_state = project.factory.entry_state(
    # stdin=pwd_input,
    args=[binary_path, pwd, msg],
    add_options={
        # angr.options.LAZY_SOLVES,
        angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
    }
)

# Add restrictions to the symbolic buffers
for byte in pwd.chop(8):
    initial_state.solver.add(byte >= 0x20)
    initial_state.solver.add(byte <= 0x7e)
for byte in msg.chop(8):
    # Or byte == 0 是必须的。否则，strcpy 复制字符串时遇到第一个 0 字节才会停止，有时候就会出现“不稳定“的现象，不会报出 unconstrained 状态
    initial_state.solver.add(claripy.Or(byte >= 0x20, byte == 0x0))
    initial_state.solver.add(byte <= 0x7e)

# Create simgr
simgr = project.factory.simulation_manager(initial_state)
simgr.stashes['found'] = []

blk = None

def breakpoint(state: SimState):
    if state.addr > 0x40061c or state.addr < 0x4005e6:
        for b in state.inspect._breakpoints.get('instruction'):
            state.inspect.remove_breakpoint('instruction', blk)
        return
    print(f"Breakpoint hit at {hex(state.addr)}")

# Manually step through the program
while len(simgr.active) > 0:
    for state in list(simgr.active):
        if state.addr == 0x400716 or state.addr == 0x40070a:
            simgr.move(from_stash='active', to_stash='deadended', filter_func=lambda s: s.addr == state.addr)
        elif state.addr == 0x400725:
            simgr.move(from_stash='active', to_stash='found', filter_func=lambda s: s.addr == state.addr)

    simgr.step()

# Output the results
if simgr.found:
    for state in simgr.found:
        print("\n\nFound a state at strcpy call:")
        print("Password:", state.solver.eval(pwd, cast_to=bytes))
        print("Message:", state.solver.eval(msg, cast_to=bytes))
else:
    print("\n\nNo states found at strcpy call.")
if simgr.unconstrained:
    for unconstrained_state in simgr.unconstrained:
        print("\n\n[WARNING!] Unconstrained state found:")
        print("Password:", unconstrained_state.solver.eval(pwd, cast_to=bytes))
        print("Message:", unconstrained_state.solver.eval(msg, cast_to=bytes))
        bb = unconstrained_state.solver.eval(msg, cast_to=bytes)
        for i, b in enumerate(bb):
            if b == 0:
                # null byte found
                print(f"0x{i:x}", end=' ')
        print()
        pass