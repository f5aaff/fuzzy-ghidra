from unicorn import *
from unicorn.arm_const import *
import sys

# Constants
BINARY_PATH = "./jq-linux-arm64"
ADDRESS = 0x1000000  # Base address for the binary
STACK_ADDRESS = 0x2000000  # Stack address
STACK_SIZE = 0x20000
CODE_SIZE = 0x40000  # Allocate memory size for the binary

def load_binary(uc, path, base_address):
    with open(path, "rb") as f:
        binary = f.read()
    uc.mem_map(base_address, CODE_SIZE)
    uc.mem_write(base_address, binary)

def fuzz(data):
    print("UC init...")
    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)

    print("memory mapping...")
    # Map memory for the binary and stack
    uc.mem_map(ADDRESS, CODE_SIZE)
    uc.mem_map(STACK_ADDRESS, STACK_SIZE)

    print("stack pointer...")
    # Set up the stack pointer
    uc.reg_write(UC_ARM_REG_SP, STACK_ADDRESS + STACK_SIZE - 4)

    print("loading binary...")
    # Load the binary into Unicorn's memory
    load_binary(uc, BINARY_PATH, ADDRESS)

    print("setting up input...")
    # Set up input buffer in Unicorn memory
    input_address = STACK_ADDRESS + 0x1000
    uc.mem_write(input_address, data)
    uc.reg_write(UC_ARM_REG_R0, input_address)  # R0 often holds the first argument

    # Set PC to the entry point
    uc.reg_write(UC_ARM_REG_PC, ADDRESS)

    try:
        print("starting emu...")
        # Start emulation
        uc.emu_start(ADDRESS, ADDRESS + CODE_SIZE)
    except UcError as e:
        print(f"Unicorn error: {e}")

# Main fuzzing loop
if __name__ == "__main__":
    # Read fuzzed data from stdin (AFL++ uses this for input piping)
    data = sys.stdin.buffer.read()
    fuzz(data)

