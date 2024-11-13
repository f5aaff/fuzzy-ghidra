#!/usr/bin/env python3
import argparse
import os
from unicornafl import *
from unicorn.arm64_const import *

coverage = set()

def coverage_hook(uc, address, size, user_data):
    coverage.add(address)

COVERAGE_FILE = "addresses"
BINARY_FILE = os.path.join(
    #os.path.dirname(os.path.abspath(__file__)), "jq-linux-arm64"
    os.path.dirname(os.path.abspath(__file__)), "run_jq_arm.sh"
)
CODE_ADDRESS = 0x00100000  # Code region starts at 1 MB
CODE_SIZE_MAX = 0x00200000  # Code size set to 2 MB (up to 3 MB)

STACK_ADDRESS = 0x00400000  # Start stack at 4 MB
STACK_SIZE = 0x00040000  # Set stack size to 256 KB

DATA_ADDRESS = 0x00440000  # Data region follows stack at 4 MB + 256 KB
DATA_SIZE_MAX = 0x00100000  # Data size set to 1 MB


def unicorn_debug_instruction(uc, address, size, user_data):
    with open(COVERAGE_FILE, 'a') as f:
        if address not in coverage:
            coverage.add(address)
            f.write(f"0x{address:016x}\n")
            f.flush()

def unicorn_debug_block(uc, address, size, user_data):
    print("Basic Block: addr=0x{0:016x}, size=0x{1:016x}".format(address, size))


def unicorn_debug_mem_access(uc, access, address, size, value, user_data):
    if access == UC_MEM_WRITE:
        print(
            "        >>> Write: addr=0x{0:016x} size={1} data=0x{2:016x}".format(
                address, size, value
            )
        )
    else:
        print("        >>> Read: addr=0x{0:016x} size={1}".format(address, size))


def unicorn_debug_mem_invalid_access(uc, access, address, size, value, user_data):
    if access == UC_MEM_WRITE_UNMAPPED:
        print(
            "        >>> INVALID Write: addr=0x{0:016x} size={1} data=0x{2:016x}".format(
                address, size, value
            )
        )
    else:
        print(
            "        >>> INVALID Read: addr=0x{0:016x} size={1}".format(address, size)
        )

def main():
    parser = argparse.ArgumentParser(description="Test harness for jq-linux-arm64")
    parser.add_argument("input_file", type=str, help="Path to the file containing the mutated input to load")
    parser.add_argument("-t", "--trace", default=True, action="store_true", help="Enables debug tracing")
    args = parser.parse_args()

    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)

    if args.trace:
        uc.hook_add(UC_HOOK_BLOCK, unicorn_debug_block)
        uc.hook_add(UC_HOOK_CODE, unicorn_debug_instruction)
        uc.hook_add(UC_HOOK_CODE, coverage_hook)
        uc.hook_add(UC_HOOK_MEM_WRITE | UC_HOOK_MEM_READ, unicorn_debug_mem_access)
        uc.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_READ_INVALID, unicorn_debug_mem_invalid_access)

    print(f"Loading binary from {BINARY_FILE}")
    with open(BINARY_FILE, "rb") as binary_file:
        binary_code = binary_file.read()

    if len(binary_code) > CODE_SIZE_MAX:
        print(f"Binary code is too large (> {CODE_SIZE_MAX} bytes)")
        return

    uc.mem_map(CODE_ADDRESS, CODE_SIZE_MAX)
    uc.mem_write(CODE_ADDRESS, binary_code)

    start_address = CODE_ADDRESS
    end_address = CODE_ADDRESS + 0xF4
    uc.reg_write(UC_ARM64_REG_PC, start_address)

    uc.mem_map(STACK_ADDRESS, STACK_SIZE)
    uc.reg_write(UC_ARM64_REG_SP, STACK_ADDRESS + STACK_SIZE)
    uc.mem_map(DATA_ADDRESS, DATA_SIZE_MAX)

    def place_input_callback(uc, input, persistent_round, data):
        if len(input) > DATA_SIZE_MAX:
            return False
        uc.mem_write(DATA_ADDRESS, input)

    uc_afl_fuzz(uc=uc, input_file=args.input_file, place_input_callback=place_input_callback, exits=[end_address])

if __name__ == "__main__":
    main()

