import os
import struct
from unicorn import *
from unicorn.arm64_const import *

# Initialize the ARM64 Emulator
ADDRESS = 0x10000
STACK_ADDR = 0x0
STACK_SIZE = 0x10000
MEMORY_SIZE = 2 * 1024 * 1024  # 2MB memory

# ARM64 code to be emulated (this is a simple test case)
ARM64_CODE = b"\x21\x00\x80\xd2"  # mov x1, #1


def fuzz(data):
    # Initialize Unicorn engine in ARM64 mode
    mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)

    # Map 2MB memory for this emulation
    mu.mem_map(ADDRESS, MEMORY_SIZE)

    # Write the ARM64 code to be emulated to memory
    mu.mem_write(ADDRESS, ARM64_CODE)

    # Map a stack for the emulation
    mu.mem_map(STACK_ADDR, STACK_SIZE)
    mu.reg_write(UC_ARM64_REG_SP, STACK_ADDR + STACK_SIZE)

    # Load fuzzed input into x0 register
    if len(data) >= 8:  # Ensure we have enough bytes to treat as an input
        fuzzed_value = struct.unpack("<Q", data[:8])[0]  # Read 8 bytes from input
        mu.reg_write(UC_ARM64_REG_X0, fuzzed_value)
    else:
        mu.reg_write(UC_ARM64_REG_X0, 0)  # Default if input too short

    try:
        # Emulate the ARM64 code
        mu.emu_start(ADDRESS, ADDRESS + len(ARM64_CODE))

        # Read back registers
        x0 = mu.reg_read(UC_ARM64_REG_X0)
        x1 = mu.reg_read(UC_ARM64_REG_X1)

        print(f"Emulation done. X0 = {x0}, X1 = {x1}")

    except UcError as e:
        print(f"Error during emulation: {e}")


def main():
    # Read data from AFL++ (using stdin)
    data = os.read(0, 1024)  # Read up to 1024 bytes of fuzzed data
    fuzz(data)


if __name__ == "__main__":
    main()

