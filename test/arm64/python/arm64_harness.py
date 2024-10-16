import sys
from unicorn import *
from unicorn.arm64_const import *
import subprocess

# Define start address and input size
ADDRESS = 0x1000000
INPUT_SIZE = 1024


def fuzz_input(data):
    try:
        # Initialize Unicorn Engine for ARM64 architecture
        uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)

        # Map 2MB memory for emulation
        uc.mem_map(ADDRESS, 2 * 1024 * 1024)

        # Write the provided data into the emulated memory at
        # the starting address
        uc.mem_write(ADDRESS, data)

        # Emulate the execution of the ARM64 code starting at ADDRESS
        uc.emu_start(ADDRESS, ADDRESS + len(data))

    except UcError as e:
        print(f"Unicorn error: {e}")


if __name__ == "__main__":
    subprocess.run(
        ["touch",
         "/home/f5adff/dev/fuzzy-ghidra/test/arm64/output/default/.cur_input"])
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <input_file>")
        sys.exit(1)

    # Read the input file that will be passed to the harness
    with open(sys.argv[1], "rb") as f:
        input_data = f.read(INPUT_SIZE)

    # Pass the input data to the fuzzing harness
    fuzz_input(input_data)
