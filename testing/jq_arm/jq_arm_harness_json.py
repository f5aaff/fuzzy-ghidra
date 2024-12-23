import argparse
import os
from sys import stdin
import tempfile
import subprocess
import time
from unicornafl import *
from unicorn.arm64_const import *

coverage = set()

def coverage_hook(uc, address, size, user_data):
    coverage.add(address)

COVERAGE_FILE = "addresses"
BINARY_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "jq-linux-arm64"
    #os.path.dirname(os.path.abspath(__file__)), "run_jq_arm.sh"

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
    print("parsing args...")
    parser = argparse.ArgumentParser(description="Test harness for jq-linux-arm64")
    parser.add_argument("input_file", type=str, help="Path to the file containing the mutated input to load")
    parser.add_argument("-t", "--trace", default=True, action="store_true", help="Enables debug tracing")
    args = parser.parse_args()

    print("instancing UC...")
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)

    if args.trace:

        print("trace arg present, attaching UC hooks...")
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

    print("mapping CODE_ADDRESS and CODE_SIZE_MAX...")
    uc.mem_map(CODE_ADDRESS, CODE_SIZE_MAX)
    print("writing to CODE_ADDRESS...")
    uc.mem_write(CODE_ADDRESS, binary_code)

    start_address = CODE_ADDRESS
    uc.reg_write(UC_ARM64_REG_PC, start_address)

    uc.mem_map(STACK_ADDRESS, STACK_SIZE)
    uc.reg_write(UC_ARM64_REG_SP, STACK_ADDRESS + STACK_SIZE)
    uc.mem_map(DATA_ADDRESS, DATA_SIZE_MAX)
    print("using input file:",args.input_file)

# Wait until the input file is created
    input_file_path = args.input_file
    while not os.path.exists(input_file_path):
        print(f"Waiting for input file: {input_file_path}...")
        time.sleep(1)  # Wait for a second before checking again

    # Read the input file content
    print("reading input data from input file...")
    with open(args.input_file, 'r') as f:
        input_data = f.read()
        print("input data:",input_data)

    # Create a temporary file to simulate stdin for jq
    print("creating temprorary file to simulate stdin for jq...")
    with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
        tmp_file.write(input_data.encode())
        tmp_file.flush()
        tmp_file.seek(0)
        print("tmp_file contents: ",input_data)
        print("creating command for jq...")
        # Create the command to run jq
        jq_query = "."  # Change this to your desired jq query
        cmd = ["./jq-linux-arm64", jq_query]
        print("jq command: ",cmd)
        # Run the command with the temporary file as input

        print("running command...")
        process = subprocess.Popen(cmd, stdin=tmp_file, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        if process.returncode != 0:
            print(f"jq failed with error: {stderr.decode()}")
            return

        # Handle output, which can be written to a memory location
        output_data = stdout.decode()
        print("process finished with exit code:",process.returncode)
        print("output: "+output_data)

        # Check if output_data size is acceptable
        if len(output_data) > DATA_SIZE_MAX:
            print(f"Output data is too large (> {DATA_SIZE_MAX} bytes)")
            return

        # Place input callback for AFL
        def place_input_callback(uc, input_data, persistent_round, data):
            uc.mem_write(DATA_ADDRESS, input_data)

        print("writing output to designated location for fuzzing...")
        # Write output to the designated memory location for fuzzing
        uc.mem_write(DATA_ADDRESS, output_data.encode())
        # Optionally, set the exit conditions
        end_address = CODE_ADDRESS + 0xF4  # Adjust based on jq's exit handling
        print("running uc_afl_fuzz...")
        uc_afl_fuzz(uc=uc, input_file=args.input_file, place_input_callback=place_input_callback, exits=[end_address])
        print("done")
if __name__ == "__main__":
    main()

