from unicorn import *
from unicorn.x86_const import *

def unicorn_harness(input_data):
    ADDRESS = 0x1000000  # Define memory address where to load the binary code

    uc = Uc(UC_ARCH_X86, UC_MODE_64)  # x86-64 emulation
    uc.mem_map(ADDRESS, 2 * 1024 * 1024)  # 2MB memory

    binary_code = b'\x90\x90\x90...'  # Use the binary bytes extracted from Ghidra
    uc.mem_write(ADDRESS, binary_code)  # Load binary code into Unicorn's memory

    uc.reg_write(UC_X86_REG_RIP, ADDRESS)  # Set the instruction pointer (RIP)
    uc.reg_write(UC_X86_REG_RSP, ADDRESS + 0x2000)  # Set the stack pointer (RSP)

    try:
        uc.emu_start(ADDRESS, ADDRESS + len(binary_code))  # Start emulation
    except UcError as e:
        print("Emulation error:", e)

