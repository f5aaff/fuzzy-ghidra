#!/bin/bash

RED="\e[31m"
GREEN="\e[32m"
NC="\e[0m"
TARGET_C=$1
OUTPUT_BIN=$2

prompt_to_install(){
    BIN=$1

    read -p "Do you wish to install this program? " yn
    case $yn in
        [Yy]* ) sudo apt-get install -y $BIN;;
        [Nn]* ) exit;;
        * ) echo "Please answer yes or no.";;
    esac
}

if [ -z "$(which mips-linux-gnu-gcc)" ]; then

    printf "$REDmips-linux-gnu-gcc bin not found. $NC\n"
    prompt_to_install "mips-linux-gnu-gcc"
fi

mips-linux-gnu-gcc -o "$OUTPUT_BIN.elf" "$TARGET_C" -fPIC-O0 -nostdlib

if [ -z "$(which mips-linux-gnu-objcopy)" ]; then

    printf "$RED mips-linux-gnu-objcopy bin not found. $NC\n"
    prompt_to_install "mips-linux-gnu-objcopy"
fi


mips-linux-gnu-objcopy -O binary --only-section=.text "$OUTPUT_BIN.elf" "$OUTPUT_BIN.bin"


printf "$GREEN done.\n $NC"
