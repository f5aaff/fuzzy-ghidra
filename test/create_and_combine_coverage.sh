#!/bin/bash


OUTPUT_DIR=$1
BINARY=$2

if [ ! -d "$OUTPUT_DIR" ]; then
    echo "$OUTPUT_DIR not found."
    exit 1
fi

TEMP_COVERAGE_DIR=$(mktemp -d)

for CRASH in "$OUTPUT_DIR/crashes/id*"; do
    if [ -f "$CRASH" ]; then
        afl-showmap -U -m none -o "$TEMP_COVERAGE_DIR/coverage_$(basename $CRASH).map" -- $BINARY < "$CRASH"
    fi
done

for QUEUE in "$OUTPUT_DIR/crashes/id*"; do
    if [ -f "$QUEUE" ]; then
        afl-showmap -U -m none -o "$TEMP_COVERAGE_DIR/coverage_$(basename $QUEUE).map" -- $BINARY < "$QUEUE"
    fi
done

COMBI_MAP=$TEMP_COVERAGE_DIR/COMBI_MAP
touch $COMBI_MAP
for MAP in "$TEMP_COVERAGE_DIR"; do
    if [ -f "$MAP" ]; then
        cat "$MAP" >> "$COMBI_MAP"
    fi
done

awk -F: '{arr[$1] += $2} END {for (i in arr) print i ":" arr[i]}' "$COMBI_MAP"

cp -r $TEMP_COVERAGE_DIR ./
cp $COMBI_MAP ./
