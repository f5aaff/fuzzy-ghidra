#!/bin/bash

# Check if the necessary arguments are provided
if [ "$#" -ne 3 ]; then
  echo "Usage: $0 <path_to_binary> <afl_output_dir> <coverage_map_output>"
  exit 1
fi

BINARY=$1             # Path to the binary to fuzz
AFL_OUTPUT_DIR=$2     # AFL++ output directory (contains queue/ and crashes/)
COVERAGE_MAP=$3       # Output file for the merged coverage map

# Check if afl-showmap is available
if ! command -v afl-showmap &> /dev/null; then
  echo "afl-showmap must be installed and available in your PATH."
  exit 1
fi

# Check if binary exists
if [ ! -f "$BINARY" ]; then
  echo "Binary not found: $BINARY"
  exit 1
fi

# Check if AFL output directory exists
if [ ! -d "$AFL_OUTPUT_DIR" ]; then
  echo "AFL output directory not found: $AFL_OUTPUT_DIR"
  exit 1
fi

# Temp directory to store individual coverage maps
TEMP_COVERAGE_DIR="./maps"
mkdir -p $TEMP_COVERAGE_DIR
MERGED_COVERAGE_MAP="$TEMP_COVERAGE_DIR/merged_map"

# Process all files in crashes/ and queue/ to generate individual coverage maps

echo "[*] Generating coverage maps for each input..."

# Process crashes
for crash_file in "$AFL_OUTPUT_DIR/crashes/id"*; do
  if [ -f "$crash_file" ]; then
    echo "[*] Processing crash file: $crash_file"
    afl-showmap -m none -r -q -o "$TEMP_COVERAGE_DIR/coverage_$(basename $crash_file).map" -- "$BINARY" < "$crash_file"
  fi
done

# Process queue
for queue_file in "$AFL_OUTPUT_DIR/queue/id"*; do
  if [ -f "$queue_file" ]; then
    echo "[*] Processing queue file: $queue_file"
    afl-showmap -m none -r -q -o "$TEMP_COVERAGE_DIR/coverage_$(basename $queue_file).map" -- "$BINARY" < "$queue_file"
  fi
done

# Merge the coverage maps into a single coverage map

echo "[*] Merging coverage maps..."

# Initialize the merged coverage map file
touch $MERGED_COVERAGE_MAP
# Merge all the individual coverage maps
for map_file in "$TEMP_COVERAGE_DIR/coverage_"*; do
  if [ -f "$map_file" ]; then
    awk '{ print $1 }' "$map_file" >> "$MERGED_COVERAGE_MAP"
  fi
done

# Step 1: Collapse duplicate edge IDs by summing their hit counts
echo "[*] Collapsing duplicate edge IDs..."

awk -F: '{ hits[$1] += $2 } END { for (id in hits) print id ":" hits[id] }' "$MERGED_COVERAGE_MAP" > "${MERGED_COVERAGE_MAP}_collapsed"

# Step 2: Convert the collapsed coverage map to hexadecimal
echo "[*] Converting coverage map to hexadecimal..."

# Use awk to convert decimal edge IDs to hexadecimal
awk -F: '{ printf "0x%x:%d\n", $1, $2 }' "${MERGED_COVERAGE_MAP}_collapsed" > "${COVERAGE_MAP}_hex"

# Clean up temporary files
rm -rf "$TEMP_COVERAGE_DIR"

echo "[*] Final merged coverage map saved to: $COVERAGE_MAP"
echo "[*] Final merged coverage map in hexadecimal saved to: ${COVERAGE_MAP}_hex"

