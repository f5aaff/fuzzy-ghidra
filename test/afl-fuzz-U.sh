#!/bin/bash

# Check if the necessary arguments are provided
if [ "$#" -ne 3 ]; then
  echo "Usage: $0 <path_to_binary> <input_corpus_dir> <output_corpus_dir>"
  exit 1
fi

BINARY=$1             # The path to the binary to fuzz
INPUT_CORPUS=$2       # Directory with initial seed inputs
OUTPUT_CORPUS=$3      # Directory to store AFL++ outputs

# Check if afl-fuzz and afl-showmap are available
if ! command -v afl-fuzz &> /dev/null || ! command -v afl-showmap &> /dev/null; then
  echo "AFL++ and afl-showmap must be installed and available in your PATH."
  exit 1
fi

# Check if binary exists
if [ ! -f "$BINARY" ]; then
  echo "Binary not found: $BINARY"
  exit 1
fi

# Check if input corpus directory exists
if [ ! -d "$INPUT_CORPUS" ]; then
  echo "Input corpus directory not found: $INPUT_CORPUS"
  exit 1
fi

# Create output corpus directory if it doesn't exist
mkdir -p "$OUTPUT_CORPUS"

# Step 1: Fuzz the binary using AFL++ in Unicorn mode
echo "[*] Starting AFL++ fuzzing in Unicorn mode..."
afl-fuzz -U -i "$INPUT_CORPUS" -o "$OUTPUT_CORPUS" -- "$BINARY" @@

# Check if AFL++ fuzzing completed successfully
if [ $? -ne 0 ]; then
  echo "[!] AFL++ fuzzing failed."
  exit 1
fi

echo "[*] Fuzzing completed. Now generating code coverage with afl-showmap..."

# Step 2: Generate coverage report using afl-showmap

COVERAGE_DIR="$OUTPUT_CORPUS/coverage_maps"
mkdir -p "$COVERAGE_DIR"

# Process crashes from AFL++ output
for crash_file in "$OUTPUT_CORPUS/crashes/id"*; do
  if [ -f "$crash_file" ]; then
    echo "[*] Processing crash file: $crash_file"
    # Generate coverage map using afl-showmap
    afl-showmap -m none -q -o "$COVERAGE_DIR/coverage_$(basename $crash_file).map" -- "$BINARY" < "$crash_file"
  fi
done

# Process queue inputs from AFL++ output
for queue_file in "$OUTPUT_CORPUS/queue/id"*; do
  if [ -f "$queue_file" ]; then
    echo "[*] Processing queue file: $queue_file"
    # Generate coverage map using afl-showmap
    afl-showmap -m none -q -o "$COVERAGE_DIR/coverage_$(basename $queue_file).map" -- "$BINARY" < "$queue_file"
  fi
done

echo "[*] Coverage maps generated in $COVERAGE_DIR."

total_maps=$(ls "$COVERAGE_DIR" | wc -l)
echo "[*] Total coverage maps generated: $total_maps"

