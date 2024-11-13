#!/bin/bash

MODE=$1

if [ "$MODE" == "afl"  ]; then

    AFL_DEBUG=1 afl-fuzz -U -m none -i sample_inputs -o output -- python jq_arm_harness_json.py @@
    exit 0
fi

if [ "$MODE" == "py"  ]; then

    python jq_arm_harness_json.py ./sample_inputs/test.json
    exit 0
fi

if [ "$MODE" == "afl_sh" ]; then

    AFL_DEBUG=1 afl-fuzz -U -m none -i sample_inputs -o output -- python ./sh_jq_arm_harness_query.py @@
    exit 0
fi

printf  "usage:\n\t'./run_jq_fuzz.sh afl' to run the full afl fuzz on the jq binary.\n\t'./run_jq_fuzz.sh py' to run just the test harness.\n"

