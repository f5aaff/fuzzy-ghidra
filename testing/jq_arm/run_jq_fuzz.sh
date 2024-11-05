#!/bin/bash

MODE=$1

if [ "$MODE" == "afl"  ]; then

    AFL_DEBUG=1 afl-fuzz -U -m none -i ./sample_inputs/ -o output/ -- python test_harness_with_cov_query.py @@
    exit 0
fi

if [ "$MODE" == "py"  ]; then

    python ./test_harness_with_cov_query.py ./sample_inputs/test.json
    exit 0
fi


printf  "usage:\n\t'./run_jq_fuzz.sh afl' to run the full afl fuzz on the jq binary.\n\t'./run_jq_fuzz.sh py' to run just the test harness.\n"

