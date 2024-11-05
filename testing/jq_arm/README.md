harness and jq bin. for ARMx64


run ```./run_jq_fuzz.sh afl```
to run the following command:
```bash
AFL_DEBUG=1 afl-fuzz -U -m none -i sample_inputs -o output -- python test_harness_with_cov_query.py @@
```

run ```./run_jq_fuzz.sh py```
to run the following command:
```bash
python test_harness_with_cov_query ./sample_inputs/test.json
```
