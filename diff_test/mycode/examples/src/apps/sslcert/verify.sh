
#!/bin/bash
# $1 : fuzz_out folder
# /home/quanlili/afl2/afl-fuzz -i ./update_seeds_der_test -o $1 -m none -M fuzzer1 ./afl @@
# dir=`ls $1/fuzzer2/queue/`
rm verify_result.csv
echo "file_name,open_state,gnu_state,mbed_state,nss_state,wolf_state,libressl_state" >verify_result.csv
rename "s/,/_/" $1/fuzzer2/queue/*
rename "s/,/_/" $1/fuzzer2/queue/*
rename "s/,/_/" $1/fuzzer2/queue/*
rename "s/ //" $1/fuzzer2/queue/*
rename "s/ //" $1/fuzzer2/queue/*
rename "s/ //" $1/fuzzer2/queue/*
for file in $1/fuzzer2/queue/* 
do
echo $file
    # ~/my_nezha/nezha-0.1/examples/src/apps/sslcert/afl  $file
    ./afl2  $file

done
cd /home/quanlili/PycharmProjects/untitled/diff 
cp verify_result.csv ./afl_result/verify_result.csv
python3 afl-diff.py
python3 sandiantu.py
