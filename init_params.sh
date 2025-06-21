#!/usr/bin/env bash

# prev_working_dir=$(pwd)
# if [ "$prev_working_dir" != "/home/doit_prj/proj/nanoBench" ]; then
#     cd "/home/doit_prj/proj/nanoBench"
# fi

source utils.sh

if [ "$EUID" -ne 0 ]; then
    echo "Error: FuzzerBench requires root privileges" >&2
    echo "Try \"sudo ./kernel-FuzzerBench.sh ...\"" >&2
    exit 1
fi

if [ ! -e /sys/FuzzerBench ]; then
    echo "Error: FuzzerBench kernel module not loaded" >&2
    echo "Load with \"sudo insmod kernel/FuzzerBench.ko\"" >&2
    exit 1
fi

if [ $(cat /sys/devices/system/cpu/smt/active) -ne 0 ]; then
    echo "Note: Hyper-threading is enabled; it can be disabled with \"sudo ./disable-HT.sh\"" >&2
fi


reset=1
for arg in "$@"; do
    if [[ "$arg" == "-asm" ]]; then
        reset=0
    fi
done

if [[ $reset -eq 1 ]]; then
    cat /sys/FuzzerBench/reset
fi

while [ "$1" ]; do
    if [[ "$1" == -asm_i* ]]; then
        assemble "$2" asm-init.bin
        echo -n "asm-init.bin" > /sys/FuzzerBench/init
        rm -f asm-init.bin
        shift 2
    elif [[ "$1" == -asm_l* ]]; then
        assemble "$2" asm-late-init.bin
        echo -n "asm-late-init.bin" > /sys/FuzzerBench/late_init
        rm -f asm-late-init.bin
        shift 2
    elif [[ "$1" == -asm_o* ]]; then
        assemble "$2" asm-one-time-init.bin
        echo -n "asm-one-time-init.bin" > /sys/FuzzerBench/one_time_init
        rm -f asm-one-time-init.bin
        shift 2
    elif [[ "$1" == -as* ]]; then
        assemble "$2" asm-code.bin
        echo -n "asm-code.bin" > /sys/FuzzerBench/code
        rm -f asm-code.bin
        shift 2
    elif [[ "$1" == -code_i* ]]; then
        echo -n "$2" > /sys/FuzzerBench/init
        shift 2
    elif [[ "$1" == -code_l* ]]; then
        echo -n "$2" > /sys/FuzzerBench/late_init
        shift 2
    elif [[ "$1" == -code_o* ]]; then
        echo -n "$2" > /sys/FuzzerBench/one_time_init
        shift 2
    elif [[ "$1" == -cod* ]]; then
        echo -n "$2" > /sys/FuzzerBench/code
        shift 2
    elif [[ "$1" == -cpu ]]; then
        echo -n "$2" > /sys/FuzzerBench/cpu
        shift 2
    elif [[ "$1" == -con* ]]; then
        echo -n "$2" > /sys/FuzzerBench/config
        shift 2
    elif [[ "$1" == -f* ]]; then
        echo "1" > /sys/FuzzerBench/fixed_counters
        shift
    elif [[ "$1" == -msr* ]]; then
        echo -n "$2" > /sys/FuzzerBench/msr_config
        shift 2
    elif [[ "$1" == -u* ]]; then
        echo "$2" > /sys/FuzzerBench/unroll_count
        shift 2
    elif [[ "$1" == -l* ]]; then
        echo "$2" > /sys/FuzzerBench/loop_count
        shift 2
    elif [[ "$1" == -no_m* ]]; then
        echo "1" > /sys/FuzzerBench/no_mem
        shift
    elif [[ "$1" == -no_n* ]]; then
        echo "1" > /sys/FuzzerBench/no_normalization
        shift
    elif [[ "$1" == -num_inputs ]]; then
        echo "$2" > /sys/FuzzerBench/num_inputs
        shift 2
    elif [[ "$1" == -n_reps ]]; then
        echo "$2" > /sys/FuzzerBench/n_reps
        shift 2
    elif [[ "$1" == -seed ]]; then
        echo "$2" > /sys/FuzzerBench/seed
        shift 2
    elif [[ "$1" == -n* ]]; then
        echo "$2" > /sys/FuzzerBench/n_measurements
        shift 2
    elif [[ "$1" == -b* ]]; then
        echo "1" > /sys/FuzzerBench/basic_mode
        shift
    elif [[ "$1" == -v* ]]; then
        echo "1" > /sys/FuzzerBench/verbose
        shift
    elif [[ "$1" == -w* ]]; then
        echo "$2" > /sys/FuzzerBench/warm_up
        shift 2
    elif [[ "$1" == -initial* ]]; then
        echo "$2" > /sys/FuzzerBench/initial_warm_up
        shift 2
    elif [[ "$1" == -al* ]]; then
        echo "$2" > /sys/FuzzerBench/alignment_offset
        shift 2
    elif [[ "$1" == -df* ]]; then
        echo "1" > /sys/FuzzerBench/drain_frontend
        shift
    elif [[ "$1" == -min* ]]; then
        echo "min" > /sys/FuzzerBench/agg
        shift
    elif [[ "$1" == -max* ]]; then
        echo "max" > /sys/FuzzerBench/agg
        shift
    elif [[ "$1" == -med* ]]; then
        echo "med" > /sys/FuzzerBench/agg
        shift
    elif [[ "$1" == -avg* ]]; then
        echo "avg" > /sys/FuzzerBench/agg
        shift
    elif [[ "$1" == -ra* ]]; then
        echo "1" > /sys/FuzzerBench/output_range
        shift
    elif [[ "$1" == -re* ]]; then
        filter_output="grep -v 0.00"
        shift
    elif [[ "$1" == -h* ]]; then
        echo "kernel-FuzzerBench.sh usage:"
        echo
        echo "  -asm <code>:                    Assembler code string (in Intel syntax) to be benchmarked."
        echo "  -asm_init <code>:               Assembler code string (in Intel syntax) to be executed once in the beginning."
        echo "  -asm_late_init <code>:          Assembler code string (in Intel syntax) to be executed once immediately before the code to be benchmarked."
        echo "  -asm_one_time_init <code>:      Assembler code string (in Intel syntax) to be executed once before the first measurement."
        echo "  -code <filename>:               Binary file containing the code to be benchmarked."
        echo "  -code_init <filename>:          Binary file containing code to be executed once in the beginning."
        echo "  -code_late_init <filename>:     Binary file containing code to be executed once immediately before the code to be benchmarked."
        echo "  -code_one_time_init <filename>: Binary file containing code to be executed once before the first measurement."
        echo "  -config <filename>:             File with performance counter event specifications."
        echo "  -fixed_counters:                Reads the fixed-function performance counters.\n"
        echo "  -n_measurements <n>:            Number of times the measurements are repeated."
        echo "  -unroll_count <n>:              Number of copies of the benchmark code inside the inner loop."
        echo "  -loop_count <n>:                Number of iterations of the inner loop."
        echo "  -warm_up_count <n>:             Number of runs before the first measurement gets recorded."
        echo "  -initial_warm_up_count <n>:     Number of runs before any measurement is performed."
        echo "  -alignment_offset <n>:          Alignment offset."
        echo "  -df:                            Drains front-end buffers between executing code_late_init and code."
        echo "  -avg:                           Selects the arithmetic mean as the aggregate function."
        echo "  -median:                        Selects the median as the aggregate function."
        echo "  -min:                           Selects the minimum as the aggregate function."
        echo "  -max:                           Selects the maximum as the aggregate function."
        echo "  -range:                         Outputs the range of the measured values (i.e., the minimum and the maximum)."
        echo "  -basic_mode:                    Enables basic mode."
        echo "  -no_mem:                        The code for reading the perf. ctrs. does not make memory accesses."
        echo "  -no_normalization:              The measurement results are not divided by the number of repetitions."
        echo "  -remove_empty_events:           Removes events from the output that did not occur."
        echo "  -cpu <n>:                       Pins the measurement thread to CPU n."
        echo "  -verbose:                       Outputs the results of all performance counter readings."
        echo "  -num_inputs <n>:                Number of random inputs to be tested in each test."
        echo "  -seed <n>:                      Choose a custom seed for input generation."
        exit 0
    else
        echo "Invalid option: $1"
        exit 1
    fi
done

# cd $prev_working_dir

exit $return_value