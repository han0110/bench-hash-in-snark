#!/bin/sh

measure_peak_memory() {
    OS=$(uname -s)

    if [ $OS = 'Darwin' ]; then V='B '; fi
    AWK_SCRIPT="{ split(\"${V}KB MB GB TB\", v); s=1; while(\$1>1024 && s<9) { \$1/=1024; s++ } printf \"%.2f %s\", \$1, v[s] }"

    if [ $OS = 'Darwin' ]; then
        $(which time) -l "$@" 2>&1 | grep 'maximum resident set size' | grep -E -o '[0-9]+' | awk "$AWK_SCRIPT"
    else
        $(which time) -f '%M' "$@" 2>&1 | grep -E -o '^[0-9]+' | awk "$AWK_SCRIPT"
    fi
}

PACKAGE=$1
HASH=$2
LOG_PERMUTATIONS=$3

export RAYON_NUM_THREADS=${RAYON_NUM_THREADS:=4}
RUN="cargo --quiet run --release -- --hash $HASH --log-permutations $LOG_PERMUTATIONS"
OUTPUT="report/t${RAYON_NUM_THREADS}_${HASH}_lp${LOG_PERMUTATIONS}"

cd $PACKAGE
mkdir -p report

# Measure time and throughput
$RUN --sample-size 10 > $OUTPUT

# Measure peak memory
printf '%s' '  peak mem: ' >> $OUTPUT
measure_peak_memory $RUN >> $OUTPUT
