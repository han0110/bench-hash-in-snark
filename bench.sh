#!/bin/sh

measure_peak_memory() {
    AWK_SCRIPT='function human_size(x) {
        if (x<1000) {return x " B"} else {x/=1024}
        s="MGTEPZY";
        while (x>=1000 && length(s)>1)
            {x/=1024; s=substr(s,2)}
        return int(x+0.5) " " substr(s,1,1) "B"
    } {sub(/^[0-9]+/, human_size($1)); print}'
    $(which time) -f '%M' "$@" 2>&1 | awk "$AWK_SCRIPT"
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
echo -n "  peak mem: " >> $OUTPUT
measure_peak_memory $RUN >> $OUTPUT
