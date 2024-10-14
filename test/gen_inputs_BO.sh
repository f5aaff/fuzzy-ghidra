#!/bin/bash

MAX=$1

if [[ -z "$MAX" ]]; then
    MAX=4
fi
PAYLOAD_LEN=2
for i in $(seq 1 "$MAX"); do
    FILE=input$i.txt
    echo $i >> $FILE
    TEXT=$(printf 'A%.0s' $(seq 1 $((PAYLOAD_LEN * 2))))
    echo $TEXT >> $FILE
    let "PAYLOAD_LEN++"
    echo $PAYLOAD_LEN
done

