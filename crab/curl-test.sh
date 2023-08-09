#!/bin/bash

EXPECTED_OUTPUT="<!DOCTYPE html>
<html>"

for i in {1..1000}
do
    OUTPUT=$(curl -s 10.96.0.101 | head -2)
    if [ "$OUTPUT" != "$EXPECTED_OUTPUT" ]; then
        echo "Output does not match expected on iteration $i"
        exit 1
    fi
done

echo "All 1000 iterations produced the expected output!"


##nano test_curl.sh
##chmod +x test_curl.sh
##  ./test_curl.sh