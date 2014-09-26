#!/bin/sh
for i in bins/*.bin; do ./me7sum $i | grep uncorrect; done
