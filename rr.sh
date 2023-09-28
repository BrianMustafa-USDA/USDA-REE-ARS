#!/bin/bash

sleepy_time=5

counter=1
while [ $counter ]
do
  printf "\r$counter"
  counter=`expr $counter + 1`
  sleep $sleepy_time
done
