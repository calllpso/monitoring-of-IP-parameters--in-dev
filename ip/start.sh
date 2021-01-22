#!/bin/bash
sudo ./sniff
sleep 5
for ((i=1; i<=10; ))
do
	sudo ./sort
	sleep 5
	sudo ./entropy
	sleep 5
done
