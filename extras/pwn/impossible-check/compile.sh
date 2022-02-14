#!/usr/bin/bash

gcc main.c -o main -Wall -no-pie -Wl,-z,relro,-z,now
