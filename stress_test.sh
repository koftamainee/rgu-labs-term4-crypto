#!/bin/bash

seq 1 100 | xargs -n1 -P100 -I{} \
./build/Release/rc4_client_server/rc4_client files/instruction_rc4.txt
