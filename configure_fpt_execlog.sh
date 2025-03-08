#!/bin/bash
cp x86_64-fpt-softmmu.mak configs/targets/x86_64-softmmu.mak
./configure --target-list=x86_64-softmmu --enable-debug --disable-linux-io-uring --enable-plugins
