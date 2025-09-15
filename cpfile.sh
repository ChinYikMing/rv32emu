#!/usr/bin/env bash

program=$1

riscv32-buildroot-linux-gnu-gcc "$program.c" -o $program
sudo mount disk1.img mnt
sudo cp $program mnt
sudo umount mnt
