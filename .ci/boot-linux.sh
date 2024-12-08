#!/usr/bin/env bash

function cleanup {
    sleep 1
    pkill -9 rv32emu
}

function ASSERT {
    $*
    local RES=$?
    if [ $RES -ne 0 ]; then
        echo 'Assert failed: "' $* '"'
        exit $RES
    fi
}

cleanup

TIMEOUT=50
EXE='build/rv32emu -k ./build/linux-image/Image -i ./build/linux-image/rootfs.cpio -b build/minimal.dtb'

ASSERT expect <<DONE
set timeout ${TIMEOUT}
spawn ${EXE}
expect "buildroot login:" { send "root\n" } timeout { exit 1 }
expect "# " { send "uname -a\n" } timeout { exit 2 }
expect "riscv32 GNU/Linux" { send "\x01"; send "x" } timeout { exit 3 }
DONE

ret=$?
cleanup

MESSAGES=("OK!" \
     "Fail to boot" \
     "Fail to login" \
     "Fail to run commands" \
)

COLOR_G='\e[32;01m' # Green
COLOR_N='\e[0m' # No color
printf "\n[ ${COLOR_G}${MESSAGES[$ret]}${COLOR_N} ]\n"

exit ${ret}
