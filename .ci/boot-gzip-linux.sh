#!/usr/bin/env bash

# Get the directory of this script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "${SCRIPT_DIR}/common.sh"

RET=0

# Allow timeout override for JIT tests (JIT compilation adds significant overhead)
TIMEOUT=${BOOT_TIMEOUT:-50}

COLOR_G='\e[32;01m' # Green
COLOR_R='\e[31;01m' # Red
COLOR_Y='\e[33;01m' # Yellow
COLOR_N='\e[0m'     # No color

MESSAGES=("${COLOR_G}OK!"
    "${COLOR_R}Fail to boot"
    "${COLOR_R}Fail to login"
    "${COLOR_R}Fail to run commands"
)

# Boot with gzipped images test
# Both gzipped
OPTS_BASE=" -k build/linux-image/Image.gz -i build/linux-image/rootfs.cpio.gz"
TEST_OPTIONS=("${OPTS_BASE}")
EXPECT_CMDS=('
    expect "buildroot login:" { send "root\n" } timeout { exit 1 }
    expect "# " { send "uname -a\n" } timeout { exit 2 }
    expect "riscv32 GNU/Linux" { send "\x01"; send "x" } timeout { exit 3 }
')
# gzipped kernel
OPTS_BASE=" -k build/linux-image/Image.gz -i build/linux-image/rootfs.cpio"
TEST_OPTIONS+=("${OPTS_BASE}")
EXPECT_CMDS+=('
    expect "buildroot login:" { send "root\n" } timeout { exit 1 }
    expect "# " { send "uname -a\n" } timeout { exit 2 }
    expect "riscv32 GNU/Linux" { send "\x01"; send "x" } timeout { exit 3 }
')
# gzipped rootfs.cpio
OPTS_BASE=" -k build/linux-image/Image -i build/linux-image/rootfs.cpio.gz"
TEST_OPTIONS+=("${OPTS_BASE}")
EXPECT_CMDS+=('
    expect "buildroot login:" { send "root\n" } timeout { exit 1 }
    expect "# " { send "uname -a\n" } timeout { exit 2 }
    expect "riscv32 GNU/Linux" { send "\x01"; send "x" } timeout { exit 3 }
')

for i in "${!TEST_OPTIONS[@]}"; do
    printf "${COLOR_Y}===== Test option: ${TEST_OPTIONS[$i]} =====${COLOR_N}\n"

    RUN_LINUX="build/rv32emu ${TEST_OPTIONS[$i]}"

    ASSERT expect <<- DONE
	set timeout ${TIMEOUT}
	spawn ${RUN_LINUX}
	${EXPECT_CMDS[$i]}
	DONE

    ret=$?
    RET=$((${RET} + ${ret}))
    cleanup

    printf "\nBoot Linux with gzipped images test: [ ${MESSAGES[$ret]}${COLOR_N} ]\n"
done

exit ${RET}
