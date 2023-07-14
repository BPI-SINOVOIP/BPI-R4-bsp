#!/usr/bin/env bash

# Author: Weijie Gao <weijie.gao@mediatek.com>

# Parameters:
# ATF_SRC=<path>:		ATF source directory
# OUT=<path>:			Output directory
# CROSS_COMPILE=<prefix>:	Toolchain prefix
# CONFIG=<file>:		Configuration file

set -eo pipefail

ATF_SRC_set=no
OUT_set=no
CROSS_COMPILE_set=no
CONFIG_set=no

script_dir=$(dirname $(readlink -f "${0}"))

# $1:	Error message
error() {
	echo -e "\033[31mERROR: ${1}\033[0m"
	exit 1
}

# $1:	Mmessage
prompt_stage() {
	echo ""
	echo -e "\033[47;30m${1}\033[0m"
}

# $1:	Config name
# $2:	Config value
print_conf() {
	echo -e "\033[1m${1}: \033[4m${2}\033[0m"
}

# $1:	Toolchain prefix
# $2:	Expected machine architecture
check_toolchain_prefix() {
	"${1}gcc" -v >/dev/null 2>&1 || error "${1}gcc does not exist!"

	machine=$("${1}gcc" -dumpmachine 2>/dev/null)
	expr index ${machine} '-' >/dev/null 2>&1 || error "Invalid machine '${machine}' from gcc!"
	triplet_cpu=${machine%%-*}
	[ x"${triplet_cpu}" = x"${2}" ] || error "'${machine}' is not supported!"
}

# Process arguments
for arg in "$@"; do
	if expr index ${arg} '=' 2>&1 >/dev/null; then
		name=${arg%%=*}
		value=${arg#*=}

		eval ${name}=\"\$value\"
		eval ${name}_set=yes
	fi
done

# Parameter validation
for arg in ATF_SRC OUT CROSS_COMPILE CONFIG; do
	eval [ x"\$${arg}_set" != x"yes" ] && error "${arg} is not set!"
done

[ -d "${ATF_SRC}" ] || error "${ATF_SRC} is not a valid directory!"
[ x"${OUT}" = x"/" ] && error "Root directory must not be used as release directory!"
[ -f "${CONFIG}" ] || error "${CONFIG} is not a valid file!"

# Include config file
source ${CONFIG}

check_toolchain_prefix "${CROSS_COMPILE}" ${TOOLCHAIN_PREFIX}

# Use absolute path for OUT
[ "${OUT:0:1}" != "/" ] && OUT=$(pwd)/${OUT}

# Print parameters
echo -e "\033[1mConfiguration:\033[0m"
print_conf "ATF source directory" "${ATF_SRC}"
print_conf "Output release directory" "${OUT}"
print_conf "Toolchain prefix" "${CROSS_COMPILE}"
print_conf "Configuration file" "${CONFIG}"

###
prompt_stage "Deleting output directory"
[ -d "${OUT}" ] && rm -rf "${OUT}"
[ -f "${OUT}" ] && rm -f "${OUT}"

###
prompt_stage "Creating output directory structure"
BUILD_DIR=${OUT}/build
RELEASE_DIR=${OUT}/release
ATF_BUILD_DIR=${BUILD_DIR}/atf

mkdir -p ${ATF_BUILD_DIR}
mkdir -p ${RELEASE_DIR}

###
SOC_FW_NAME_UPCASE=$(echo ${SOC_FW_NAME} | tr 'a-z' 'A-Z')
prompt_stage "Building ATF ${SOC_FW_NAME_UPCASE}"

eval make -C ${ATF_SRC} -f Makefile -j$(nproc) \
	BUILD_BASE=${ATF_BUILD_DIR}/normal \
	CROSS_COMPILE=${CROSS_COMPILE} \
	LOG_LEVEL=${ATF_LOG_LEVEL} \
	PLAT=${PLATFORM} \
	BOOT_DEVICE=ram \
	${ATF_BUILD_OPTIONS} \
	${SOC_FW_NAME}

cp ${ATF_BUILD_DIR}/normal/${PLATFORM}/release/${SOC_FW_NAME}.bin ${RELEASE_DIR}/${SOC_FW_NAME}.bin

###
for variant in ${ATF_VARIANTS}; do
	eval ATF_NAME="\$ATF_NAME_${variant}"

	prompt_stage "Building ATF BL2 variant '${ATF_NAME}'"

	BL2_SUFFIX=-${ATF_NAME}
	eval BL2_VARIANT_OPTIONS="\$BL2_VARIANT_OPTIONS_${variant}"

	mkdir -p ${ATF_BUILD_DIR}/${ATF_NAME}

	eval make -C ${ATF_SRC} -f Makefile -j$(nproc) \
		BUILD_BASE=${ATF_BUILD_DIR}/${ATF_NAME} \
		CROSS_COMPILE=${CROSS_COMPILE} \
		LOG_LEVEL=${ATF_LOG_LEVEL} \
		PLAT=${PLATFORM} \
		${ATF_BUILD_OPTIONS} \
		${BL2_BUILD_OPTIONS} \
		${BL2_VARIANT_OPTIONS} \
		bl2

	cp ${ATF_BUILD_DIR}/${ATF_NAME}/${PLATFORM}/release/${BL2_OUT_NAME} ${RELEASE_DIR}/bl2${BL2_SUFFIX}.img

done
