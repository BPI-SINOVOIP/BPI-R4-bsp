#!/usr/bin/env bash

# Author: Weijie Gao <weijie.gao@mediatek.com>

# Parameters:
# ATF_SRC=<path>:		ATF source directory
# OUT=<path>:			Output directory
# CROSS_COMPILE_A32=<prefix>:	Toolchain prefix for AArch32
# CROSS_COMPILE_A64=<prefix>:	Toolchain prefix for AArch64

set -eo pipefail

ATF_SRC_set=no
OUT_set=no
CROSS_COMPILE_A32_set=no
CROSS_COMPILE_A64_set=no

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
# $3:	Expected machine architecture display name
check_toolchain_prefix() {
	"${1}gcc" -v >/dev/null 2>&1 || error "${1}gcc does not exist!"

	machine=$("${1}gcc" -dumpmachine 2>/dev/null)
	expr index ${machine} '-' >/dev/null 2>&1 || error "Invalid machine '${machine}' from gcc!"
	triplet_cpu=${machine%%-*}
	[ x"${triplet_cpu}" = x"${2}" ] || error "'${machine}' is not capable for ${3}!"
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
for arg in ATF_SRC OUT CROSS_COMPILE_A32 CROSS_COMPILE_A64; do
	eval [ x"\$${arg}_set" != x"yes" ] && error "${arg} is not set!"
done

[ -d "${ATF_SRC}" ] || error "${ATF_SRC} is not a valid directory!"
[ x"${OUT}" = x"/" ] && error "Root directory must not be used as release directory!"

check_toolchain_prefix "${CROSS_COMPILE_A32}" arm AArch32
check_toolchain_prefix "${CROSS_COMPILE_A64}" aarch64 AArch64

# Use absolute path for OUT
[ "${OUT:0:1}" != "/" ] && OUT=$(pwd)/${OUT}

# Print parameters
echo -e "\033[1mConfiguration:\033[0m"
print_conf "ATF source directory" "${ATF_SRC}"
print_conf "Output release directory" "${OUT}"
print_conf "AArch32 toolchain prefix" "${CROSS_COMPILE_A32}"
print_conf "AArch64 toolchain prefix" "${CROSS_COMPILE_A64}"

###
prompt_stage "Deleting output directory"
[ -d "${OUT}" ] && rm -rf "${OUT}"
[ -f "${OUT}" ] && rm -f "${OUT}"

###
CONFIGS=$(find ${script_dir}/ -name '*.config' -printf "%f ")

################################################################################
PLATFORMS=

for f in ${CONFIGS}; do
	__plat=${f%%.*}
	PLATFORMS="${PLATFORMS} ${__plat}"
done

ARCH_mt7629=32
################################################################################

###
prompt_stage "Creating output directory structure"
BUILD_DIR=${OUT}/build
FILES_DIR=${OUT}/files

mkdir -p ${BUILD_DIR}
mkdir -p ${FILES_DIR}

###
for plat in ${PLATFORMS}; do
	prompt_stage "Building ATF binary release files for ${plat}"

	eval ARCH="\$ARCH_${plat}"
	[ x"$ARCH" = x ] && ARCH=64

	eval CROSS_COMPILE="\$CROSS_COMPILE_A${ARCH}"

	OUTDIR=${BUILD_DIR}/${plat}

	${script_dir}/build_atf_files.sh \
		ATF_SRC=${ATF_SRC} \
		OUT=${OUTDIR} \
		CONFIG=${script_dir}/${plat}.config \
		CROSS_COMPILE=${CROSS_COMPILE}

	mkdir -p ${FILES_DIR}/${plat}
	cp -a ${OUTDIR}/release/* ${FILES_DIR}/${plat}/

done
