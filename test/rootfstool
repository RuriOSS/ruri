#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# This file is part of rootfstool
#
# Copyright (c) 2023 Moe-hacker
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
#
ROOTFSTOOL_VERSION="1.5-hotfix"
RGB_MAIN_COLOR="254;228;208"
MAIN_COLOR="\033[1;38;2;${RGB_MAIN_COLOR}m"
LXC_MIRROR_MAIN="http://images.linuxcontainers.org"
LXC_MIRROR_BFSU="https://mirrors.bfsu.edu.cn/lxc-images"
LXC_MIRROR_TUNA="https://mirrors.tuna.tsinghua.edu.cn/lxc-images"
LXC_MIRROR_NJU="https://mirror.nju.edu.cn/lxc-images"
LXC_MIRROR_ISCAS="https://mirror.iscas.ac.cn/lxc-images"
function select_mirror() {
  case ${MIRROR} in
  "bfsu")
    export LXC_MIRROR=${LXC_MIRROR_BFSU}
    ;;
  "tuna")
    export LXC_MIRROR=${LXC_MIRROR_TUNA}
    ;;
  "nju")
    export LXC_MIRROR=${LXC_MIRROR_NJU}
    ;;
  "iscas")
    export LXC_MIRROR=${LXC_MIRROR_ISCAS}
    ;;
  "main" | "")
    export LXC_MIRROR=${LXC_MIRROR_MAIN}
    ;;
  *)
    echo -e "\033[31mUnknow mirror!\033[0m"
    exit 1
    ;;
  esac
}
function list_mirrors() {
  echo main
  echo bfsu
  echo tuna
  echo nju
  echo iscas
}
function show_helps() {
  echo -e "${MAIN_COLOR}Usage:"
  echo -e "  rootfstool <command> [<args>]"
  echo
  echo -e "Commands:"
  echo -e "  version,v    #Show version info"
  echo -e "  help,h       #Show helps"
  echo -e "  list,l       #List all distros"
  echo -e "  mirrorlist,m #List mirrors"
  echo -e "  search,s     #Search available versions of distro"
  echo -e "  url,u        #Get rootfs download link"
  echo -e "  download,d   #Download rootfs as rootfs.tar.xz"
  echo -e "  exec,e       #Exec a built-in function *Only for developer"
  echo
  echo -e "Args:"
  echo -e "--distro,-d    #Specify os distro"
  echo -e "--arch,-a      #Specify cpu architecture"
  echo -e "--version,-v   #Specify distro version"
  echo -e "--mirror,-m    #Specify the mirror, available mirrors are: main bfsu tuna nju"
  echo
  echo -e "Some examples:"
  echo -e "#List available arm64 OS distros"
  echo -e "\033[32mrootfstool \033[33mlist \033[34m-a ${MAIN_COLOR}arm64 \033[34m-m ${MAIN_COLOR}bfsu"
  echo -e "${MAIN_COLOR}#Search available versions of Ubuntu arm64"
  echo -e "\033[32mrootfstool \033[33msearch \033[34m-a ${MAIN_COLOR}arm64 \033[34m-d ${MAIN_COLOR}ubuntu \033[34m-m ${MAIN_COLOR}bfsu"
  echo -e "${MAIN_COLOR}#Get rootfs download link of Ubuntu bionic arm64"
  echo -e "\033[32mrootfstool \033[33murl \033[34m-a ${MAIN_COLOR}arm64 \033[34m-d ${MAIN_COLOR}ubuntu \033[34m-v ${MAIN_COLOR}bionic \033[34m-m ${MAIN_COLOR}bfsu"
  printf "\033[0m"
}
function show_version_info() {
  echo -e "${MAIN_COLOR}rootfstool version ${ROOTFSTOOL_VERSION} By Moe-hacker"
  echo -e "Special thanks to:"
  echo -e "\033[4mhttps://github.com/2moe/tmoe/\033[0m"
}
function get_cpu_arch() {
  # It will create a global variable CPU_ARCH
  # From tmoe
  if [[ $(command -v dpkg) && $(command -v apt-get) ]]; then
    DPKG_ARCH=$(dpkg --print-architecture)
    case ${DPKG_ARCH} in
    armel) ARCH_TYPE="armel" ;;
    armv7* | armv8l | armhf | arm) ARCH_TYPE="armhf" ;;
    aarch64 | arm64* | armv8* | arm*) ARCH_TYPE="arm64" ;;
    i*86 | x86) ARCH_TYPE="i386" ;;
    x86_64 | amd64) ARCH_TYPE="amd64" ;;
    *) ARCH_TYPE=${DPKG_ARCH} ;;
    esac
  else
    UNAME_ARCH=$(uname -m)
    case ${UNAME_ARCH} in
    armv7* | armv8l) ARCH_TYPE="armhf" ;;
    armv[1-6]*) ARCH_TYPE="armel" ;;
    aarch64 | armv8* | arm64 | arm*) ARCH_TYPE="arm64" ;;
    x86_64 | amd64) ARCH_TYPE="amd64" ;;
    i*86 | x86) ARCH_TYPE="i386" ;;
    s390*) ARCH_TYPE="s390x" ;;
    ppc*) ARCH_TYPE="ppc64el" ;;
    mips64) ARCH_TYPE="mips64el" ;;
    mips*) ARCH_TYPE="mipsel" ;;
    risc*) ARCH_TYPE="riscv64" ;;
    *) ARCH_TYPE=${UNAME_ARCH} ;;
    esac
  fi
  export CPU_ARCH=${ARCH_TYPE}
}
function list_distros() {
  # It will print the distro name if any version of distro is available for current ${CPU_ARCH}
  # $MIRROR and $CPU_ARCH are defined at main()
  if [[ ${CPU_ARCH} == "" ]]; then
    get_cpu_arch
  fi
  export MIRROR=${MIRROR}
  select_mirror
  for i in $(curl -sL ${LXC_MIRROR}/meta/1.0/index-system | grep ${CPU_ARCH} | grep -v cloud | cut -d ";" -f 1 | uniq); do
    echo -e "[${CPU_ARCH}] $i"
  done
}
function list_distro_version() {
  # If the version of the distro is available, print it
  # $MIRROR, $DISTRO and $CPU_ARCH are defined at main()
  if [[ ${DISTRO} == "" ]]; then
    echo -e "\033[31mOS distro not set.\033[0m"
    exit 1
  fi
  if [[ ${CPU_ARCH} == "" ]]; then
    get_cpu_arch
  fi
  export MIRROR=${MIRROR}
  select_mirror
  if [[ $(curl -sL "${LXC_MIRROR}/meta/1.0/index-system" | grep ${DISTRO} | grep ${CPU_ARCH}) == "" ]]; then
    echo -e "\033[31mCould not found image for current cpu architecture.\033[0m"
    exit 1
  fi
  for i in $(curl -sL "${LXC_MIRROR}/meta/1.0/index-system" | grep ${DISTRO} | grep ${CPU_ARCH} | grep -v cloud | cut -d ";" -f 1,2); do
    echo -e "[${CPU_ARCH}] $(echo $i | cut -d ";" -f 1) : $(echo $i | cut -d ";" -f 2)"
  done
}
function get_rootfs_url() {
  # Get rootfs download link of Specified $DISTRO and $VERSION
  # $MIRROR, $DISTRO, $VERSION and $CPU_ARCH are defined at main()
  if [[ ${CPU_ARCH} == "" ]]; then
    get_cpu_arch
  fi
  export MIRROR=${MIRROR}
  select_mirror
  PATH=$(curl -sL "${LXC_MIRROR}/meta/1.0/index-system" | grep ${DISTRO} | grep ${VERSION} | grep ${CPU_ARCH} | grep -v cloud | tail -n 1 | cut -d ";" -f 6)
  echo ${LXC_MIRROR}${PATH}rootfs.tar.xz
}
function download_rootfs() {
  # $MIRROR, $DISTRO, $VERSION and $CPU_ARCH are defined at main()
  rm -f rootfs.tar.xz
  wget $(get_rootfs_url)
}
function exec_function() {
  # *Only for developer.
  "$@"
}
function main() {
  case $1 in
  "exec" | "e")
    shift
    exec_function "$@"
    exit 0
    ;;
  "version" | "v")
    show_version_info
    exit 0
    ;;
  "help" | "h")
    show_helps
    exit 0
    ;;
  "list" | "l")
    TO_EXEC="list_distros"
    ;;
  "mirrorlist" | "m")
    list_mirrors
    exit 0
    ;;
  "search" | "s")
    TO_EXEC="list_distro_version"
    ;;
  "url" | "u")
    TO_EXEC="get_rootfs_url"
    ;;
  "download" | "d")
    TO_EXEC="download_rootfs"
    ;;
  *)
    show_helps
    exit 1
    ;;
  esac
  shift
  while [[ $1 ]]; do
    case $1 in
    "--distro" | "-d")
      shift
      export DISTRO=$1
      ;;
    "--arch" | "-a")
      shift
      export CPU_ARCH=$1
      ;;
    "--version" | "-v")
      shift
      export VERSION=$1
      ;;
    "--mirror" | "-m")
      shift
      export MIRROR=$1
      ;;
    *)
      show_helps
      exit 1
      ;;
    esac
    shift
  done
  ${TO_EXEC}
}
main "$@"
#  ██╗ ██╗  ███████╗   ████╗   ███████╗
# ████████╗ ██╔════╝ ██╔═══██╗ ██╔════╝
# ╚██╔═██╔╝ █████╗   ██║   ██║ █████╗
# ████████╗ ██╔══╝   ██║   ██║ ██╔══╝
# ╚██╔═██╔╝ ███████╗ ╚██████╔╝ ██║
#  ╚═╝ ╚═╝  ╚══════╝  ╚═════╝  ╚═╝
