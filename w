#!/bin/sh
# command wrapper
set -eu

dir="$(realpath "$0")"
dir="${dir%/*}"
oper="${1-list}"
shift

set -x

cd "$dir/"
case "$oper" in
list)	echo build run format stat disable-coredump
	;;
build)	make
	;;
run)	./ruri "$@"
	;;
format)	find src/ -name '*.c' -o -name '*.h' | xargs clang-format --verbose -i
	;;
add)	git add .
	;;
stat)	git diff --cached --stat
	;;
disable-coredump) :
	sudo sysctl kernel.core_pattern='|/bin/false'
	;;
*)	echo "$0: $oper: unknown operation"
	exit 1
	;;
esac
