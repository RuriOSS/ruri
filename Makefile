# SPDX-License-Identifier: MIT
#
#
# This file is part of ruri, with ABSOLUTELY NO WARRANTY.
#
# MIT License
#
# Copyright (c) 2022-2024 Moe-hacker
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
#
# Premature optimization is the root of evil.
#
ifeq ($(wildcard config.mk),)
$(error config.mk is missing. Please run 'make configure' before building)
endif

CCCOLOR     = \033[1;38;2;254;228;208m
LDCOLOR     = \033[1;38;2;254;228;208m
STRIPCOLOR  = \033[1;38;2;254;228;208m
BINCOLOR    = \033[34;1m
ENDCOLOR    = \033[0m
CC_LOG = @printf '    $(CCCOLOR)CC$(ENDCOLOR) $(BINCOLOR)%b$(ENDCOLOR)\n'
LD_LOG = @printf '    $(LDCOLOR)LD$(ENDCOLOR) $(BINCOLOR)%b$(ENDCOLOR)\n'
STRIP_LOG = @printf ' $(STRIPCOLOR)STRIP$(ENDCOLOR) $(BINCOLOR)%b$(ENDCOLOR)\n'
CLEAN_LOG = @printf ' $(CCCOLOR)CLEAN$(ENDCOLOR) $(BINCOLOR)%b$(ENDCOLOR)\n'
# Strip.
STRIP = strip
# Formater.
FORMATER = clang-format -i
SRC = src/*.c src/easteregg/*.c
HEADER = src/include/*.h src/easteregg/include/*.h
# Checker.
CHECKER = clang-tidy
CHECKER_FLAGS = --checks=*,-clang-analyzer-security.insecureAPI.strcpy,-altera-unroll-loops,-cert-err33-c,-concurrency-mt-unsafe,-clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling,-readability-function-cognitive-complexity,-cppcoreguidelines-avoid-magic-numbers,-readability-magic-numbers,-bugprone-easily-swappable-parameters,-cert-err34-c,-misc-include-cleaner,-readability-identifier-length,-bugprone-signal-handler,-cert-msc54-cpp,-cert-sig30-c,-altera-id-dependent-backward-branch,-bugprone-suspicious-realloc-usage,-hicpp-signed-bitwise,-clang-analyzer-security.insecureAPI.UncheckedReturn,-bugprone-reserved-identifier,-cert-dcl37-c,-cert-dcl51-cpp,-google-readability-function-size,-hicpp-function-size,-readability-function-size,-bugprone-reserved-identifier,-cert-dcl37-c,-cert-dcl51-cpp
-include config.mk
# Target.
objects = easteregg/action.o easteregg/nekofeng.o easteregg/layer.o easteregg/typewriter.o caplist.o chroot.o cprintf.o info.o rurienv.o rurifetch.o seccomp.o signal.o umount.o unshare.o rootless.o mount.o k2v.o elf-magic.o config.o cgroup.o passwd.o ps.o ruri.o main.o
O = out
BIN_TARGET = ruri
.NOTPARALLEL:
.ONESHELL:
.PHONY :all dev static static-bionic build_dir check format clean upk2v upcprintf help test config dbg_config dev_config static_config configure
all :build_dir $(objects)
	@cd $(O)
	@$(CC) $(CFLAGS) -o $(BIN_TARGET) $(objects) $(LD_FLAGS)
	$(LD_LOG) $(BIN_TARGET)
	@$(STRIP) $(BIN_TARGET)
	$(STRIP_LOG) $(BIN_TARGET)
	@cp -f $(BIN_TARGET) ../
	@cd .. && rm -rf $(O)
dev :build_dir $(objects)
	@cd $(O)
	@$(CC) $(CFLAGS) -o $(BIN_TARGET) $(objects) $(LD_FLAGS)
	$(LD_LOG) $(BIN_TARGET)
	@cp -f $(BIN_TARGET) ../
	@cd .. && rm -rf $(O)
static :all
static-bionic :all
build_dir:
	@mkdir -p $(O)
	@mkdir -p $(O)/easteregg
$(objects) :%.o:src/%.c $(build_dir)
	@cd $(O)
	@$(CC) $(CFLAGS) -c ../$< -o $@
	$(CC_LOG) $@
check :
	@printf "\033[1;38;2;254;228;208mCheck list:\n"
	@sleep 1.5s
	@$(CHECKER) $(CHECKER_FLAGS) --list-checks $(SRC) -- $(DEV_CFLAGS)
	@printf ' \033[1;38;2;254;228;208mCHECK\033[0m \033[34;1m%b\033[0m\n' $(SRC)
	@$(CHECKER) $(CHECKER_FLAGS) $(SRC) -- $(COMMIT_ID)
	@printf ' \033[1;38;2;254;228;208mDONE.\n'
configure:
	@bash autogen.sh && bash configure
format :
	$(FORMATER) $(SRC) $(HEADER)
	shfmt -i 4 -w test/*.sh
	shfmt -i 4 -w test/root/*.sh
	shfmt -i 4 -w configure
	chmod 777 test/*.sh
	chmod 777 test/root/*
	clang-format -i test/*.c
	sed -i "s/U '/U'/g" src/easteregg/*.c
	sed -i "s/U \"/U\"/g" src/easteregg/*.c
	clang-format -i build.c
clean :
	$(CLEAN_LOG) $(BIN_TARGET)
	@rm -f $(BIN_TARGET)||true
	$(CLEAN_LOG) $(O)
	@rm -rf $(O)||true
	$(CLEAN_LOG) peda*
	@rm -f peda*
upk2v :
	cp ../libk2v/src/k2v.c src/k2v.c
	cp ../libk2v/src/include/k2v.h src/include/k2v.h
upcprintf :
	cp ../cprintf/cprintf.c src/cprintf.c
	cp ../cprintf/include/cprintf.h src/include/cprintf.h
help :
	@printf "\033[1;38;2;254;228;208mUsage:\n"
	@echo "  make all            compile"
	@echo "  make dev            compile, do not strip"
	@echo "  make clean          clean"
	@echo "Only for developers:"
	@echo "  make check          run clang-tidy"
	@echo "  make format         format code"
test :
	cd test && $(MAKE)
