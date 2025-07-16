// SPDX-License-Identifier: MIT
/*
 *
 * This file is part of ruri, with ABSOLUTELY NO WARRANTY.
 *
 * MIT License
 *
 * Copyright (c) 2022-2024 Moe-hacker
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 *
 */
#include "include/ruri.h"
#include "include/elf-magic.h"
/*
 * This file provides functions to get ELF magic number and mask for cross_arch.
 * These info will be used for binfmt_misc.
 * Maybe it seems stupid, but it's okey.
 */
// Get ELF magic number and mask for cross_arch specified.
struct RURI_ELF_MAGIC *ruri_get_magic(const char *_Nonnull cross_arch)
{
	/*
	 * I know that this seems to be a little bit stupid,
	 * but we have no other ways to match the architecture to its ELF magic.
	 * TODO: Support more architecture aliases.
	 */
	struct RURI_ELF_MAGIC *ret = (struct RURI_ELF_MAGIC *)malloc(sizeof(struct RURI_ELF_MAGIC));
	// Avoid to simulate the same architecture as host.
	if (strcmp(cross_arch, RURI_HOST_ARCH) == 0) {
		ruri_error("Do not simulate the same architecture as host.");
	}
	if (strcmp(cross_arch, "aarch64") == 0 || strcmp(cross_arch, "arm64") == 0 || strcmp(cross_arch, "armv8") == 0) {
		if (strcmp(RURI_HOST_ARCH, "aarch64") == 0) {
			ruri_error("Do not simulate the same architecture as host.");
		}
		ret->magic = ruri_magicof(aarch64);
		ret->mask = ruri_maskof(aarch64);
	} else if (strcmp(cross_arch, "alpha") == 0) {
		ret->magic = ruri_magicof(alpha);
		ret->mask = ruri_maskof(alpha);
	} else if (strcmp(cross_arch, "arm") == 0 || strcmp(cross_arch, "armhf") == 0 || strcmp(cross_arch, "arm32") == 0 || strcmp(cross_arch, "armel") == 0 || strcmp(cross_arch, "armv7") == 0) {
		if (strcmp(RURI_HOST_ARCH, "arm") == 0) {
			ruri_error("Do not simulate the same architecture as host.");
		}
		ret->magic = ruri_magicof(arm);
		ret->mask = ruri_maskof(arm);
	} else if (strcmp(cross_arch, "armeb") == 0) {
		ret->magic = ruri_magicof(armeb);
		ret->mask = ruri_maskof(armeb);
	} else if (strcmp(cross_arch, "cris") == 0) {
		ret->magic = ruri_magicof(cris);
		ret->mask = ruri_maskof(cris);
	} else if (strcmp(cross_arch, "hexagon") == 0) {
		ret->magic = ruri_magicof(hexagon);
		ret->mask = ruri_maskof(hexagon);
	} else if (strcmp(cross_arch, "hppa") == 0) {
		ret->magic = ruri_magicof(hppa);
		ret->mask = ruri_maskof(hppa);
	} else if (strcmp(cross_arch, "i386") == 0 || strcmp(cross_arch, "x86") == 0) {
		if (strcmp(RURI_HOST_ARCH, "i386") == 0) {
			ruri_error("Do not simulate the same architecture as host.");
		}
		ret->magic = ruri_magicof(i386);
		ret->mask = ruri_maskof(i386);
	} else if (strcmp(cross_arch, "loongarch64") == 0 || strcmp(cross_arch, "loong64") == 0 || strcmp(cross_arch, "loongarch") == 0) {
		if (strcmp(RURI_HOST_ARCH, "loongarch64") == 0) {
			ruri_error("Do not simulate the same architecture as host.");
		}
		ret->magic = ruri_magicof(loongarch64);
		ret->mask = ruri_maskof(loongarch64);
	} else if (strcmp(cross_arch, "m68k") == 0) {
		ret->magic = ruri_magicof(m68k);
		ret->mask = ruri_maskof(m68k);
	} else if (strcmp(cross_arch, "microblaze") == 0) {
		ret->magic = ruri_magicof(microblaze);
		ret->mask = ruri_maskof(microblaze);
	} else if (strcmp(cross_arch, "mips") == 0) {
		ret->magic = ruri_magicof(mips);
		ret->mask = ruri_maskof(mips);
	} else if (strcmp(cross_arch, "mips64") == 0) {
		ret->magic = ruri_magicof(mips64);
		ret->mask = ruri_maskof(mips64);
	} else if (strcmp(cross_arch, "mips64el") == 0) {
		ret->magic = ruri_magicof(mips64el);
		ret->mask = ruri_maskof(mips64el);
	} else if (strcmp(cross_arch, "mipsel") == 0) {
		ret->magic = ruri_magicof(mipsel);
		ret->mask = ruri_maskof(mipsel);
	} else if (strcmp(cross_arch, "mipsn32") == 0) {
		ret->magic = ruri_magicof(mipsn32);
		ret->mask = ruri_maskof(mipsn32);
	} else if (strcmp(cross_arch, "mipsn32el") == 0) {
		ret->magic = ruri_magicof(mipsn32el);
		ret->mask = ruri_maskof(mipsn32el);
	} else if (strcmp(cross_arch, "ppc") == 0) {
		ret->magic = ruri_magicof(ppc);
		ret->mask = ruri_maskof(ppc);
	} else if (strcmp(cross_arch, "ppc64") == 0) {
		ret->magic = ruri_magicof(ppc64);
		ret->mask = ruri_maskof(ppc64);
	} else if (strcmp(cross_arch, "ppc64le") == 0) {
		ret->magic = ruri_magicof(ppc64le);
		ret->mask = ruri_maskof(ppc64le);
	} else if (strcmp(cross_arch, "riscv32") == 0) {
		ret->magic = ruri_magicof(riscv32);
		ret->mask = ruri_maskof(riscv32);
	} else if (strcmp(cross_arch, "riscv64") == 0) {
		ret->magic = ruri_magicof(riscv64);
		ret->mask = ruri_maskof(riscv64);
	} else if (strcmp(cross_arch, "s390x") == 0) {
		ret->magic = ruri_magicof(s390x);
		ret->mask = ruri_maskof(s390x);
	} else if (strcmp(cross_arch, "sh4") == 0) {
		ret->magic = ruri_magicof(sh4);
		ret->mask = ruri_maskof(sh4);
	} else if (strcmp(cross_arch, "sh4eb") == 0) {
		ret->magic = ruri_magicof(sh4eb);
		ret->mask = ruri_maskof(sh4eb);
	} else if (strcmp(cross_arch, "sparc") == 0) {
		ret->magic = ruri_magicof(sparc);
		ret->mask = ruri_maskof(sparc);
	} else if (strcmp(cross_arch, "sparc32plus") == 0) {
		ret->magic = ruri_magicof(sparc32plus);
		ret->mask = ruri_maskof(sparc32plus);
	} else if (strcmp(cross_arch, "sparc64") == 0) {
		ret->magic = ruri_magicof(sparc64);
		ret->mask = ruri_maskof(sparc64);
	} else if (strcmp(cross_arch, "x86_64") == 0 || strcmp(cross_arch, "amd64") == 0) {
		if (strcmp(RURI_HOST_ARCH, "x86_64") == 0) {
			ruri_error("Do not simulate the same architecture as host.");
		}
		ret->magic = ruri_magicof(x86_64);
		ret->mask = ruri_maskof(x86_64);
	} else if (strcmp(cross_arch, "xtensa") == 0) {
		ret->magic = ruri_magicof(xtensa);
		ret->mask = ruri_maskof(xtensa);
	} else if (strcmp(cross_arch, "xtensaeb") == 0) {
		ret->magic = ruri_magicof(xtensaeb);
		ret->mask = ruri_maskof(xtensaeb);
	} else {
		free(ret);
		return NULL;
	}
	ruri_log("Cross architecture: {cyan}%s\n", cross_arch);
	ruri_log("ELF magic: {cyan}%s\n", ret->magic);
	ruri_log("ELF mask: {cyan}%s\n", ret->mask);
	return ret;
}
