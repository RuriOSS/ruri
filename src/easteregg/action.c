// SPDX-License-Identifier: MIT
/*
 *
 * This file is part of ruri, with ABSOLUTELY NO WARRANTY.
 *
 * MIT License
 *
 * Copyright (c) 2024 Moe-hacker
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
#include "include/nekofeng.h"
// NOLINTBEGIN
/*
 * This file defines the actions of the animation.
 * All the functions have the same arguments.
 */
#ifndef RURI_CORE_ONLY
void nekofeng_face(useconds_t inr, unsigned int keep)
{
	struct NEKOFENG_ACTION *action = NULL;
	action = nekofeng_add_action(action, -17, -9,
				     U"\033[0m              ██                        ██\n"
				     "\033[0m            ██  ██                    ██  ██\n"
				     "\033[0m            ██    ████              ██      ██\n"
				     "\033[0m          ██          ██          ████      ██\n"
				     "\033[0m          ██      ██████████████████          ██\n"
				     "\033[0m        ██      ██                  ██        ██\n"
				     "\033[0m        ██    ██                      ████    ██\n"
				     "\033[0m      ████████        ██      ██          ████  ██\n"
				     "\033[0m      ██    ██        ██    ██  ██    ██    ██  ██\n"
				     "\033[0m    ████      ██    ██  ████  ██    ██  ██    ██████\n"
				     "\033[0m    ██        ██  ██    ██      ████  ██  ██  ████████\n"
				     "\033[0m    ██      ██  ██                          ████\n"
				     "\033[0m    ██        ██                              ██\n"
				     "\033[0m  ████        ██                              ██\n"
				     "\033[0m  ██          ██                              ██\n"
				     "\033[0m  ██          ██                               ██\n"
				     "\033[0m  ██          ██                                ██\n"
				     "\033[0m  ████    ██  ██                                ██\n"
				     "\033[0m    ████  ██████                              ██\n"
				     "\033[0m      ██████  ████                        ████\n"
				     "\033[0m                ████                    ████\n"
				     "\033[0m                    ████████████████████\n");
	nekofeng_play_action(action, inr, keep);
	nekofeng_free_action(action);
}
void nekofeng_mouth(useconds_t inr, unsigned int keep)
{
	struct NEKOFENG_ACTION *action = NULL;
	action = nekofeng_add_action(action, 10, 8,
				     U"\n"
				     "\n"
				     "  ███\n");
	action = nekofeng_add_action(action, 10, 8,
				     U"\n"
				     "\n"
				     "  ████\n");
	action = nekofeng_add_action(action, 10, 8,
				     U"\n"
				     "\n"
				     " ██████\n");
	action = nekofeng_add_action(action, 10, 8,
				     U"\n"
				     "██    ██\n"
				     "  ████\n");
	nekofeng_play_action(action, inr, keep);
	nekofeng_free_action(action);
}
void nekofeng_ahoge(useconds_t inr, unsigned int keep)
{
	struct NEKOFENG_ACTION *action = NULL;
	action = nekofeng_add_action(action, 6, -8,
				     U"      ██\n"
				     "     ██\n"
				     "    ██\n");
	action = nekofeng_add_action(action, 6, -8,
				     U"        ██\n"
				     "      ██\n"
				     "    ██\n");
	action = nekofeng_add_action(action, 6, -8,
				     U"      ██\n"
				     "     ██\n"
				     "    ██\n");
	action = nekofeng_add_action(action, 6, -8,
				     U"  ██\n"
				     "   ██\n"
				     "    ██\n");
	action = nekofeng_add_action(action, 6, -8,
				     U"██\n"
				     "  ██\n"
				     "    ██\n");
	action = nekofeng_add_action(action, 6, -8,
				     U"  ██\n"
				     "   ██\n"
				     "    ██\n");
	nekofeng_play_action(action, inr, keep);
	nekofeng_free_action(action);
}
void nekofeng_blink_lefteye(useconds_t inr, unsigned int keep)
{
	struct NEKOFENG_ACTION *action = NULL;
	action = nekofeng_add_action(action, 1, 2,
				     U"  ██████ \n"
				     "██      ██\n"
				     "  ██████\n"
				     "  ██  ██\n"
				     "  ██████\n");
	action = nekofeng_add_action(action, 1, 2,
				     U"\n"
				     "  ██████ \n"
				     "██      ██\n"
				     "  ██  ██\n"
				     "  ██████\n");
	action = nekofeng_add_action(action, 1, 2,
				     U"\n\n"
				     "  ██████ \n"
				     "██      ██\n"
				     "  ██████\n");
	action = nekofeng_add_action(action, 1, 2,
				     U"\n\n\n"
				     "  ██████ \n"
				     "██████████\n");
	action = nekofeng_add_action(action, 1, 2,
				     U"\n\n"
				     "   ████\n"
				     "       ██\n"
				     "  █████\n");
	action = nekofeng_add_action(action, 1, 2,
				     U"\n"
				     "  ████\n"
				     "      ██\n"
				     "        ██\n"
				     "  ██████\n");
	nekofeng_play_action(action, inr, keep);
	nekofeng_free_action(action);
}
void nekofeng_blink_righteye(useconds_t inr, unsigned int keep)
{
	struct NEKOFENG_ACTION *action = NULL;
	action = nekofeng_add_action(action, 16, 2,
				     U"  ██████ \n"
				     "██      ██\n"
				     "  \033[31m██  ██\n"
				     "    ██  \n"
				     "  ██  ██\n");
	action = nekofeng_add_action(action, 16, 2,
				     U"\n"
				     "  ██████ \n"
				     "██\033[31m██  ██\033[0m██\n"
				     "    \033[31m██\n"
				     "  ██  ██\n");
	action = nekofeng_add_action(action, 16, 2,
				     U"\n\n"
				     "  ██████ \n"
				     "██  \033[31m██\033[0m  ██\n"
				     "  \033[31m██  ██\n");
	action = nekofeng_add_action(action, 16, 2,
				     U"\n\n\n"
				     "  ██████  \n"
				     "██\033[31m██  ██\033[0m██ \n");
	action = nekofeng_add_action(action, 16, 2,
				     U"\n\n"
				     "  ████\n"
				     "██\n"
				     "  █████\n");
	action = nekofeng_add_action(action, 16, 2,
				     U"\n"
				     "    ████\n"
				     "  ██\n"
				     "██\n"
				     "  ██████\n");
	nekofeng_play_action(action, inr, keep);
	nekofeng_free_action(action);
}
#endif
// NOLINTEND