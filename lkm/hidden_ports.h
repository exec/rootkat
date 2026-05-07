/* SPDX-License-Identifier: MIT */
#ifndef ROOTKAT_HIDDEN_PORTS_H
#define ROOTKAT_HIDDEN_PORTS_H

#include <linux/types.h>

/*
 * Tiny fixed-size hidden-port registry. Same shape as hidden_pids;
 * separate file because the uses are independent.
 */
#define ROOTKAT_HIDDEN_PORTS_MAX 16

void rootkat_hide_port(u16 port);
void rootkat_unhide_port(u16 port);
bool rootkat_is_port_hidden(u16 port);

#endif
