/* SPDX-License-Identifier: MIT */
#ifndef ROOTKAT_RESOLVER_H
#define ROOTKAT_RESOLVER_H

/*
 * Try each candidate name in order. Returns the address of the first
 * one that resolves, or 0. On success, writes the matched name into
 * *matched (may be NULL).
 */
unsigned long rootkat_resolve(const char * const *candidates,
                              const char **matched);

#endif
