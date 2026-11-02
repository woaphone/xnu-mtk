/*
 * Linux port: the IIG-generated DriverKit headers include <string.h> for the
 * userspace class section. In the kernel build that section is excluded, but
 * the include is unconditional; map it to the kernel's libkern declarations.
 */
#ifndef _XNU_EXTERNAL_STRING_H
#define _XNU_EXTERNAL_STRING_H
#include <libkern/libkern.h>
#endif
