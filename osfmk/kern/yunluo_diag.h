/*
 * yunluo_diag.h - reusable crash diagnostics for the UniXNU bring-up on
 * Xiaomi Redmi Pad "yunluo" (MT6789).
 *
 * The panic screen renders the panic format string and its arguments on the
 * framebuffer, but not earlier kprintf history.  These helpers collect the
 * AArch64 caller chain from the frame-pointer chain (x29) so one boot's panic
 * shows who reached the failure.  The kernel is built with
 * -momit-leaf-frame-pointer: non-leaf frames are present, omitted leaf frames
 * simply do not appear in the chain.
 *
 * Usage (from the function whose callers are wanted):
 *
 *     YUNLUO_PANIC_BT("short message");
 *     YUNLUO_PANIC_BT1("short message", ptr);
 *
 *     void *bt[YUNLUO_BT_MAX];
 *     yunluo_bt_collect(bt, YUNLUO_BT_MAX);
 *     kprintf("YUNLUO: x bt=%p,%p\n", bt[0], bt[1]);
 *
 * Keep panic messages short: the framebuffer renderer wraps at the screen
 * edge, about 110-120 characters per line at the current font scale.
 *
 * No ABI impact: only inline code and macros, no classes or symbols.
 */
#ifndef _KERN_YUNLUO_DIAG_H_
#define _KERN_YUNLUO_DIAG_H_

#include <stdint.h>
#include <kern/debug.h>
#include <pexpert/pexpert.h>

#if defined(__has_feature)
#if __has_feature(ptrauth_calls)
#include <ptrauth.h>
#define YUNLUO_DIAG_PTRAUTH 1
#endif
#endif

#ifdef __cplusplus
#define YUNLUO_BT_NULL nullptr
#else
#define YUNLUO_BT_NULL ((void *)0)
#endif

#define YUNLUO_BT_MAX 8U
#define YUNLUO_BT_FMT "bt=%p,%p,%p,%p,%p,%p,%p,%p"

/* Raw frame-record indexing trips -Wunsafe-buffer-usage under
 * -Weverything; it is deliberate and bounded here. */
#if defined(__clang__)
#if __has_warning("-Wunsafe-buffer-usage")
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunsafe-buffer-usage"
#define YUNLUO_DIAG_WARN_PUSHED 1
#endif
#endif

/*
 * Walk the frame-pointer chain starting at the current frame.  Returns the
 * number of slots filled; unused slots are set to NULL.
 *
 * Bounded to `max` frames and to increasing, plausibly-aligned frame
 * addresses inside a small window above the current frame, so a corrupt
 * frame pointer cannot turn the diagnostic into an endless walk.  Only
 * addresses in the kernel VA range are reported.
 *
 * Must stay always_inline: __builtin_frame_address(0) then denotes the frame
 * of the function containing the expansion, so bt[0] is that function's
 * return address (its caller).
 */
static __inline__ __attribute__((always_inline, unused)) unsigned int
yunluo_bt_collect(void **bt, unsigned int max)
{
	uintptr_t fp = (uintptr_t)__builtin_frame_address(0);
	uintptr_t base = fp;
	unsigned int n = 0;

	while ((fp != 0) && (n < max)) {
		uintptr_t *frame;
		uintptr_t next;
		uintptr_t ret;

		/* Frame records on arm64 and x86_64 are pointer-aligned. */
		if ((fp & (sizeof(uintptr_t) - 1)) != 0) {
			break;
		}
		/* The stack grows down; caller frames live above this one. */
		if ((fp < base) || ((fp - base) > 0x40000)) {
			break;
		}

		frame = (uintptr_t *)fp;
		next = frame[0];
		ret = frame[1];

#ifdef YUNLUO_DIAG_PTRAUTH
		next = (uintptr_t)ptrauth_strip((void *)next,
		    ptrauth_key_frame_pointer);
		ret = (uintptr_t)ptrauth_strip((void *)ret,
		    ptrauth_key_return_address);
#endif

		/* Stop at the first non-kernel frame (or a missing frame). */
		if (ret < 0xffff000000000000ULL) {
			break;
		}
		bt[n++] = (void *)ret;

		if ((next <= fp) || ((next - fp) > 0x40000)) {
			break;
		}
		fp = next;
	}

	while (n < max) {
		bt[n++] = YUNLUO_BT_NULL;
	}

	return n;
}

#if defined(YUNLUO_DIAG_WARN_PUSHED)
#pragma clang diagnostic pop
#undef YUNLUO_DIAG_WARN_PUSHED
#endif

/*
 * Declare a filled chain array in the current scope.  The array name is
 * supplied by the caller so several diagnostics can coexist.
 */
#define YUNLUO_BT_DECLARE(name) \
	void *name[YUNLUO_BT_MAX] = { YUNLUO_BT_NULL }; \
	(void)yunluo_bt_collect(name, YUNLUO_BT_MAX)

/* Expand a collected chain into eight variadic arguments. */
#define YUNLUO_BT_ARGS(name) \
	(name)[0], (name)[1], (name)[2], (name)[3], \
	(name)[4], (name)[5], (name)[6], (name)[7]

/* panic("<message> bt=...") from the current function. */
#define YUNLUO_PANIC_BT(msg) do { \
	YUNLUO_BT_DECLARE(yunluo_bt_); \
	panic("%s " YUNLUO_BT_FMT, (msg), \
	    YUNLUO_BT_ARGS(yunluo_bt_)); \
} while (0)

/* panic("<message> <ptr> bt=...") from the current function. */
#define YUNLUO_PANIC_BT1(msg, arg) do { \
	YUNLUO_BT_DECLARE(yunluo_bt_); \
	panic("%s %p " YUNLUO_BT_FMT, (msg), (void *)(arg), \
	    YUNLUO_BT_ARGS(yunluo_bt_)); \
} while (0)

#endif /* _KERN_YUNLUO_DIAG_H_ */
