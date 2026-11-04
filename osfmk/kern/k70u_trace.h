#ifndef K70U_TRACE_H
#define K70U_TRACE_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
#if defined(__arm64__)
void k70u_pmsg(const char *);
void k70u_trace_hex(const char *, uint64_t);
void k70u_trace(const char *, const char *);
void k70u_startup_event(const char *, uint64_t, uint64_t, uint64_t, uint64_t);
void k70u_irq_hex(const char *, uint64_t);
void k70u_irq_state(const char *);
void k70u_display_start(void);
extern volatile uint64_t k70u_irq_count;
#else
#define k70u_pmsg(s) ((void)0)
#define k70u_trace_hex(a,b) ((void)0)
#define k70u_trace(a,b) ((void)0)
#define k70u_startup_event(a,b,c,d,e) ((void)0)
#define k70u_irq_hex(a,b) ((void)0)
#define k70u_irq_state(a) ((void)0)
#define k70u_display_start() ((void)0)
#endif
#ifdef __cplusplus
}
#endif
#endif
