/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */
 
#ifndef CYCLIC_H
#define CYCLIC_H

extern void DtraceWinOSDpcStack(thread_t *td);

typedef uintptr_t cyclic_id_t;
typedef uint16_t cyc_level_t;
typedef void (*cyc_func_t)(void *);
typedef uintptr_t dtrace_cpu_t;

#define	CYCLIC_NONE	((cyclic_id_t)0)
#define CYCLIC 0
#define OMNI_CYCLIC 1

typedef struct cyc_handler {
	cyc_func_t cyh_func;
	void *cyh_arg;
} cyc_handler_t;

typedef struct cyc_time {
	hrtime_t cyt_interval;
	hrtime_t cyt_when;
} cyc_time_t;

typedef struct cyc_omni_handler {
	void (*cyo_online)(void *, dtrace_cpu_t *, cyc_handler_t *, cyc_time_t *);
	void (*cyo_offline)(void *, dtrace_cpu_t *, void *);
	void *cyo_arg;
} cyc_omni_handler_t;

typedef struct cyclic {
	KDPC Dpc;
	KTIMER Timer;
	cyc_func_t cy_func;
	void *cy_arg;
	hrtime_t cy_interval;
	hrtime_t cy_expire;
	int perodic;
} cyclic_t;

typedef struct cyclic_omni {
	PRKDPC Odpc;
	int type;
	int cpus;
	cyc_omni_handler_t omni;
	cyclic_t *cyc;
} cyclic_omni_t;

extern cyclic_id_t cyclic_add(cyc_handler_t *, cyc_time_t *);
extern void cyclic_remove(cyclic_id_t);
extern cyclic_id_t cyclic_add_omni(cyc_omni_handler_t *);

int strcasecmp(char *s1, char *s2); //_strnicmp
int strncasecmp(char *s1, char *s2, register int n);

#endif