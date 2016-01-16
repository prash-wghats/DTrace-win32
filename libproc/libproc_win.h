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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND 
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE 
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL 
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS 
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT 
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY 
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
 * SUCH DAMAGE. 
 */
struct proc_mod;

struct ps_prochandle {
	pid_t	pid;			/* Process ID. */
	int 	tid;			/* thread ID */
	HANDLE thandle;			/* Thread handle */
	int	flags;			/* Process flags. */
	int	status;			/* Process status (PS_*). */
	int 	wstat;			/* wait/error code */
	int	exitcode;			/* exit code */
	int 	model;
	HANDLE phandle;			/* process handle */
	BYTE saved;			/* instruction at the breakpoint address */
	uintptr_t addr;			/* breakpoint address */
	rd_event_msg_t msg;
	rd_agent_t *rdap;		/* librtld_db agent */
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	pthread_t pthr;			/* debugged process thread */
	struct proc_mod *modules;	/* list of modules loaded by process */
	struct proc_mod *exe_module;	
	HANDLE event;			/* signal when process stopped */
	int dll_load_order;
};