/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2022 Philip Paeps
 *
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

/* TCP Authentication Option (RFC 5925) */
#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_inet.h"
#include "opt_inet6.h"
#include "opt_ipsec.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/lock.h>
#include <sys/rmlock.h>
#include <sys/socket.h>
#include <sys/sockopt.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/protosw.h>

#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/tcp.h>
#include <netinet/tcp_var.h>

#include <net/vnet.h>

#include <netipsec/ipsec.h>
#include <netipsec/ipsec_support.h>
#include <netipsec/xform.h>

#ifdef INET6
#include <netinet/ip6.h>
#include <netipsec/ipsec6.h>
#endif

#include <netipsec/key.h>
#include <netipsec/key_debug.h>

static int
tcp_ipsec_pcbctl(struct inpcb *inp, struct sockopt *sopt)
{
	struct tcpcb *tp;
	int error, optval;

	if (sopt->sopt_name != TCP_AUTHOPT) {
		return (ENOPROTOOPT);
	}

	if (sopt->sopt_dir == SOPT_GET) {
		INP_RLOCK(inp);
		if (inp->inp_flags & (INP_TIMEWAIT | INP_DROPPED)) {
			INP_RUNLOCK(inp);
			return (ECONNRESET);
		}
		tp = intotcpcb(inp);
		optval = (tp->t_flags2 & TF2_AO) ? 1 : 0;
		INP_RUNLOCK(inp);

		/* On success return with released INP_WLOCK */
		return (sooptcopyout(sopt, &optval, sizeof(optval)));
	}

	error = sooptcopyin(sopt, &optval, sizeof(optval), sizeof(optval));
	if (error != 0)
		return (error);

	/* INP_WLOCK_RECHECK */
	INP_WLOCK(inp);
	if (inp->inp_flags & (INP_TIMEWAIT | INP_DROPPED)) {
		INP_WUNLOCK(inp);
		return (ECONNRESET);
	}
	tp = intotcpcb(inp);
	if (optval > 0)
		tp->t_flags2 |= TF2_AO;
	else
		tp->t_flags2 &= ~TF2_AO;

	INP_WUNLOCK(inp);
	return (error);
}

static int
tcp_ipsec_input(struct mbuf *m, struct tcphdr *th, u_char *buf)
{

	return (0);
}

static int
tcp_ipsec_output(struct mbuf *m, struct tcphdr *th, u_char *buf)
{

	return (0);
}

static int
tcpao_init(struct secasvar *sav, struct xformsw *xsp)
{

	return (-1);
}

static void
tcpao_cleanup(struct secasvar *sav)
{
}

static struct xformsw tcpao_xformsw = {
	.xf_type =	XF_TCPAO,
	.xf_name =	"TCP-AO",
	.xf_init =	tcpao_init,
	.xf_cleanup =	tcpao_cleanup,
};

static const struct tcpao_methods tcpao_methods = {
	.input = tcp_ipsec_input,
	.output = tcp_ipsec_output,
	.pcbctl = tcp_ipsec_pcbctl,
};

#ifndef KLD_MODULE
static const struct tcpao_support tcpao_ipsec = {
	.enabled = IPSEC_MODULE_ENABLED,
	.methods = &tcpao_methods
};
const struct tcpao_support * const tcpao_ipsec_support = &tcpao_ipsec;
#endif /* !KLD_MODULE */

static int
tcpao_modevent(module_t mod, int type, void *data)
{

	switch (type) {
	case MOD_LOAD:
		xform_attach(&tcpao_xformsw);
#ifdef KLD_MODULE
		tcpao_support_enable(&tcpao_methods);
#endif
		break;
	case MOD_UNLOAD:
#ifdef KLD_MODULE
		tcpao_support_disable();
#endif
		xform_detach(&tcpao_xformsw);
		break;
	default:
		return (EOPNOTSUPP);
	}
	return (0);
}

static moduledata_t tcpao_mod = {
	"tcpao",
	tcpao_modevent,
	0
};

DECLARE_MODULE(tcpao, tcpao_mod, SI_SUB_PROTO_DOMAIN, SI_ORDER_ANY);
MODULE_VERSION(tcpao, 1);
#ifdef KLD_MODULE
MODULE_DEPEND(tcpao, ipsec_support, 1, 1, 1);
#endif
