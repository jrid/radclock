/*
 * Copyright (C) 2012, Matthew Davis <matt@synclab.org>
 * Copyright (C) 2012, Julien Ridoux <julien@synclab.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef PROTO_1588_H
#define PROTO_1588_H

#define PTP_MULTICAST_PRIMARY	"224.0.1.129"
#define PTP_MULTICAST_PDELAY	"224.0.0.107"

/* IEEE 1588 message types */
#define	PTP_SYNC				0x0
#define	PTP_DELAYREQ			0x1
#define	PTP_PDELAYREQ			0x2
#define	PTP_PDELAYRESP			0x3
#define	PTP_FOLLOWUP			0x8
#define	PTP_DELAYRESP			0x9
#define	PTP_PDELAYRESPFOLLOWUP	0xA
#define	PTP_ANNOUNCE			0xB
#define	PTP_SIGNALING			0xC
#define	PTP_MANAGEMENT			0xD

/*
 * What a shitty definition of seconds on 48 bytes !!  Forget this and make secs
 * hold in a 64bit type.  This pushes the problem down into the network layer
 * and trust it to do the right thing.
 */
struct ptp_stamp {
	uint64_t	sec;
	uint32_t	nsec;
};

// FIXME how to get around the volatile stuff?
struct ptp_port_id {
	uint64_t	clock_id;
	uint16_t	port_nb;
};

/*
 * PTP common header
 */
struct ptp_header {
    /* Message type and transportation specific flags */
#define PTP_MSG_TYPE_MASK        0x0F
#define PTP_TRANSP_SPECIFIC_MASK 0xF0
#define PTP_MSG_TYPE(_v)         ((_v) & PTP_MSG_TYPE_MASK)
#define PTP_TRANSP_SPECIFIC(_v)  (((_v) & PTP_TRANSP_SPECIFIC_MASK) >> 4)
    uint8_t type_transp_flags;

    /* PTP version and reserved flags */
#define PTP_VERSION_MASK  0x0F
#define PTP_RESERVED_MASK 0xF0
#define PTP_VERSION(_v)   ((_v) & PTP_VERSION_MASK)
#define PTP_RESERVED(_v)  (((_v) & PTP_RESERVED_MASK) >> 4)
    uint8_t ver_reserved_flags;

    uint16_t length;
    uint8_t  domain_num;
    uint8_t  reserved1;
    uint16_t flag;
    uint64_t correction;
    uint32_t reserved2;
    uint8_t  src_port[10];
    uint16_t seq;
    uint8_t  control;
    uint8_t  msg_interval;
};

#define	PTP_HEADER_LEN	34

/* IEEE 1588 header flags */
#define PTPFLAG_ALTMASTER		0x0001
#define PTPFLAG_TWOSTEP			0x0002
#define PTPFLAG_UNICAST			0x0004
#define PTPFLAG_UNDEF1			0x0008
#define PTPFLAG_UNDEF2			0x0010
#define PTPFLAG_PROFILE1		0x0020
#define PTPFLAG_PROFILE2		0x0040
#define PTPFLAG_SECURITY		0x0080
#define PTPFLAG_LEAP61			0x0100
#define PTPFLAG_LEAP59			0x0200
#define PTPFLAG_UTCVALID		0x0400
#define PTPFLAG_PTPSCALE		0x0800
#define PTPFLAG_TIMETRAC		0x1000
#define PTPFLAG_FREQTRAC		0x2000

/*
 * IEEE 1588 announce message
 */
struct ptp_announce {
	uint8_t		origin_stamp[10];
	uint16_t	utc_offset;
	uint8_t		reserved;
	uint8_t		gm_priority1;
	uint32_t	gm_quality;
	uint8_t		gm_priority2;
	uint64_t	gm_id;
	uint16_t	steps_removed;
	uint8_t		time_source;
};

/*
 * IEEE 1588 delay request message
 */
struct ptp_delayreq {
    struct ptp_stamp stamp;
};

/*
 * IEEE 1588 delay response message
 */
struct ptp_delayresp {
    struct ptp_stamp stamp;
	uint8_t req_clockid[10];
};

/*
 * IEEE 1588 sync message
 */
struct ptp_sync {
    struct ptp_stamp stamp;
};

/*
 * IEEE 1588 follow-up message
 */
struct ptp_followup {
    struct ptp_stamp stamp;
};

#endif
