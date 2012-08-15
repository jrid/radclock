/*
 * Copyright (C) 2006-2012, Julien Ridoux <julien@synclab.org>
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

#include "../config.h"
#ifndef HAVE_POSIX_TIMER
#include <sys/time.h>
#endif

#include <sys/types.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

#include "radclock.h"
#include "radclock-private.h"
#include "radclock_daemon.h"
#include "sync_history.h"
#include "sync_algo.h"
#include "config_mgr.h"
#include "create_stamp.h"
#include "verbose.h"
#include "rawdata.h"
#include "jdebug.h"


/* Needed for the spy capture ... cannot pass the handle to the signal catcher */
extern struct radclock_handle *clock_handle;

#ifdef HAVE_POSIX_TIMER
timer_t spy_timerid;
#endif


/*
 * Insert a newly created raw_data_bundle structure (packet or PPS signal...)
 * into the clock_handle raw data linked list.
 * We always insert at the HEAD. Beware, this is made lock free, we rely on the
 * buffer consumer not to do stupid stuff !!
 * IMPORTANT: we do assume libpcap gives us packets in chronological order
 */
inline void
insert_rdb_in_list(struct raw_data_queue *rq, struct raw_data_bundle *rdb)
{
	JDEBUG

	// XXX Should get rid of the lock, the chain list is supposed to be lock
	// free ... well, theoretically. It seems that free_and_cherry_pick is
	// actuall messing with this new rdb if hammering with NTP control packets
	pthread_mutex_lock(&rq->rdb_mutex);

	JDEBUG_STR("INSERT: rdb at %p, ->next at %p, end at %p, start at %p",
		rdb, rdb->next, rq->rdb_end, rq->rdb_start);

	if (rq->rdb_start != NULL)
		rq->rdb_start->next = rdb;

	rq->rdb_start = rdb;

	if (rq->rdb_end == NULL)
		rq->rdb_end = rdb;

	pthread_mutex_unlock(&rq->rdb_mutex);
}



/*
 * Really, I have tried to make this as fast as possible
 * but if you have a better implementation, go for it.
 */
void
fill_rawdata_ntp(u_char *c_handle, const struct pcap_pkthdr *pcap_hdr,
		const u_char *packet_data)
{
	struct radclock_handle *handle;
	struct raw_data_bundle *rdb;
	int err;

	JDEBUG

	handle = (struct radclock_handle *) c_handle;

	/* Initialise raw data bundle */
	rdb = (struct raw_data_bundle *) malloc(sizeof(struct raw_data_bundle));
	JDEBUG_MEMORY(JDBG_MALLOC, rdb);
	assert(rdb);

	RD_PKT(rdb)->buf = (void *) malloc( pcap_hdr->caplen * sizeof(char));
	JDEBUG_MEMORY(JDBG_MALLOC, RD_PKT(rdb)->buf);
	assert(RD_PKT(rdb)->buf);

	/* Copy data of interest into the raw data bundle */
	RD_PKT(rdb)->vcount = 0;

	// TODO: should process the error code correctly
	err = extract_vcount_stamp(handle->clock, handle->clock->pcap_handle,
			pcap_hdr, packet_data, &(RD_PKT(rdb)->vcount));

	memcpy(&(RD_PKT(rdb)->pcap_hdr), pcap_hdr, sizeof(struct pcap_pkthdr));
	memcpy(RD_PKT(rdb)->buf, packet_data, pcap_hdr->caplen * sizeof(char));

	rdb->next = NULL;
	rdb->read = 0;		/* Of course not read yet */
	rdb->type = RD_TYPE_NTP;

	/* Insert the new bundle in the linked list */
	insert_rdb_in_list(handle->pcap_queue, rdb);
}


/*
 * Get timestamps from the sysclock when the POSIX timer quicks in.
 */
void
fill_rawdata_spy(int sig)
{
	struct raw_data_bundle *rdb;

	JDEBUG

	/* Initialise raw data bundle */
	rdb = (struct raw_data_bundle *) malloc (sizeof(struct raw_data_bundle));
	JDEBUG_MEMORY(JDBG_MALLOC, rdb);

	/* What time is it mister stratum-1? */
	radclock_get_vcounter(clock_handle->clock, &(RD_SPY(rdb)->Ta));
	gettimeofday( &(RD_SPY(rdb)->Tb), NULL);
	gettimeofday( &(RD_SPY(rdb)->Te), NULL);
	radclock_get_vcounter(clock_handle->clock, &(RD_SPY(rdb)->Tf));

	rdb->next = NULL;
	rdb->read = 0;
	rdb->type = RD_TYPE_SPY;

	/* Insert the new bundle in the linked list */
// TODO SHOULD HAVE IT'S OWN RAW_DATA_QUEUE
	insert_rdb_in_list(clock_handle->pcap_queue, rdb);
}


/*
 * Fake loop for capturing spy data.
 * Init a POSIX timer to capture data periodically and check if need
 * to return
 */
int
spy_loop(struct radclock_handle *handle)
{
#ifdef HAVE_POSIX_TIMER
	struct itimerspec itimer_ts;
#else
	struct itimerval itimer_tv;
#endif

	/* Signal catching */
	struct sigaction sig_struct;
	sigset_t alarm_mask;

	JDEBUG

	/* Initialise the signal data */
	sigemptyset(&alarm_mask);
	sigaddset(&alarm_mask, SIGALRM);
	sig_struct.sa_handler = fill_rawdata_spy; /* Not so dummy handler */
	sig_struct.sa_mask = alarm_mask;
	sig_struct.sa_flags = 0;
	sigaction(SIGALRM,  &sig_struct, NULL);

#ifdef HAVE_POSIX_TIMER
	if (timer_create (CLOCK_REALTIME, NULL, &spy_timerid) < 0) {
		verbose(LOG_ERR, "spy_loop: creation of POSIX timer failed: %s", strerror(errno));
		return (-1);
	}

	itimer_ts.it_value.tv_sec = 0;
	itimer_ts.it_value.tv_nsec = 5e8;
	itimer_ts.it_interval.tv_sec = (int) handle->conf->poll_period;
	itimer_ts.it_interval.tv_nsec = 0;

	if (timer_settime(spy_timerid, 0 /*!TIMER_ABSTIME*/, &itimer_ts, NULL) < 0) {
		verbose(LOG_ERR, "spy_loop: POSIX timer cannot be set: %s", strerror(errno));
		return (-1);
	}
#else
	itimer_tv.it_value.tv_sec = 0;
	itimer_tv.it_value.tv_usec = 5e5;
	itimer_tv.it_interval.tv_sec = (int) handle->conf->poll_period;
	itimer_tv.it_interval.tv_usec = 0;

	if (setitimer (ITIMER_REAL, &itimer_tv, NULL) < 0) {
		verbose(LOG_ERR, "spy_loop: creation of timer failed: %s", strerror(errno));
		return (-1);
	}
#endif

	while ((handle->unix_signal != SIGHUP) && (handle->unix_signal != SIGTERM)) {
		/* Check every second if need to quit */
		usleep(1000000);
	}
	
	verbose(LOG_NOTICE, "Out of spy loop");
	return (0);
}


void
fill_rawdata_1588(u_char *c_handle, const struct pcap_pkthdr *pcap_hdr,
		const u_char *packet_data)
{
	struct radclock_handle *handle;
	struct raw_data_bundle *rdb;
	int err;

	JDEBUG

	handle = (struct radclock_handle *) c_handle;

	/* Initialise raw data bundle */
	rdb = (struct raw_data_bundle *) malloc(sizeof(struct raw_data_bundle));
	JDEBUG_MEMORY(JDBG_MALLOC, rdb);
	assert(rdb);

	RD_PKT(rdb)->buf = (void *) malloc(pcap_hdr->caplen * sizeof(char));
	JDEBUG_MEMORY(JDBG_MALLOC, RD_PKT(rdb)->buf);
	assert(RD_PKT(rdb)->buf);

	/* Copy data of interest into the raw data bundle */
	RD_PKT(rdb)->vcount = 0;

	// TODO: should process the error code correctly
	err = extract_vcount_stamp(handle->clock, handle->clock->pcap_handle,
			pcap_hdr, packet_data, &(RD_PKT(rdb)->vcount));

	memcpy(&(RD_PKT(rdb)->pcap_hdr), pcap_hdr, sizeof(struct pcap_pkthdr));
	memcpy(RD_PKT(rdb)->buf, packet_data, pcap_hdr->caplen * sizeof(char));

	rdb->next = NULL;
	rdb->read = 0;
	rdb->type = RD_TYPE_1588;

	/* Insert the new bundle in the linked list */
	insert_rdb_in_list(handle->pcap_queue, rdb);
}


/*
 * Compute IP header checksum.
 */
uint16_t
do_ip_checksum(uint16_t *buf, uint16_t len)
{
	uint32_t checksum;
	int i;

	/* Sum all 16bit words. Assume even len. */
	checksum = 0;
	for (i=0; i<len/2; i++)
		checksum += (uint32_t) buf[i];

	/* Add carries */
	while (checksum >> 16)
	  checksum = (checksum & 0xFFFF) + (checksum >> 16);

	/* Return 1's complement checksum */
	return ((uint16_t) ~checksum);
}


/*
 * Compute UDP header checksum.
 */
uint16_t
do_udp_checksum(uint16_t *src_addr, uint16_t *dst_addr, uint16_t *buf,
		uint16_t len)
{
	uint32_t checksum;
	int i;

	/* Sum all 16bit words. Assume buf has extra byte at 0 if len not even. */
	checksum = 0;
	for (i=0; i<len/2; i++)
		checksum += (uint32_t) buf[i];

	/* Add pseudo header information */
	checksum += src_addr[0] + src_addr[1];
	checksum += dst_addr[0] + dst_addr[1];
	checksum += 17;			/* Proto UDP */
	checksum += len;

	/* Add carries */
	while (checksum >> 16)
	  checksum = (checksum & 0xFFFF) + (checksum >> 16);

	/* Return 1's complement checksum */
	return ((uint16_t) ~checksum);
}



/*
 * Push packets read from socket error queue into raw data queue. Useful to
 * retrieve hardware timestamps on the sending side.
 */
#if !defined(__linux__)
void
fill_rawdata_1588eq(struct radclock_handle *handle, vcounter_t vcount,
		struct timespec ts, unsigned char *ptp_msg, size_t pktlen)
{
}
#else
void
fill_rawdata_1588eq(struct radclock_handle *handle, vcounter_t vcount,
		struct timespec ts, unsigned char *ptp_msg, size_t pktlen)
{
	struct raw_data_bundle *rdb;
	linux_sll_header_t *sllh;
	struct iphdr *iph;
	struct udphdr *udph;
	unsigned char *pload;
	int datalen;
	int err;
	uint16_t checksum;

	JDEBUG

	/* Initialise raw data bundle */
	rdb = (struct raw_data_bundle *) malloc(sizeof(struct raw_data_bundle));
	JDEBUG_MEMORY(JDBG_MALLOC, rdb);
	assert(rdb);

	datalen = sizeof(linux_sll_header_t) + sizeof(struct iphdr) +
			sizeof(struct udphdr) + pktlen;
	RD_PKT(rdb)->buf = (void *) malloc(datalen * sizeof(char));
	JDEBUG_MEMORY(JDBG_MALLOC, RD_PKT(rdb)->buf);
	assert(RD_PKT(rdb)->buf);

	/* Copy data of interest into the raw data bundle */
	RD_PKT(rdb)->vcount = vcount;

	/* Build completely fake PCAP header */
//	RD_PKT(rdb)->pcap_hdr.ts.tv_sec = ts.tv_sec;
//	RD_PKT(rdb)->pcap_hdr.ts.tv_usec = (long)(ts.tv_nsec / 1000);
	RD_PKT(rdb)->pcap_hdr.ts.tv_sec = 123456789;
	RD_PKT(rdb)->pcap_hdr.ts.tv_usec = 1000;
	RD_PKT(rdb)->pcap_hdr.len = datalen;
	RD_PKT(rdb)->pcap_hdr.caplen = datalen;

	/* Build entire packet data, SLL, IPv4, UDP */
	sllh  = (linux_sll_header_t *) RD_PKT(rdb)->buf;
	iph   = (struct iphdr *)((uint8_t *)sllh + sizeof(linux_sll_header_t));
	udph  = (struct udphdr *)((uint8_t *)iph + sizeof(struct iphdr));
	pload = (unsigned char *)((uint8_t *)udph + sizeof(struct udphdr));


verbose(LOG_ERR, "pload-udph = %d, udph-iph= %d, iph-sllh= %d",
		pload-(unsigned char *)udph,
		(unsigned char *)udph - (unsigned char *)iph,
		(unsigned char *)iph - (unsigned char *)sllh);

	/* IEEE 1588 */
	memcpy(pload, ptp_msg, pktlen);

verbose(LOG_ERR, "pload = %x", *(uint32_t *)pload);
verbose(LOG_ERR, "pload = %x", *(uint32_t *)ptp_msg);



	/* UDP header */
#if defined(__FreeBSD__) || defined (__APPLE__)
	udph->uh_sport = htons(319);
	udph->uh_dport = htons (319);
#else
	udph->source = htons(319);
	udph->dest = htons (319);
#endif
	udph->check = 0;
	udph->len = htons(sizeof(struct udphdr) + pktlen);

	/* IP header */
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0x0;
	iph->id = 0;
	iph->frag_off = htons(0x4000);        /* DF */
	iph->ttl = 64;
	iph->protocol = 17;
	iph->saddr = IEEE1588_CLIENT(handle)->s_from.sin_addr.s_addr;
	iph->daddr = IEEE1588_CLIENT(handle)->s_to.sin_addr.s_addr;
	iph->tot_len = htons(sizeof (struct iphdr) + sizeof(struct udphdr) + pktlen);
	iph->check = 0;
	checksum = do_ip_checksum((uint16_t *)iph, 20);
//	iph->check = htons(checksum);
	iph->check = checksum;

	/* Recompute UDP checksum */
	checksum = do_udp_checksum((uint16_t *)&iph->saddr, (uint16_t *)&iph->daddr,
			(uint16_t *)pload, sizeof(struct udphdr) + pktlen);
	udph->check = checksum;

	/* SLL */
	sllh->pkttype = htons(3);	/* LINUX_SLL_OTHERHOST */
	sllh->hatype = htons(1);	/* ARPHRD_ETHER : 10/100 Mbps Ethernet */
	sllh->protocol = htons(ETHERTYPE_IP);

	/* Insert the new bundle in the linked list */
	rdb->next = NULL;
	rdb->read = 0;
	rdb->type = RD_TYPE_1588;
	insert_rdb_in_list(handle->ieee1588eq_queue, rdb);
}
#endif

int
capture_raw_data(struct radclock_handle *handle)
{
	int err;

	JDEBUG

	err = 0;
	switch(handle->run_mode) {

	case RADCLOCK_SYNC_LIVE:
		switch (handle->conf->synchro_type) {
		case SYNCTYPE_SPY:
			err = spy_loop(handle);
			break;

		case SYNCTYPE_PIGGY:
		case SYNCTYPE_NTP:
			/* Call pcap_loop() with number of packet =-1 so that it
			 * actually never returns until error or explicit break.
			 * pcap_loop will block until receiving packets to process.
			 * The fill_rawdata_ntp callback is in charge of extracting
			 * relevant information and inserting raw data bundles in the
			 * linked list known by the clock handle.
			 */
			err = pcap_loop(handle->clock->pcap_handle, -1 /*packet*/,
					fill_rawdata_ntp, (u_char *) handle);
			break;

		case SYNCTYPE_1588:
			err = pcap_loop(handle->clock->pcap_handle, -1 /*packet*/,
					fill_rawdata_1588, (u_char *) handle);
			break;

		case SYNCTYPE_PPS:
			verbose(LOG_ERR, "IMPLEMENT ME!!");
			err = -1;
			break;

		case SYNCTYPE_VM_UDP:
		case SYNCTYPE_XEN:
		case SYNCTYPE_VMWARE:
			err = receive_loop_vm(handle);
			break;

		default:
			break;
		}
		break;

	/* Since we are the radclock, we should know which mode we run in !! */	
	case RADCLOCK_SYNC_DEAD:
	case RADCLOCK_SYNC_NOTSET:
	default:
		verbose(LOG_ERR, "Trying to capture data with wrong running mode");
		return (-1);
	}

	/* Error can be -1 (read error) or -2 (explicit loop break) */
	if (err < 0)
		return (err);

	/* Pass here if running in spy_loop for example */
	return (0);
}



/* This function will free the raw_data that has already been read and deliver
 * the next raw data element to read. Remember that the access to the raw data
 * buffer is lock free (e.g., pcap_loop() is adding element to it) !!
 * IMPORTANT: Forbidden to screw up in here, there is no safety net
 */
struct raw_data_bundle *
free_and_cherrypick(struct raw_data_queue *rq)
{
	struct raw_data_bundle *rdb, *rdb_tofree;

	JDEBUG

	/* Position at the end of the buffer */
	rdb_tofree = NULL;
	rdb = rq->rdb_end;

	/* Is the buffer empty ? */
	if (rdb == NULL)
		return (rdb);

	/*
	 * Free data that has been read previously. We make sure we never remove the
	 * first element of the list. So that pcap_loop() does not get confused
	 */
	while (rdb != rq->rdb_start) {
		if (rdb->read == 0)
			break;
		else {
			/* Record who is the buddy to kill */
			rdb_tofree = rdb;
			rdb = rdb->next;
			
			/* Position new end of the raw data buffer and nuke */
			// XXX again, should get rid of the locking
			pthread_mutex_lock(&rq->rdb_mutex);
			rq->rdb_end = rdb;
			rdb_tofree->next = NULL;

			if (rdb_tofree->type == RD_TYPE_NTP) {
				JDEBUG_MEMORY(JDBG_FREE, RD_PKT(rdb_tofree)->buf);
				free(RD_PKT(rdb_tofree)->buf);
				RD_PKT(rdb_tofree)->buf = NULL;
			}
			JDEBUG_STR( "FREE: rdb at %p, ->next at %p, end at %p, start at %p",
				rdb_tofree, rdb_tofree->next,
				rq->rdb_end, rq->rdb_start);
			JDEBUG_MEMORY(JDBG_FREE, rdb_tofree);
			free(rdb_tofree);
			rdb_tofree = NULL;
			pthread_mutex_unlock(&rq->rdb_mutex);
		}
	}
	/* Remember we never delete the first element of the raw data buffer. So we
	 * can have a lock free add at the HEAD of the list. However, we may have
	 * read the first element, so we don't want get_bidir_stamp() to spin like
	 * a crazy on this return. If we read it before, return error code.
	 * Here, rdb should NEVER be NULL. If we sef fault here, blame the guy who
	 * wrote that ...
	 */
	if (rdb->read == 1)
		return (NULL);

	return (rdb);
}




int
deliver_rawdata_spy(struct radclock_handle *handle, struct stamp_t *stamp)
{
	struct raw_data_bundle *rdb;

	JDEBUG

	/* Do some clean up if needed and gives the current raw data bundle
	 * to process.
	 */
	// TODO should have it's own queue
	rdb = free_and_cherrypick(handle->pcap_queue);

	/* Check we have something to do */
	if (rdb == NULL)
		return (1);

	if (rdb->type != RD_TYPE_SPY) {
		verbose(LOG_ERR, "!! Asked to deliver SPY stamps from rawdata but "
				"parsing other type !!");
		return (-1);
	}

	BST(stamp)->Ta = RD_SPY(rdb)->Ta;
	BST(stamp)->Tb = (long double) (RD_SPY(rdb)->Tb.tv_sec) +
			(long double) (RD_SPY(rdb)->Tb.tv_usec / 1e6);
	BST(stamp)->Te = (long double) (RD_SPY(rdb)->Te.tv_sec) +
			(long double) (RD_SPY(rdb)->Te.tv_usec / 1e6);
	BST(stamp)->Tf = RD_SPY(rdb)->Tf;
	stamp->type = STAMP_SPY;
	stamp->qual_warning = 0;

	/* Mark this raw data element read */
	rdb->read = 1;

	return (0);
}




// XXX TODO XXX this is a bit messy. some parts are specific to the source,
// maybe that should be in the corresponding file?  Quite complicated with
// multiple sources, the chain list management is not re-entrant with multiple
// sources!!
int
deliver_rawdata_pcap(struct raw_data_queue *rq, int pcap_datalink,
		struct radpcap_packet_t *pkt, vcounter_t *vcount)
{
	struct raw_data_bundle *rdb;

	JDEBUG

	/* Do some clean up if needed and gives the current raw data bundle
	 * to process.
	 */
	rdb = free_and_cherrypick(rq);

	/* Check we have something to do */
	if (rdb == NULL)
		return (1);

	if ((rdb->type != RD_TYPE_NTP) && (rdb->type != RD_TYPE_1588)) {
		verbose(LOG_ERR, "Asked to deliver pcap packet from rawdata but "
				"parsing other type !!");
		return (1);
	}

	/* Copy pcap header and packet payload back-to-back.
	 * The buffer is defined to be way larger than what we need, so
	 * should be safe to copy the captured payload.
	 */
	memcpy(pkt->buffer, &(RD_PKT(rdb)->pcap_hdr), sizeof(struct pcap_pkthdr));
	memcpy(pkt->buffer + sizeof(struct pcap_pkthdr), RD_PKT(rdb)->buf,
			RD_PKT(rdb)->pcap_hdr.caplen);

	/* Position the pointers of the radpcap_packet structure */
	pkt->header = pkt->buffer;
	pkt->payload = pkt->buffer + sizeof(struct pcap_pkthdr);
	pkt->size = RD_PKT(rdb)->pcap_hdr.caplen + sizeof(struct pcap_pkthdr);
	pkt->type = pcap_datalink;

	/* Fill the vcount */
	*vcount = RD_PKT(rdb)->vcount;

	/* Mark this raw data element read */
	rdb->read = 1;

	return (0);
}

