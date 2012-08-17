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

#include "../config.h"

// XXX so far, we only know how to do this on linux
#ifndef WITH_RADKERNEL_LINUX
int ieee1588_client_init(struct radclock_handle *handle) { return (1); }
int ieee1588_client(struct radclock_handle *handle) { return(1); }

#else	/* WITH_RADKERNEL_LINUX */

#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>

#include <arpa/inet.h>
#include <net/if.h>

// H/W timestamping specific
#include <asm/types.h>
#include <linux/net_tstamp.h>
#include <linux/errqueue.h>
#include <linux/sockios.h>

#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <syslog.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "radclock.h"
#include "radclock-private.h"
#include "radclock_daemon.h"
#include "misc.h"
#include "verbose.h"
#include "sync_history.h"
#include "sync_algo.h"
#include "config_mgr.h"
#include "proto_1588.h"
#include "pthread_mgr.h"
#include "jdebug.h"



static void
pack_ptpstamp(uint8_t *p, struct ptp_stamp *stamp)
{
	uint32_t lsec;

	lsec = stamp->sec & 0xFFFFFFFF;
	*p = htons((uint16_t)(stamp->sec >> 32));
	*(p + 2) = htonl((uint32_t)(lsec));
	*(p + 6) = htonl((uint32_t)(stamp->nsec));
}


static void
unpack_ptpstamp(uint8_t *p, struct ptp_stamp *stamp)
{
	uint64_t sec;

	sec = ntohs(*(uint16_t *)p);
	sec = sec << 32;
	stamp->sec = ntohl(*(uint32_t *)(p + 2));
	stamp->sec |= sec;
	stamp->nsec = ntohl(*(uint32_t *)(p + 6));
}


static int
create_delay_req(struct radclock_handle *handle, uint8_t *buf, size_t *bytes,
	int seq, uint8_t *clock_id)
{
	struct ptp_header *hdr;
	struct ptp_delayreq *req;
	vcounter_t vcount;
	long double time;
	struct ptp_stamp stamp;

	*bytes = sizeof(struct ptp_header) + sizeof(struct ptp_delayreq);

	/* Setup the ptp header */
	// TODO: this needs to be finished
	hdr = (struct ptp_header *) buf;
	hdr->type_transp_flags  |= PTP_MSG_TYPE(0x1);
	hdr->ver_reserved_flags |= PTP_VERSION(0x2);
	hdr->length = ntohs(44);
	memcpy(hdr->src_port, clock_id, 10);

	hdr->seq = ntohs((uint16_t)seq);
	hdr->control = 1;

	/* Put the delay request in */
	req = (struct ptp_delayreq *) (buf + PTP_HEADER_LEN);
	radclock_get_vcounter(verbose_data.handle->clock, &vcount);
	counter_to_time(&handle->rad_data, &vcount, &time);
	stamp.sec = (uint64_t)time;
	stamp.nsec = (uint32_t)(1e9 * (time - (uint64_t)time));
	pack_ptpstamp((uint8_t *)&req->stamp, &stamp);

	return (0);
}


/*
 * Init 1588 client code. Create socket for sending Delay Requests and retrieve
 * hardware timestamps from the error queue. Details on how to have hardware
 * timestamps on the sending side is from Linux kernel documentation:
 * <kernel>/Documentation/networking/timestamping/timestamp.c
 */
int
ieee1588_client_init(struct radclock_handle *handle)
{
	int sd, hwts_flag, err;
	struct ifreq device, hwtstamp;
	struct hwtstamp_config hwconfig;
	struct sockaddr_in addr;
	struct ip_mreq imr;
	const char *dev = handle->conf->network_device;

	/* Create the sockets */
	sd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sd == -1) {
		verbose (LOG_ERR, "Failed creating 1588 event socket");
		return (1);
	}

	/* Allow binding to a socket already bound */
	setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, (int []){1}, sizeof(int));

	/* Set the specified device as the interface to use */
	setsockopt(sd, SOL_SOCKET, SO_BINDTODEVICE, dev, strlen(dev));

	/* Enable HW timestamping: get the interface device address */
	memset(&device, 0, sizeof(device));
	strncpy(device.ifr_name, dev, sizeof(device.ifr_name));
	err = ioctl(sd, SIOCGIFADDR, &device);
	if (err == -1) {
		verbose(LOG_ERR, "ioctl: device %s", device);
		return (1);
	}

	/* Enable HW timestamping */
	if (handle->conf->hw_tstamp) {
		memset(&hwtstamp, 0, sizeof(hwtstamp));
		strncpy(hwtstamp.ifr_name, dev, sizeof(hwtstamp.ifr_name));
		hwtstamp.ifr_data = (void *)&hwconfig;
		memset(&hwconfig, 0, sizeof(hwconfig));
		hwconfig.tx_type = HWTSTAMP_TX_ON;
		hwconfig.rx_filter = HWTSTAMP_FILTER_ALL;
		err = ioctl(sd, SIOCSHWTSTAMP, &hwtstamp);
		if (err == -1) {
			verbose(LOG_ERR, "ioctl: hwtstamp");
			return (1);
		}
	}

	/* Create the address data */
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(319);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	/* Bind */
	err = bind(sd, (const struct sockaddr *)&addr, sizeof(addr));
	if (err == -1) {
		verbose(LOG_ERR, "Binding to the event socket");
		return (1);
	}

	/* Set multicast group for outgoing packets */
	inet_aton(PTP_MULTICAST_PRIMARY, &addr.sin_addr);
	imr.imr_multiaddr.s_addr = addr.sin_addr.s_addr;
	imr.imr_interface.s_addr =
			((struct sockaddr_in *)&device.ifr_addr)->sin_addr.s_addr;
	err = setsockopt(sd, IPPROTO_IP, IP_MULTICAST_IF, &imr.imr_interface.s_addr,
			sizeof(struct in_addr));
	if (err == -1) {
		verbose(LOG_ERR, "Enabling multicast interface");
		return (1);
	}

	/* Join multicast group */
	err = setsockopt(sd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &imr,
			sizeof(struct ip_mreq));
	if (err == -1) {
		verbose(LOG_ERR, "Joining multicast group");
		return (1);
	}

	/* Enable multicast loop-back */
	err = setsockopt(sd, IPPROTO_IP, IP_MULTICAST_LOOP, (int []){1}, sizeof(int));
	if (err == -1) {
		verbose(LOG_ERR, "Enabling multicast loop-back");
		return (1);
	}

	/*
	 * Set the socket timestamping flags for receiving both the raw hardware
	 * timestamp and the hardware timestamp converted to system time.  We only
	 * do this for packet TX.  This data is available via ancillary cmsg data.
	 */
	if (handle->conf->hw_tstamp) {
		hwts_flag = SOF_TIMESTAMPING_TX_HARDWARE  |
					SOF_TIMESTAMPING_SYS_HARDWARE |
					SOF_TIMESTAMPING_RAW_HARDWARE;

		err = setsockopt(sd, SOL_SOCKET, SO_TIMESTAMPING, &hwts_flag,
				sizeof(hwts_flag));
		if (err == -1) {
			verbose(LOG_ERR, "setsockopt hwtstamp");
			return (1);
		}
	}

	/* Registre the socket in the radclock handle */
	IEEE1588_CLIENT(handle)->socket = sd;
	IEEE1588_CLIENT(handle)->s_to = addr;

	return (0);
}



/*
 * Read data from the sock and plop it into a packet, also preserve the addr.
 * Much thanks to: http://linuxgazette.net/149/misc/melinte/ttools.c and
 * <kernel_source>/Documentation/networking/timestamping/timestamp.c
 */
static void
get_errq_data(struct radclock_handle *handle, char *clock_id)
{
	ssize_t bytes;
	struct msghdr msg;
	struct iovec iov;
	struct cmsghdr *cmsg, *cmsgts;
	struct sockaddr_in addr;
	uint64_t *stamp;
	struct timespec kstamp;
	vcounter_t vcount;
	struct ptp_header *ptph;
	unsigned char buf[1024] = {0};
	int sd;

	memset(&addr, 0, sizeof(addr));
	memset(&iov, 0, sizeof(iov));
	memset(&msg, 0, sizeof(msg));
	msg.msg_name = (unsigned char *)&addr;
	msg.msg_namelen = sizeof(addr);
	msg.msg_control = buf;
	msg.msg_controllen = sizeof(buf);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_flags = 0;
	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);

	/* Get the message back from the socket's error queue */
// XXX should we use recvfrom instead to check addr etc.?
	sd = IEEE1588_CLIENT(handle)->socket;

	if ((bytes = recvmsg(sd, &msg, MSG_ERRQUEUE | MSG_DONTWAIT)) < 0)
		return;

	/* Iterate across the aux/ancliarily data for the message from the errq */
	for (cmsg=CMSG_FIRSTHDR(&msg); cmsg; cmsg=CMSG_NXTHDR(&msg, cmsg)) {
		/*
		 * This has to be a DELAY_REQ. Make sure we have received enough bytes
		 * to parse the header, check a few fields to see if it is an IEEE 1588
		 * message (version, type and clock_id since we sent it).
		 */
		if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_RECVERR) {
			if (bytes < (sizeof(struct ptp_header) + sizeof(struct ptp_delayreq)))
				continue;
			ptph = (struct ptp_header *)CMSG_DATA(cmsg);

			if (PTP_MSG_TYPE(ptph->type_transp_flags) != 0x1 ||
					PTP_VERSION(ptph->ver_reserved_flags) != 0x2 ||
					memcmp(ptph->src_port, clock_id, 10) != 0) {
				continue;
			}
		}

		/*
		 * We found a delay request, the next cmsg header must give us access to
		 * hardware timestamps. If not, disregard this cmsg. Is it possible the
		 * model breaks (ie, changes in kernel implementation)? Possibly, so
		 * this should break, good warning.
		 * Following is the series of timestamps set via setsockopt for
		 * SO_TIMESTAMPING. Logic is based on implementation in timestamp.c in
		 * the kernel docs <kernel>/Documentation/networking/timestamping/.
		 * If implementation changes, good luck figuring out whats changed.
		 */
		cmsgts = CMSG_NXTHDR(&msg, cmsg);
		if (cmsgts->cmsg_level != SOL_SOCKET ||
				cmsgts->cmsg_type != SO_TIMESTAMPING)
			continue;

		/*
		 * Software timestamp (should be all zeros as we didnt set it via
		 * setsockopt)
		 */
		stamp = (uint64_t *)CMSG_DATA(cmsg);
		verbose(VERB_DEBUG,"1588 EQ - SW: %ld.%09ld\n",
				(long)((struct timespec *)stamp)->tv_sec,
				(long)((struct timespec *)stamp)->tv_nsec);

		/* The next timestamp is the hw counter converted to sys time */
		++stamp;
		kstamp = *((struct timespec *)stamp);
		printf(VERB_DEBUG, "1588 EQ - HW Modified: %ld.%09ld\n",
				(long)kstamp.tv_sec, (long)kstamp.tv_nsec);

		/* The third timestamp is the raw hardware counter value */
		++stamp;
		vcount = *(vcounter_t *)stamp;
		verbose(VERB_DEBUG,"1588 EQ - Raw: %llu\n", (long long)vcount);

		// Need to insert the packet in fake pcap queue
		fill_rawdata_1588eq(handle, vcount, kstamp, CMSG_DATA(cmsg),
				sizeof(struct ptp_header) + sizeof(struct ptp_delayreq));
	}
}


int
ieee1588_client(struct radclock_handle *handle)
{
	/* Max of delay(44) and pdelay request (54) */
	uint8_t buf[54];
	size_t bytes;
	fd_set fds;
	int err;
	char *clock_id = "ADEADBEEFS";
	int seq = 666;
	struct timeval tv;

	/* Create a message to send */
	err = create_delay_req(handle, buf, &bytes, seq, (uint8_t *)clock_id);
	if (err) {
		verbose(LOG_ERR, "Failed creating 1588 delay request");
		return (1);
	}

	/* Send a delay request */
	err = sendto(IEEE1588_CLIENT(handle)->socket, buf, bytes, 0,
			(struct sockaddr *)&(IEEE1588_CLIENT(handle)->s_to),
			sizeof(struct sockaddr_in));
	if (err == -1) {
		verbose(LOG_ERR, "Sending DelayRequest message");
		return (1);
	}

	/* Receive data */
	FD_ZERO(&fds);
	FD_SET(IEEE1588_CLIENT(handle)->socket, &fds);
	memset(&tv, 0, sizeof(tv));
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	err = select(IEEE1588_CLIENT(handle)->socket + 1, &fds, NULL, NULL, &tv);
	if (err == -1) {
		verbose(LOG_ERR, "IEEE 1588 Select error on socket");
		return (1);
	}

	/* Check the sockets */
	if (FD_ISSET(IEEE1588_CLIENT(handle)->socket, &fds))
		get_errq_data(handle, clock_id);

	/* Wait and resend */
	sleep(1);

	return (0);
}

#endif
