/*-
 * Copyright (C) 2010-2019 Daisuke Aoyama <aoyama@peach.ne.jp>
 * All rights reserved.
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
 *
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/endian.h>
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <machine/_inttypes.h>
#include "ibft.h"
#include "isboot.h"

#if __FreeBSD_version < 1100000
#define kern_getenv getenv
#endif

extern uint8_t *ibft_signature;

struct kenv_ibft {
	struct ibft_table_header header;
	struct ibft_control control;
	struct ibft_initiator initiator;
	struct ibft_nic nic0;
	struct ibft_target target0;
	struct ibft_nic nic1;
	struct ibft_target target1;
	uint8_t initiator_name [ISBOOT_NAME_MAX];
	uint8_t target_name [ISBOOT_NAME_MAX];
	uint8_t host_name [ISBOOT_NAME_MAX];
	uint8_t chap_user [ISBOOT_CHAP_MAX];
	uint8_t chap_secret [ISBOOT_CHAP_MAX];
} kenv_ibft;

uint8_t *
ibft_create_kenv_table(void)
{
	uint8_t *ibft;
	char *cp;
	int sum, i;

	/* fake iBFT can be disabled */
	cp = kern_getenv("ibft.kenv.disabled");
	if (cp != NULL) {
		if (cp[0] != '\0' && strcmp(cp, "0") != 0)
			return (NULL);
	}

	/* iBF Table Header */
	struct ibft_table_header *header = &kenv_ibft.header;
	header->signature[0] = 'i';
	header->signature[1] = 'B';
	header->signature[2] = 'F';
	header->signature[3] = 'T';
	header->length = htole16(sizeof kenv_ibft);
	header->revision = 1;
	header->checksum = 0;
	strncpy(header->oemid, "ISBOOT", 6);
	strncpy(header->oemtableid, "ISBOOT", 8);
	memset(header->reserved, 0, 24);

	/* Control Structure */
	struct ibft_control *control = &kenv_ibft.control;
	control->id = IBFT_ID_CONTROL;
	control->version = 1;
	control->length = htole16(sizeof kenv_ibft.control);
	control->index = 0;
	control->flags = 0;

	control->extensions = 0;
	control->initiator_offset = htole16(offsetof(struct kenv_ibft, initiator));
	control->nic0_offset = htole16(offsetof(struct kenv_ibft, nic0));
	control->target0_offset = htole16(offsetof(struct kenv_ibft, target0));
	control->nic1_offset = 0;
	control->target1_offset = 0;

	/* Initiator Structure */
	struct ibft_initiator *initiator = &kenv_ibft.initiator;
	initiator->id = IBFT_ID_INITIATOR;
	initiator->version = 1;
	initiator->length = htole16(sizeof kenv_ibft.initiator);
	initiator->index = 0;
	initiator->flags = 0x03;

	memset(initiator->isns, 0 , IBFT_IP_LEN);
	memset(initiator->slp, 0, IBFT_IP_LEN);
	memset(initiator->pri_radius, 0, IBFT_IP_LEN);
	memset(initiator->sec_radius, 0, IBFT_IP_LEN);
	initiator->name_length = 0;
	initiator->name_offset = 0;

	cp = kern_getenv("ibft.initiator");
	if (cp != NULL) {
		strncpy(kenv_ibft.initiator_name, cp, ISBOOT_NAME_MAX - 1);
		kenv_ibft.initiator_name[ISBOOT_NAME_MAX - 1] = '\0';
		freeenv(cp);
		initiator->name_length = htole16(strlen(kenv_ibft.initiator_name));
		initiator->name_offset = htole16(offsetof(struct kenv_ibft, initiator_name));
	}

	/* NIC Structure */
	struct ibft_nic *nic0 = &kenv_ibft.nic0;
	nic0->id = IBFT_ID_NIC;
	nic0->version = 1;
	nic0->length = htole16(sizeof kenv_ibft.nic0);
	nic0->index = 0;
	nic0->flags = 0x03;

	memset(nic0->ip, 0, IBFT_IP_LEN);
	nic0->mask_prefix = 0;
	nic0->origin = 0;
	memset(nic0->gateway, 0, IBFT_IP_LEN);
	memset(nic0->pri_dns, 0, IBFT_IP_LEN);
	memset(nic0->sec_dns, 0, IBFT_IP_LEN);
	memset(nic0->dhcp, 0, IBFT_IP_LEN);
	nic0->vlan = htole16(0);
	memset(nic0->mac, 0, IBFT_MAC_LEN);
	nic0 ->pci_bus_dev_func = 0; /* bus=8, dev=5, func=3 bits */
	nic0->host_name_length = 0;
	nic0->host_name_offset = 0;

	cp = kern_getenv("ibft.nic_host");
	if (cp != NULL) {
		strncpy(kenv_ibft.host_name, cp, ISBOOT_NAME_MAX - 1);
		kenv_ibft.host_name[ISBOOT_NAME_MAX - 1] = '\0';
		freeenv(cp);
		nic0->host_name_length = htole16(strlen(kenv_ibft.host_name));
		nic0->host_name_offset = htole16(offsetof(struct kenv_ibft, host_name));
	}

	cp = kern_getenv("ibft.nic_addr");
	if (cp != NULL) {
	        unsigned int ip0, ip1, ip2, ip3, ip4, ip5, ip6, ip7;
		if (sscanf(cp, "%u.%u.%u.%u", &ip0, &ip1, &ip2, &ip3) == 4) {
			/* IPv4-mapped IPv6 */
			*(uint16_t*)(nic0->ip +  0) = htobe16(0);
			*(uint16_t*)(nic0->ip +  2) = htobe16(0);
			*(uint16_t*)(nic0->ip +  4) = htobe16(0);
			*(uint16_t*)(nic0->ip +  6) = htobe16(0);
			*(uint16_t*)(nic0->ip +  8) = htobe16(0);
			*(uint16_t*)(nic0->ip + 10) = htobe16(0xffffU);
			*(uint8_t*)(nic0->ip + 12) = ip0;
			*(uint8_t*)(nic0->ip + 13) = ip1;
			*(uint8_t*)(nic0->ip + 14) = ip2;
			*(uint8_t*)(nic0->ip + 15) = ip3;
		} else if (sscanf(cp, "%x:%x:%x:%x:%x:%x:%x:%x",
			&ip0, &ip1, &ip2, &ip3, &ip4, &ip5, &ip6, &ip7) == 8) {
			/* IPv6 */
			*(uint16_t*)(nic0->ip +  0) = htobe16(ip0);
			*(uint16_t*)(nic0->ip +  2) = htobe16(ip1);
			*(uint16_t*)(nic0->ip +  4) = htobe16(ip2);
			*(uint16_t*)(nic0->ip +  6) = htobe16(ip3);
			*(uint16_t*)(nic0->ip +  8) = htobe16(ip4);
			*(uint16_t*)(nic0->ip + 10) = htobe16(ip5);
			*(uint16_t*)(nic0->ip + 12) = htobe16(ip6);
			*(uint16_t*)(nic0->ip + 14) = htobe16(ip7);
		}
		freeenv(cp);
	}

	cp = kern_getenv("ibft.nic_mask");
	if (cp != NULL) {
		unsigned int mask;
		if (sscanf(cp, "%u", &mask) == 1) {
			nic0->mask_prefix = mask & 0xffU;
		}
		freeenv(cp);
	}

	cp = kern_getenv("ibft.nic_vlan");
	if (cp != NULL) {
		unsigned int vlan;
		if (sscanf(cp, "%u", &vlan) == 1) {
			nic0->vlan = htole16(vlan & 0xffffU);
		}
		freeenv(cp);
	}

	cp = kern_getenv("ibft.nic_mac");
	if (cp != NULL) {
		unsigned int mac0, mac1, mac2, mac3, mac4, mac5;
		if (sscanf(cp, "%x:%x:%x:%x:%x:%x",
			&mac0, &mac1, &mac2, &mac3, &mac4, &mac5) == 6) {
			/* Ether Address */
			nic0->mac[0] = mac0;
			nic0->mac[1] = mac1;
			nic0->mac[2] = mac2;
			nic0->mac[3] = mac3;
			nic0->mac[4] = mac4;
			nic0->mac[5] = mac5;
		}
		freeenv(cp);
	}

	/* Target Structure */
	struct ibft_target *target0 = &kenv_ibft.target0;
	target0->id = IBFT_ID_TARGET;
	target0->version = 1;
	target0->length = htole16(sizeof kenv_ibft.target0);
	target0->index = 0;
	target0->flags = 0x03;

	memset(target0->ip, 0, IBFT_IP_LEN);
	target0->port = htole16(0);
	target0->lun = htole64(0);
	target0->chap_type = 0;
	target0->nic_index = 0;
	target0->name_length = 0;
	target0->name_offset = 0;
	target0->chap_name_length = 0;
	target0->chap_name_offset = 0;
	target0->chap_secret_length = 0;
	target0->chap_secret_offset = 0;
	target0->rev_chap_name_length = 0;
	target0->rev_chap_name_offset = 0;
	target0->rev_chap_secret_length = 0;
	target0->rev_chap_secret_offset = 0;

	cp = kern_getenv("ibft.target");
	if (cp != NULL) {
		strncpy(kenv_ibft.target_name, cp, ISBOOT_NAME_MAX - 1);
		kenv_ibft.target_name[ISBOOT_NAME_MAX - 1] = '\0';
		freeenv(cp);
		target0->name_length = htole16(strlen(kenv_ibft.target_name));
		target0->name_offset = htole16(offsetof(struct kenv_ibft, target_name));
	}

	cp = kern_getenv("ibft.target_addr");
	if (cp != NULL) {
	        unsigned int ip0, ip1, ip2, ip3, ip4, ip5, ip6, ip7;
		if (sscanf(cp, "%u.%u.%u.%u", &ip0, &ip1, &ip2, &ip3) == 4) {
			/* IPv4-mapped IPv6 */
			*(uint16_t*)(target0->ip +  0) = htobe16(0);
			*(uint16_t*)(target0->ip +  2) = htobe16(0);
			*(uint16_t*)(target0->ip +  4) = htobe16(0);
			*(uint16_t*)(target0->ip +  6) = htobe16(0);
			*(uint16_t*)(target0->ip +  8) = htobe16(0);
			*(uint16_t*)(target0->ip + 10) = htobe16(0xffffU);
			*(uint8_t*)(target0->ip + 12) = ip0;
			*(uint8_t*)(target0->ip + 13) = ip1;
			*(uint8_t*)(target0->ip + 14) = ip2;
			*(uint8_t*)(target0->ip + 15) = ip3;
		} else if (sscanf(cp, "%x:%x:%x:%x:%x:%x:%x:%x",
			&ip0, &ip1, &ip2, &ip3, &ip4, &ip5, &ip6, &ip7) == 8) {
			/* IPv6 */
			*(uint16_t*)(target0->ip +  0) = htobe16(ip0);
			*(uint16_t*)(target0->ip +  2) = htobe16(ip1);
			*(uint16_t*)(target0->ip +  4) = htobe16(ip2);
			*(uint16_t*)(target0->ip +  6) = htobe16(ip3);
			*(uint16_t*)(target0->ip +  8) = htobe16(ip4);
			*(uint16_t*)(target0->ip + 10) = htobe16(ip5);
			*(uint16_t*)(target0->ip + 12) = htobe16(ip6);
			*(uint16_t*)(target0->ip + 14) = htobe16(ip7);
		}
		freeenv(cp);
	}

	cp = kern_getenv("ibft.target_port");
	if (cp != NULL) {
		unsigned int port;
		if (sscanf(cp, "%u", &port) == 1) {
			target0->port = htole16(port & 0xffffU);
		}
		freeenv(cp);
	}

	cp = kern_getenv("ibft.target_lun");
	if (cp != NULL) {
		uint64_t lun;
		if (sscanf(cp, "%"PRIu64, &lun) == 1) {
			target0->lun = htole64(lun);
		}
		freeenv(cp);
	}

	/* compute checksum of iBFT */
	ibft = (uint8_t*)&kenv_ibft;
	for (i = 0, sum = 0; i < sizeof kenv_ibft; i++) {
		sum += *((uint8_t *)ibft + i);
	}
	sum = 0x100 - (sum & 0xff);
	header->checksum = sum;

	return (ibft);
}
