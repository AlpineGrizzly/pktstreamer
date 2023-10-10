/*
	Copyright (C) 2023 Brett Kuskie <fullaxx@gmail.com>

	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; version 2 of the License.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program; if not, write to the Free Software
	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
//#include <unistd.h>
#include <errno.h>
#include "pcap/pcap.h"
#include "manual_dissection.h"
#include "async_zmq_sub.h"

// Prototypes
void count_packet(unsigned int pkts, unsigned int bytes);

// Globals
unsigned int g_linktype = 0;
unsigned int g_magic = 0;

// Externals found in pkt_recv.c
extern unsigned int g_shutdown;
extern unsigned int g_us_ts;
extern unsigned int g_ns_ts;
extern unsigned long g_zmqerr_count;
extern unsigned long g_zmqpkt_count;

/* Ethertype processing functions */

/* Network link layer process functions */
static int process_ipv4(unsigned char*buf, int len);
static int process_ipv4_options(unsigned char* buf, int len, int opt_len);

static int process_ipv6(unsigned char* buf, int len);

static int process_rth(unsigned char* buf, int len);
static void process_rth_flags(unsigned char* buf, int len, uint32_t flags);

static void process_ppp(unsigned char*buf, int len);
static void process_ppp_hdlc(unsigned char*buf, int len);
static int process_arp(unsigned char*buf, int len);

/* Extraneous functions */
static void print_mac(uint8_t *mac);

/* Ipv4 Transport layer process functions */
static int process_tcp(unsigned char* buf, int len);
static int process_tcp_options(unsigned char* buf, int len);
static int process_udp(unsigned char* buf, int len);

static void process_ip(unsigned char *buf, uint8_t proto);    /* https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers */
static int resolve_ip_proto(unsigned char* buf, int len, int proto);
static void process_ieee(unsigned char *buf, uint16_t proto); /* https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml#ieee-802-numbers-1 */

static int process_tcp_options(unsigned char* buf, int len) { 
	/* Simple print the tcp kind */
	tcp_opt_t* opt = (tcp_opt_t*)buf;
	int r_bytes = 0; /* Bytes processed */

	if (len < 1) return 0;/* Make sure we have enough bytes to switch on kind */

	/* Switch on kind */
	switch(opt->kind)  {
		case TCP_EOOL:
			printf("TCP_EOOL ");
			r_bytes += 1;
			break;
		case TCP_NOP:
			printf("TCP_NOP ");
			r_bytes += 1;
			break;
		case TCP_MSS:
			printf("TCP_MSS ");
			r_bytes += opt->len;
			break;
		case TCP_WS:
			printf("TCP_WS ");
			r_bytes += opt->len;
			break;
		case TCP_SP:
			printf("TCP_SP ");
			r_bytes += opt->len;
			break;
		case TCP_S:
			printf("TCP_S ");
			r_bytes += opt->len;
			break;
		case TCP_ECHO:
			printf("TCP_ECHO ");
			r_bytes += opt->len;
			break;
		case TCP_ECHOR:
			printf("TCP_ECHOR ");
			r_bytes += opt->len;
			break;
		case TCP_TS:
			printf("TCP_TS ");
			r_bytes += opt->len;
			break;
		default: 
			return 0;
	}

	len -= r_bytes;

	if (len > 0)
		r_bytes += process_tcp_options(&buf[r_bytes], len);
	
	return r_bytes;
}

/** 
 * process_tcp
 * 
 * Process the transport level tcp header
 * 
 * @param buf Pointer to buffer beginning with the first byte of tcp header
 * @param len Length of buffer
 * 
 * @return Number of bytes processed in tcp header
*/
static int process_tcp(unsigned char* buf, int len) { 
	tcp_t* tcp_h = (tcp_t*)buf; // Overlay tcp header over buffer
	int r_bytes = 0; /* Bytes processed */

	if (len < TCP_T_SIZE) return 0; // Base case , do we have bytes to extracter header
	
	/* Extract bit fields */
	uint16_t h_cookie_jar = H_16(tcp_h->do_rs_c); /* Get the data offset, reserve, and control bit fields */
	uint8_t h_len = ((h_cookie_jar >> 12) & 0xf)*4; /* Network words to bytes */ 
	uint8_t rsvd = (h_cookie_jar >> 8) & 0xf;
	uint8_t control = 0; /* To be further broken up */ 

	/* Extract fields */
	printf("%d %d %ld %ld %02X %X %X %d %02X %d ", 
			H_16(tcp_h->s_port),
			H_16(tcp_h->d_port),
			H_32(tcp_h->seq),
			H_32(tcp_h->ack),
			h_len,
			rsvd, 
			control, 
			H_16(tcp_h->win),
			H_16(tcp_h->check),
			H_16(tcp_h->p));
	
	r_bytes += TCP_T_SIZE;
	len -= r_bytes;

	/* Process options if they exist */
	/* Reference https://datatracker.ietf.org/doc/html/draft-ietf-tcpm-tcp-edo-12 */
	if (h_len > TCP_T_SIZE) { 
		printf("TCP_OPT ");
		r_bytes += process_tcp_options(&buf[TCP_T_SIZE], h_len - r_bytes);
	}
	
	return r_bytes;
}

/** 
 * process_udp
 * 
 * Process the transport level udp header
 * 
 * @param buf Pointer to buffer beginning with the first byte of udp header
 * @param len Length of buffer
 * 
 * @return Number of bytes processed in udp header
*/
static int process_udp(unsigned char* buf, int len) { 
	/* Check if we have enough bytes in our length for header */
	if (len < UDP_T_SIZE) return 0;

	udp_t* udp_h = (udp_t *)buf; /* Overlay udp header on buffer */
	int udp_len;                 /* Total length of udp header and payload in bytes */
	int pl_len;                  /* Length of udp payload */
	int r_bytes = 0;             /* Bytes processed */

	udp_len = H_16(udp_h->len);

	/* Extract header fields */
	printf("%d %d %d %04X ", 
			H_16(udp_h->s_port),
			H_16(udp_h->d_port),
			udp_len,
			H_16(udp_h->check));
	
	r_bytes += UDP_T_SIZE;
	pl_len = udp_len - UDP_T_SIZE; /* Less the header from length to get payload length */
	len -= r_bytes;                /* Less the header from remaining length */
	
	return r_bytes;
}

/**
 * process_ipv4_options
 * 
 * Process the Options field found in the ipv4 header
 * 
 * @param buf point to the buffer containing option field data
 * @param len Length in bytes of buffer
 * @param opt_len Length in bytes of options field 
 * 
 * Reference for breakout https://www.rfc-editor.org/rfc/rfc791.html#section-2.2
 * 
 * @return number of bytes processed in option field
*/
static int process_ipv4_options(unsigned char* buf, int len, int opt_len) { 
	uint8_t opt_type = buf[0]; /* Holds option type octet */
	uint8_t r_bytes = 0;       /* Holds number of bytes processed from buffer */

	if (opt_len < 1 || len < 1) return 0; /* Check that we have at least the option type octet */
	
	// opt type can be broken into the following
	//    Field      | Bits
	// Copied Flag   | 1 
	// Option Class  | 2 
	// Option Number | 5
	uint8_t c_flag    = opt_type >> 7 & 0x01;
	uint8_t opt_class = opt_type >> 5 & 0x03; 
	uint8_t opt_num   = opt_type      & 0x1f; 
	
	/* Break out of option flag, looks kinda weird being before the opt type print */
	printf("%X %X %d ",
			c_flag,
			opt_class,
			opt_num);  

	/* Need a switch on option type byte (First byte of option field) */
	switch(opt_type) { 
		case OPT_EOOL:
			printf("OPT_EOOL ");
			for(int i = 0; i < opt_len; i++) { 
				printf("%02X ", buf[i]);
			}
			return opt_len;
			break;
		case OPT_NOP:
			printf("OPT_NOP ");
			break;
		case OPT_RR:
			printf("OPT_RR ");
			// NOTE!!! This function has NOT been tested yet as I have no pcap sample to test it on
			// +--------+--------+--------+---------//--------+
        	// |00000111| length | pointer|     route data    |
        	// +--------+--------+--------+---------//--------+
			//     8        8         8         
			// Pointer; Min == 4
			// If pointer > length -> Recorded data area is full (Not sure if this matter)
			// NOTE: Apparently when parsing this, we should also be able to parse out the ip
			// addresses it is recording. 
			// bytesof 
			if (opt_len < OPTRR_T_SIZE) return 0; /* Prevent further processing if we are missing option data */

			optrr_t* rr = (optrr_t*)buf;

			printf("%d %d %02X ",
						rr->type,
						rr->len,
						rr->p);

			/* TODO Just dumping the rest of the options but I believe this is support print addresses */
			for (int i = sizeof(optrr_t); i < opt_len; i++)
				printf("%02X ", buf[i]);
			
			r_bytes += opt_len;
			break;
		case OPT_ZSU:
			printf("OPT_ZSU ");
			break;
		case OPT_MTUP:
			printf("OPT_MTUP ");
			break;
		case OPT_MTUR:
			printf("OPT_MTUR ");
			break;
		case OPT_ENCODE:
			printf("OPT_ENCODE ");
			break;
		case OPT_QS:
			printf("OPT_QS ");
			break;
		case OPT_TS:
			printf("OPT_TS ");
			break;
		case OPT_TR:
			printf("OPT_TR ");
			break;
		case OPT_SEC:
			printf("OPT_SEC ");
			break;
		case OPT_LSR:
			printf("OPT_LSR ");
			break;
		case OPT_ESEC:
			printf("OPT_ESEC ");
			break;
		case OPT_CIPSO:
			printf("OPT_CIPSO ");
			break;
		case OPT_SID:
			printf("OPT_SID ");
			break;
		case OPT_SSR:
			printf("OPT_SSR ");
			break;
		case OPT_VISA:
			printf("OPT_VISA ");
			break;
		case OPT_IMITD:
			printf("OPT_IMITD ");
			break;
		case OPT_EIP:
			printf("OPT_EIP ");
			break;
		case OPT_ADDEXT:
			printf("OPT_ADDEXT ");
			break;
		case OPT_RTRALT:
			printf("OPT_RTRALT ");
			/* Reference https://www.rfc-editor.org/rfc/rfc2113.html */
			// +--------+--------+--------+--------+
            // |10010100|00000100|  2 octet value  |
            // +--------+--------+--------+--------+
			/* If we don't have enough bytes for option, return and prevent further processing */
			if (opt_len < 4) return 0; 

			optl_t* rtalt = (optl_t*)buf; /* Overlay option header on buffer */
			
			/* Print the type and length */
			printf("%02X %d ", 
					rtalt->type, 
					rtalt->len);
			
			/* Process the option data octets */
			for(int i = sizeof(optl_t); i < rtalt->len; i++) { 
				printf("%02X ", buf[i]);
			}

			r_bytes += rtalt->len;
			break;
		case OPT_SDB:
			printf("OPT_SDB ");
			break;
		case OPT_NOT_ASS:
			printf("OPT_NOT_ASS ");
			break;
		case OPT_DPS:
			printf("OPT_DPS ");
			break;
		case OPT_UMP:
			printf("OPT_UMP ");
			break;
		case OPT_FINN:
			printf("OPT_FINN ");
			break;
		case OPT_EXP1: /* Experiment values that mean nothing */
		case OPT_EXP2:
		case OPT_EXP3:
		case OPT_EXP4:
			printf("OPT_EXP ");
			break;
		default:
			printf("OPT_UNKNOWN ");
				for(int i = 0; i < opt_len; i++) { 
					printf("%02X ", buf[i]);
				}
			return opt_len; /* Dump the rest of the options if we encounter a snag */
	}

	/* Decrement by our bytes processed */
	opt_len -= r_bytes;
	len -= r_bytes;
	
	// Disabled until I get test with more samples
	/* Recursively check for more options */ 
	//if (opt_len > 0) { 
	//	/* Passing reference to buf where we left off reading options */
	//	process_ipv4_options(&buf[r_bytes], len, opt_len); 
	//	exit(1);
	//}
	printf(" { %d } ", len);
	return r_bytes;
}

/** 
 * process_ipv4
 * 
 * Will take a ptr to where the ipv4 header begins and print out the corresponding fields
 * 
 * @param buf Pointer to where ipv4 header begins 
 * @param len Length in bytes of in buffer that are yet to be parsed 
 * 
 * @return Returns 1 if successful, 0 otherwise
 */
static int process_ipv4(unsigned char *buf, int len) { 
	int r_bytes = 0; /* Counts bytes processed from ipv4 down */
	
	if (len < IPV4_HEADER_MIN) return 0; /* Check buffer length */

	ipv4_t *n_layer = (ipv4_t *)buf;
	printf("IPV4 ");
	
	/* Extract bit fields */
	uint8_t vers   =  n_layer->vh >> 4;    		   /* Version */
	uint8_t h_len  = (n_layer->vh & 0xf)*4;        /* IHL / Internet Header length (Network word to bytes)*/
	uint8_t dscp   = (n_layer->dscp >> 2) & 0x3f;  /* DSCP */
	uint8_t ecn    = (n_layer->dscp) & 0x3;  	   /* ECN */
	uint8_t flags  = (n_layer->flags >> 12) & 0x7; /* Flags */
	uint8_t offset = (n_layer->flags) & 0x1fff;    /* Fragment offset */

	/* Check we have minimum / maximum header length */
	if (h_len < IPV4_HEADER_MIN) return 0;
	
	/* Ensure we have the correct version */
	if (vers != 4) return 0;  				
	
	/* Extracting ip into human readable format */
	char s_addr[INET_ADDRSTRLEN];
	char d_addr[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, n_layer->src_ip, s_addr, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, n_layer->dest_ip, d_addr, INET_ADDRSTRLEN); 

	int t_len = H_16(n_layer->length); /* total length of ipv4 header and data */
	
	printf("%X %d %d %X %4d %04X %02X %02X %3d %02X %04X %15s %15s ", 
			vers,
			h_len,  
			dscp,
			ecn, 
			t_len,
			H_16(n_layer->id),
			flags,
			offset,
			n_layer->ttl,
			n_layer->proto, 
			H_16(n_layer->checksum),
			s_addr,
			d_addr); /* See ipv4_t structure */

	r_bytes += IPV4_HEADER_MIN;
	len -= r_bytes;

	/* if header is more than 20 bytes (5 words), process the options */
	if (h_len > IPV4_HEADER_MIN) {
		r_bytes += process_ipv4_options(&buf[IPV4_HEADER_MIN], len, h_len - IPV4_HEADER_MIN);
	}

	/* Check that our total packet length corresponds to what our ipv4 header says remains */
	if (len > t_len)
		len = t_len; // Correct for accuracy on weird packets (Just a weird issue, may be a problem when publishing to zmq) 

	len -= r_bytes; /* Less ipv4 header after processing */
	if (len > 0)
		r_bytes += resolve_ip_proto(&buf[h_len], len, n_layer->proto);
	return r_bytes;
}

/** 
 * process_ipv6
 * 
 * Will take a ptr to where the ipv6 header begins and print out the corresponding fields
 * 
 * @param buf Pointer to where ipv6 header begins 
 * @param len Length of buffer 
 * 
 * @return Number of bytes processed 
 * 
*/
static int process_ipv6(unsigned char *buf, int len) { 
	printf("IPV6 ");
	ipv6_t *n_layer = (ipv6_t *)buf; /* Overlay structure on buffer */
	int r_bytes = 0; /* Number of bytes processed */

	/* Get Ipv6 addresses */
	char s_addr[INET6_ADDRSTRLEN];
	char d_addr[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, n_layer->src_ip, s_addr, INET6_ADDRSTRLEN); 
	inet_ntop(AF_INET6, n_layer->dest_ip, d_addr, INET6_ADDRSTRLEN); 

	/* Extract bit fields */
	uint8_t  vers = (H_32(n_layer->vers) >> 28) & 0xf;  /* Version */
	uint8_t  trcl = (H_32(n_layer->vers) >> 20) & 0xff; /* Traffic class */
	uint32_t flow =  H_32(n_layer->vers) & 0xfffff;     /* Flow label */

	/* Confirm version is correct */
	if (vers != 6) return 0; 

	printf("%d %02X %05X %d %d %d %s %s ", 
			vers,                  /* Version */ 
			trcl, 				   /* traffic class */
			flow, 				   /* flow label */
			H_16(n_layer->length), /* Payload length */
			n_layer->proto,        /* Next header */
			n_layer->limit,        /* hop limit  */
			s_addr, d_addr);       /* Source and destination ipv6 addresses */
	
	r_bytes += IPV6_T_SIZE; /* Add processed header bytes */

	/* Process next header */
	r_bytes += resolve_ip_proto(&buf[r_bytes], len, n_layer->proto);

	return r_bytes;
}

/**
 * process_arp
 * 
 * Process address resolution protocol 
 * 
 * @param buf Pointer to buffer beginning with arp protocol to be decoded
 * @param len Length of buffer
 * 
 * @return Number of bytes processed
*/
static int process_arp(unsigned char*buf, int len) { 
	printf("ARP ");
	arp_t* arp = (arp_t*)buf;
	int r_bytes = 0;

	if(len < ARP_T_SIZE) return 0; /* Do we have enough bytes to process header */

	/* Extract IP addresses */
	// TODO this may be a if else for Ipv4 vs Ipv6 determined 
	char s_addr[INET_ADDRSTRLEN];
	char d_addr[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, arp->src_ipv4, s_addr, INET_ADDRSTRLEN); 
	inet_ntop(AF_INET, arp->dst_ipv4, d_addr, INET_ADDRSTRLEN);

	printf("%04X %d %d %d %d ",
			H_16(arp->h_type),
			H_16(arp->p_type),
			arp->h_len,
			arp->p_len,
			H_16(arp->oper));

	/* Printing Sending and receiving MAC addresses and IP's */
	print_mac(arp->src_mac);
	printf("%s ", s_addr);

	print_mac(arp->dst_mac);
	printf("%s ", d_addr);

	r_bytes += ARP_T_SIZE;
	return r_bytes;
}


/** 
 * get_next_word
 * 
 * Given a buffer, will return the host 32 unsigned integer at the beginning of it 
 * 
 * @param buf
 * 
 * @return first unsigned 32 bit integer value from buffer
*/
static uint32_t get_next_word(unsigned char* buf) {
	return H_32((uint32_t)buf[0] << 24 | buf[1] << 16 | buf[2] << 8 | buf[3]);
}

/**
 * process_rth_flags
 * 
 * Processes flags present in the Radio tap header
 * 
 * @param bit_flags Structure containing each of the present fields
 * @param flags Integer containing flag bits to be stored in bit_flags
 */
static void process_rth_flags(unsigned char* buf, int len, uint32_t flags) {
	rth_flags_t temp = {0}; /* Initialize temporary struct to hold data */
	int r_bytes = 0; /* holds bytes processed from flags */

	if (RTH_FLAG_WORD > len) return 0; /* Check that we have enough bytes to read flags */	

	printf("%08X ", flags);

	/* Process bytes */
	r_bytes += sizeof(flags);
	len -= sizeof(flags);

	/* Bit shift flags into their respect locations */	
	temp.tsft             = GET_BIT(flags, 0);  /* Bit 0 */       
	temp.flags            = GET_BIT(flags, 1);  /* Bit 1 */      
	temp.rate             = GET_BIT(flags, 2);  /* Bit 2 */       
	temp.channel          = GET_BIT(flags, 3);  /* Bit 3 */         
	temp.fhss             = GET_BIT(flags, 4);  /* Bit 4 */
	temp.dbm_ant_sig      = GET_BIT(flags, 5);  /* Bit 5 */
	temp.dbm_ant_ns       = GET_BIT(flags, 6);  /* Bit 6 */
	temp.lock_q 		  = GET_BIT(flags, 7);  /* Bit 7 */
	temp.tx_ant			  = GET_BIT(flags, 8);  /* Bit 8 */
	temp.db_tx_ant        = GET_BIT(flags, 9);  /* Bit 9 */
	temp.db_m_tx_pow      = GET_BIT(flags, 10); /* Bit 10 */
	temp.ant              = GET_BIT(flags, 11); /* Bit 11 */
	temp.db_antsignal     = GET_BIT(flags, 12); /* Bit 12 */
	temp.db_antnoise      = GET_BIT(flags, 13); /* Bit 13 */
	temp.rx_flags         = GET_BIT(flags, 14); /* Bit 14 */
	temp.tx_flags         = GET_BIT(flags, 15); /* Bit 15 */
	//// Bit 16 skipped
	temp.data_retries     = GET_BIT(flags, 17); /* Bit 17 */
	temp.present_xchannel = GET_BIT(flags, 18); /* Bit 18 */
	temp.mcs              = GET_BIT(flags, 19); /* Bit 19 */
	temp.ampdu            = GET_BIT(flags, 20); /* Bit 20 */
	temp.vht              = GET_BIT(flags, 21); /* Bit 21 */
	temp.frame_ts  		  = GET_BIT(flags, 22); /* Bit 22 */
	temp.heinfo			  = GET_BIT(flags, 23); /* Bit 23 */
	temp.hemuinfo         = GET_BIT(flags, 24); /* Bit 24 */
	/// Bit 25 skipped
	temp.psdu			  = GET_BIT(flags, 26); /* Bit 26 */
	temp.l_sig 			  = GET_BIT(flags, 27); /* Bit 27 */
	temp.tlvs             = GET_BIT(flags, 28); /* Bit 28 */
	temp.rt_ns            = GET_BIT(flags, 29); /* Bit 29 */
	temp.ven_ns           = GET_BIT(flags, 30); /* Bit 30 */
	temp.ext              = GET_BIT(flags, 31); /* Bit 31 */ 

	/* Check if there is another ext header */
	if (temp.ext) {
		uint32_t next_flag = get_next_word(&buf[r_bytes]);	
		process_rth_flags(&buf[r_bytes], len, next_flag);	
	}
}

/** 
 * process_rth
 * 
 * Process IEEE 802.11 Radiotap header
 * 
 * @param buf Pointer to buffer that contains radio tap header and data
 * 
 * TODO: Currently only parses up to the header; The it_present field defines the
 * 		 fields that are present and can be parsed accordingly
*/
static int process_rth(unsigned char* buf, int len) { 
	rth_t* rth = (rth_t*)buf; /* Overlay buffer with radio tap struct */
	int r_bytes = 0;

	/* Check we have enough bytes to process the header */
	if (RTH_SIZE > len) return 0;
	
	/* Extract and print fields */
	printf(" %02X %d ",
			rth->it_version,
			rth->it_len);

	r_bytes += RTH_SIZE; /* Process header bytes */

	/* Check that we have enough bytes in our buffer to process the rest of the header */
	if (rth->it_len > len) return r_bytes;
	
	/* Process flags present field */
	/* Get the first fields present word */
	uint32_t fields_present = get_next_word(&buf[RTH_SIZE]);
	process_rth_flags(&buf[RTH_SIZE], rth->it_len - RTH_SIZE, fields_present); /* Passing buffer at point where another extension header where exist pass the first (Not well worded) */

	r_bytes += rth->it_len - RTH_SIZE;

	/* TODO Process the 802.11 header that follows */
	return r_bytes;
}

/**
 * process_ppp
  
 * Processes Point to Point protocol header and data
 * 
 * @param buf Pointer to buffer containing PPP header and information
*/
static void process_ppp(unsigned char*buf, int len) {
	printf("PPP ");
}

/**
 * process_ppp_hdlc
 * 
 * Processes Point to Point protocol header and data in HDLC-like framing
 * 
 * @param buf Pointer to buffer containing PPP header and information in HDLC-like framing
*/
static void process_ppp_hdlc(unsigned char*buf, int len) {
	printf("PPP-HDLC ");
	ppp_hdlc_t *ppp = (ppp_hdlc_t*)buf;
	uint16_t proto = H_16(ppp->proto);

	printf("%02X %02X %04X ", 
			ppp->addr, 
			ppp->ctrl,
			proto);

	/* Switch on proto for network layer decapsulating */
	switch(proto) { 
		case PPP_IPV4: 
			len -= process_ipv4(&buf[PPP_HDLC_SIZE], len);
			break;

		case PPP_IPV6: 
			len -= process_ipv6(&buf[PPP_HDLC_SIZE], len);
			break;
		
		case PPP_MPLS_UNICAST: 
			printf("PPP_MPLS_UNICAST ");
			break;
	} 
}

/**
 * print_mac
 * 
 * Will print mac address of a pointer to a byte array containing address
 * 
 * @param mac pointer to 6 byte array containing mac address
*/
static void print_mac(uint8_t *mac) {
	for(int i = 0; i < MAC_SIZE; i++) {
		printf("%02X", mac[i]);
		if (i != MAC_SIZE - 1) putc(':', stdout);
	}
	putc(' ', stdout);
}

static int process_eigrp_param(unsigned char* buf, int len) { 
	eigrp_param_t* param = (eigrp_param_t*)buf; /* Overlay where parameter would begin */
	int r_bytes = 0;

	if (len < EIGRP_PARAM_SIZE) return 0;

	/* Print type and length fields */
	int p_len = H_16(param->len);
	
	/* Check if param type is valid */
	switch(H_16(param->type)) { 
		case TLV_PARAMETER_TYPE: 
			printf("TLV_PARAMETER_TYPE ");
			break;
		case TLV_AUTHENTICATION_TYPE: 
			printf("TLV_AUTHENTICATION_TYPE ");
			break;
		case TLV_SEQUENCE_TYPE: 
			printf("TLV_SEQUENCE_TYPE ");
			break;
		case TLV_SOFTWARE_VERSION_TYPE: 
			printf("TLV_SOFTWARE_VERSION_TYPE ");
			break;
		case TLV_MULTICAST_SEQUENCE_TYPE: 
			printf("TLV_MULTICAST_SEQUENCE_TYPE ");
			break;
		case TLV_PEER_INFORMATION_TYPE: 
			printf("TLV_PEER_INFORMATION_TYPE ");
			break;
		case TLV_PEER_TERMINATION_TYPE: 
			printf("TLV_PEER_TERMINATION_TYPE ");
			break;
		case TLV_PEER_TID_LIST_TYPE: 
			printf("TLV_PEER_TID_LIST_TYPE ");
			break;
		case TLV_INTERNAL_TYPE:
			printf("TLV_INTERNAL_TYPE ");
			break;
		case TLV_EXTERNAL_TYPE:
			printf("TLV_EXTERNAL_TYPE ");
			break;
		case TLV_COMMUNITY_TYPE:
			printf("TLV_COMMUNITY_TYPE ");
			break;
		default:
			return r_bytes;
	}

	r_bytes += EIGRP_PARAM_SIZE;
	r_bytes += p_len - r_bytes; /* Fake processing data (TODO) */
	
	len -= r_bytes;
	r_bytes += process_eigrp_param(&buf[r_bytes], len);

	return r_bytes;

}

/** 
 * resolve_ip_proto
 * 
 * Resolves IP protocol being used 
 * 
 * @param buf Pointer to buffer containing protocol information
 * @param len Length of buffer
 * @param proto Protocol number to be resolved
 * 
 * @return Numbers of bytes processed
*/
static int resolve_ip_proto(unsigned char* buf, int len, int proto) { 
	int r_bytes = 0;

	if (len < 1) return 0;

	/* Welcome to the 9...errr innumberable circles of Hell! */
	/* For Reference https://datatracker.ietf.org/doc/html/rfc8200 */
	switch(proto) { 
		/* Transport Link Layer cases */
		case IP_HOPOPT:
			printf("IP_HOPOPT ");
			break;
		case IP_ICMP:
			printf("IP_ICMP ");
			break;
		case IP_IGMP:
			printf("IP_IGMP ");
			break;
		case IP_GGP:
			printf("IP_GGP ");
			break;
		case IP_IPV4:
			printf("IP_IPV4 ");
			r_bytes += process_ipv4(buf, len);
			break;
		case IP_ST:
			printf("IP_ST ");
			break;
		case IP_TCP:
			printf("IP_TCP ");
			r_bytes += process_tcp(buf, len);
			break;
		case IP_CBT:
			printf("IP_CBT ");
			break;
		case IP_EGP:
			printf("IP_EGP ");
			break;
		case IP_IGP:
			printf("IP_IGP ");
			break;
		case IP_BBN_RCC_MON:
			printf("IP_BBN_RCC_MON ");
			break;
		case IP_NVP_II:
			printf("IP_NVP_II ");
			break;
		case IP_PUP:
			printf("IP_PUP ");
			break;
		case IP_ARGUS:
			printf("IP_ARGUS ");
			break;
		case IP_EMCON:
			printf("IP_EMCON ");
			break;
		case IP_XNET:
			printf("IP_XNET ");
			break;
		case IP_CHAOS:
			printf("IP_CHAOS ");
			break;
		case IP_UDP:
			printf("IP_UDP ");
			r_bytes += process_udp(buf, len);
			break;
		case IP_MUX:
			printf("IP_MUX ");
			break;
		case IP_DCN_MEAS:
			printf("IP_DCN_MEAS ");
			break;
		case IP_HMP:
			printf("IP_HMP ");
			break;
		case IP_PRM:
			printf("IP_PRM ");
			break;
		case IP_XNS_IDP:
			printf("IP_XNS_IDP ");
			break;
		case IP_TRUNK_1:
			printf("IP_TRUNK_1 ");
			break;
		case IP_TRUNK_2:
			printf("IP_TRUNK_2 ");
			break;
		case IP_LEAF_1:
			printf("IP_LEAF_1 ");
			break;
		case IP_LEAF_2:
			printf("IP_LEAF_2 ");
			break;
		case IP_RDP:
			printf("IP_RDP ");
			break;
		case IP_IRTP:
			printf("IP_IRTP ");
			break;
		case IP_ISO_TP4:
			printf("IP_ISO_TP4 ");
			break;
		case IP_NETBLT:
			printf("IP_NETBLT ");
			break;
		case IP_MFE_NSP:
			printf("IP_MFE_NSP ");
			break;
		case IP_MERIT_INP:
			printf("IP_MERIT_INP ");
			break;
		case IP_DCCP:
			printf("IP_DCCP ");
			break;
		case IP_T3PC:
			printf("IP_T3PC ");
			break;
		case IP_IDPR:
			printf("IP_IDPR ");
			break;
		case IP_XTP:
			printf("IP_XTP ");
			break;
		case IP_DDP:
			printf("IP_DDP ");
			break;
		case IP_IDPR_CMTP:
			printf("IP_IDPR_CMTP ");
			break;
		case IP_TP:
			printf("IP_TP ");
			break;
		case IP_IL:
			printf("IP_IL ");
			break;
		case IP_IPV6:
			printf("IP_IPV6 ");
			r_bytes += process_ipv6(buf, len);
			break;
		case IP_SDRP:
			printf("IP_SDRP ");
			break;
		case IP_IPV6_Route:
			printf("IP_IPV6_Route ");
			ipv6_rh_t* rh = (ipv6_rh_t*)buf;
			
			if (len < RH_SIZE) return 0; /* Check if we have bytes to process */
			
			uint8_t h_len = (rh->len+1)*8; /* Calculate funky header length */

			printf("%d %d ", rh->proto, h_len);

			r_bytes += RH_SIZE; /* Add the header to bytes processed */
			len -= r_bytes;

			/* Attempt to process protocol */
			r_bytes += resolve_ip_proto(&buf[h_len], len, rh->proto);
			break;
		case IP_IPV6_Frag:
			printf("IP_IPV6_Frag ");
			break;
		case IP_IDRP:
			printf("IP_IDRP ");
			break;
		case IP_RSVP:
			printf("IP_RSVP ");
			break;
		case IP_GRE:
			printf("IP_GRE ");
			break;
		case IP_DSR:
			printf("IP_DSR ");
			break;
		case IP_BNA:
			printf("IP_BNA ");
			break;
		case IP_ESP:
			printf("IP_ESP ");
			break;
		case IP_AH:
			printf("IP_AH ");
			break;
		case IP_I_NLSP:
			printf("IP_I_NLSP ");
			break;
		case IP_SWIPE:
			printf("IP_SWIPE ");
			break;
		case IP_NARP:
			printf("IP_NARP ");
			break;
		case IP_MOBILE:
			printf("IP_MOBILE ");
			break;
		case IP_TLSP:
			printf("IP_TLSP ");
			break;
		case IP_SKIP:
			printf("IP_SKIP ");
			break;
		case IP_IPV6_ICMP:
			printf("IP_IPV6_ICMP ");
			break;
		case IP_IPV6_NoNxt:
			printf("IP_IPV6_NoNxt ");
			break;
		case IP_IPV6_Opts:
			printf("IP_IPV6_Opts ");
			break;
		case IP_HOST_INTERNAL:
			printf("IP_HOST_INTERNAL ");
			break;
		case IP_CFTP:
			printf("IP_CFTP ");
			break;
		case IP_LOCAL_NET:
			printf("IP_LOCAL_NET ");
			break;
		case IP_SAT_EXPAK:
			printf("IP_SAT_EXPAK ");
			break;
		case IP_KRYPTOLAN:
			printf("IP_KRYPTOLAN ");
			break;
		case IP_RVD:
			printf("IP_RVD ");
			break;
		case IP_IPPC:
			printf("IP_IPPC ");
			break;
		case IP_DIST_FILE_SYS:
			printf("IP_DIST_FILE_SYS ");
			break;
		case IP_SAT_MON:
			printf("IP_SAT_MON ");
			break;
		case IP_VISA:
			printf("IP_VISA ");
			break;
		case IP_IPCV:
			printf("IP_IPCV ");
			break;
		case IP_CPNX:
			printf("IP_CPNX ");
			break;
		case IP_CPHB:
			printf("IP_CPHB ");
			break;
		case IP_WSN:
			printf("IP_WSN ");
			break;
		case IP_PVP:
			printf("IP_PVP ");
			break;
		case IP_BR_SAT_MON:
			printf("IP_BR_SAT_MON ");
			break;
		case IP_SUN_ND:
			printf("IP_SUN_ND ");
			break;
		case IP_WB_MON:
			printf("IP_WB_MON ");
			break;
		case IP_WB_EXPAK:
			printf("IP_WB_EXPAK ");
			break;
		case IP_ISO_IP:
			printf("IP_ISO_IP ");
			break;
		case IP_VMTP:
			printf("IP_VMTP ");
			break;
		case IP_SECURE_VMTP:
			printf("IP_SECURE_VMTP ");
			break;
		case IP_VINES:
			printf("IP_VINES ");
			break;
		case IP_IPTM:
			printf("IP_IPTM ");
			break;
		case IP_NSFNET_IGP:
			printf("IP_NSFNET_IGP ");
			break;
		case IP_DGP:
			printf("IP_DGP ");
			break;
		case IP_TCF:
			printf("IP_TCF ");
			break;
		case IP_EIGRP:
			printf("IP_EIGRP ");
			/* Reference https://datatracker.ietf.org/doc/html/rfc7868 */
			eigrp_h_t* eigrp_h = (eigrp_h_t*)buf; /* Overlay the buffer with header */
			
			if (len < EIGRP_H_SIZE) return 0; /* Check buffer length */

			/* Process the header */
			/** TODO Extract bit fields */

			/** Print all fields */
			printf("%d %d %02X %08X %2ld %2ld %04X %d ",
					eigrp_h->vers,
					eigrp_h->op,
					H_16(eigrp_h->cksum),
					H_32(eigrp_h->flags),
					H_32(eigrp_h->seq),
					H_32(eigrp_h->ack),
					H_16(eigrp_h->v_id),
					H_16(eigrp_h->asn));
			
			r_bytes += EIGRP_H_SIZE;

			/** Check for additional parameters */
			r_bytes += process_eigrp_param(&buf[r_bytes], len - r_bytes);
			break;
		case IP_OSPFIGP:
			printf("IP_OSPFIGP ");
			break;
		case IP_Sprite_RPC:
			printf("IP_Sprite_RPC ");
			break;
		case IP_LARP:
			printf("IP_LARP ");
			break;
		case IP_MTP:
			printf("IP_MTP ");
			break;
		case IP_AX25:
			printf("IP_AX25 ");
			break;
		case IP_IPIP:
			printf("IP_IPIP ");
			break;
		case IP_MICP:
			printf("IP_MICP ");
			break;
		case IP_SCC_SP:
			printf("IP_SCC_SP ");
			break;
		case IP_ETHERIP:
			printf("IP_ETHERIP ");
			break;
		case IP_ENCAP:
			printf("IP_ENCAP ");
			break;
		case IP_PRIV_ENC:
			printf("IP_PRIV_ENC ");
			break;
		case IP_GMTP:
			printf("IP_GMTP ");
			break;
		case IP_IFMP:
			printf("IP_IFMP ");
			break;
		case IP_PNNI:
			printf("IP_PNNI ");
			break;
		case IP_PIM:
			printf("IP_PIM ");
			break;
		case IP_ARIS:
			printf("IP_ARIS ");
			break;
		case IP_SCPS:
			printf("IP_SCPS ");
			break;
		case IP_QNX:
			printf("IP_QNX ");
			break;
		case IP_AN:
			printf("IP_AN ");
			break;
		case IP_IPComp:
			printf("IP_IPComp ");
			break;
		case IP_SNP:
			printf("IP_SNP ");
			break;
		case IP_Compaq_Peer:
			printf("IP_Compaq_Peer ");
			break;
		case IP_IPX_in_IP:
			printf("IP_IPX_in_IP ");
			break;
		case IP_VRRP:
			printf("IP_VRRP ");
			break;
		case IP_PGM:
			printf("IP_PGM ");
			break;
		case IP_ZERO_HOP:
			printf("IP_ZERO_HOP ");
			break;
		case IP_L2TP:
			printf("IP_L2TP ");
			break;
		case IP_DDX:
			printf("IP_DDX ");
			break;
		case IP_IATP:
			printf("IP_IATP ");
			break;
		case IP_STP:
			printf("IP_STP ");
			break;
		case IP_SRP:
			printf("IP_SRP ");
			break;
		case IP_UTI:
			printf("IP_UTI ");
			break;
		case IP_SMP:
			printf("IP_SMP ");
			break;
		case IP_SM:
			printf("IP_SM ");
			break;
		case IP_PTP:
			printf("IP_PTP ");
			break;
		case IP_ISIS_IPv4:
			printf("IP_ISIS_IPv4 ");
			break;
		case IP_FIRE:
			printf("IP_FIRE ");
			break;
		case IP_CRTP:
			printf("IP_CRTP ");
			break;
		case IP_CRUDP:
			printf("IP_CRUDP ");
			break;
		case IP_SSCOPMCE:
			printf("IP_SSCOPMCE ");
			break;
		case IP_IPLT:
			printf("IP_IPLT ");
			break;
		case IP_SPS:
			printf("IP_SPS ");
			break;
		case IP_PIPE:
			printf("IP_PIPE ");
			break;
		case IP_SCTP:
			printf("IP_SCTP ");
			break;
		case IP_FC:
			printf("IP_FC ");
			break;
		case IP_RSVP_E2E_IGNORE:
			printf("IP_RSVP_E2E_IGNORE ");
			break;
		case IP_MOB_HEADER:
			printf("IP_MOB_HEADER ");
			break;
		case IP_UDPLite:
			printf("IP_UDPLite ");
			break;
		case IP_MPLS_in_IP:
			printf("IP_MPLS_in_IP ");
			break;
		case IP_manet:
			printf("IP_manet ");
			break;
		case IP_HIP:
			printf("IP_HIP ");
			break;
		case IP_Shim6:
			printf("IP_Shim6 ");
			break;
		case IP_WESP:
			printf("IP_WESP ");
			break;
		case IP_ROHC:
			printf("IP_ROHC ");
			break;
		case IP_Ethernet:
			printf("IP_Ethernet ");
			break;
		case IP_AGGFRAG:
			printf("IP_AGGFRAG ");
			break;
		case IP_NSH:
			printf("IP_NSH ");
			break;
		default:
			printf(" UNKNOWN_PROTO [%d] ", proto);
	}
	
	return r_bytes;

}
/** 
 * resolve_proto
 * 
 * Will pass a buffer containing a protocol such as ipv4, v6, or arp and print out its contents 
 * 
 * @param buf Pointer to buffer containing protocol to be resolved 
 * @param len Length of buffer
 * @param proto Integer representing the protocol from the previous layer
 * 
 * @return Number of bytes read
*/
static int resolve_proto(unsigned char* buf, int len, int proto) { 
	int r_bytes = 0; /* Number of bytes processed */

	/* Switch and process corresponding network link layer */
	switch(proto) { 
		case IPV4:
			r_bytes += process_ipv4(buf, len);
			break;
		case IPV6: 
			r_bytes += process_ipv6(buf, len);
			break;
		case ARP:
			r_bytes += process_arp(buf, len);
			break;
	}
	return r_bytes;
}

static void dissect_packet(unsigned char *buf, int len)
{
	if (len <= 0) return 0; /* Catch an empty packet */
	printf(" %4d ", len);

	/* Switch g_linktype to parse data link layer */
    switch(g_linktype) {
		case DLT_LINUX_SLL:
			printf(" DLT_LINUX_SLL ");
			
			/* Process Linux SLL */
			lsll_t* sll = (lsll_t*) buf;
			uint16_t sw_proto = H_16(sll->proto);

			printf("%04X %04X %04X ", 
					H_16(sll->type),
					H_16(sll->arphrd_type),
					H_16(sll->len));
			print_mac(sll->src); 
			printf("%04X", sw_proto); /* Ugly way to print everything I want */

			len -= resolve_proto(&buf[LSLL_SIZE], len, sw_proto);
			break;
		
        case DLT_EN10MB: {  
			printf(" DLT_EN10MB ");

			eth_t* en10 = (eth_t*) buf;            /* Overlay eth2_t struct with buffer */
			uint16_t sw_proto = H_16(en10->proto); /* Byte swap on proto */
			
			/* Print source destination mac addresses + ethertype */
			print_mac(en10->dst);
			print_mac(en10->src);
			printf("%04X ", sw_proto);

			len -= sizeof(eth_t); /* Less the eth2 header */

			len -= resolve_proto(&buf[ETH2_SIZE], len, sw_proto);
        }
		break;

		case DLT_IPV4: { 
			printf(" DLT_IPV4 ");
			len -= process_ipv4(buf, len); /* Packet begins with a raw IPv4 header */
		}
		break;
		
		case DLT_IPV6: { 
			printf(" DLT_IPV6 ");
			len -= process_ipv6(buf, len); /* Packet begins with a raw IPv6 header */
		}
		break;

		case DLT_RAW: {
			printf(" DLT_RAW ");

			uint8_t vers = (buf[0] >> 4) & 0xf; /* Get the IP version */

			/* Switch on IP version to process, 0x4 is IPv4, 0x6 is IPv6*/
			switch(vers) { 
				case 4:
					len -= process_ipv4(buf, len);
					break;

				case 6:
					len -= process_ipv6(buf, len);
					break;
#ifdef DEBUG
				default:
					/* Unknown IP version, print for debugging purposes */
					printf("UNKNOWN VERS %X", vers);
#endif
			}
        }
		break;
		
        case DLT_IEEE802: {
            printf(" DLT_IEEE802 "); 
        }
		break;
        
		case DLT_SLIP: { 
			printf(" DLT_SLIP ");
        }
		break;
        
		case DLT_PPP: {
			printf(" DLT_PPP ");
			unsigned short hdlc_check = (unsigned short)buf[0] << 8 | buf[1];
			
			if (hdlc_check == HDLC_FRAMING)
				process_ppp_hdlc(buf, len);  /* Process with HDLC-like framing */
			else
				process_ppp(buf, len);       /* Otherwise process per normal PPP header */
        }
		break;
        
		case DLT_PPP_SERIAL: {
			printf(" DLT_SERIAL "); 
        }
		break;
        
		case DLT_PPP_ETHER: { 
			printf(" DLT_ETHER ");
        }
		break;
        
		case DLT_IEEE802_11: { 
			printf(" DLT_IEEE802_11 ");
        }
		break;
        
		case DLT_IEEE802_11_RADIO: { 
			printf(" DLT_IEEE802_11_RADIO ");
			len -= process_rth(buf, len);
        }
		break;
        
		case DLT_IEEE802_11_RADIO_AVS: { 
			printf(" DLT_IEEE802_11_RADIO_AVS ");
        }
		break;
        
		case DLT_PPP_PPPD: { 
			printf(" DLT_PPP_PPPD ");
        }
		break;
        
		case DLT_IEEE802_16_MAC_CPS: { 
			printf(" DLT_IEEE802_16_MAC_CPS ");
        }
		break;
        
		case DLT_IEEE802_15_4_LINUX: { 
			printf(" DLT_IEEE802_15_4_LINUX ");
        }
		break;
        
		case DLT_IEEE802_16_MAC_CPS_RADIO: { // Appears
			printf(" DLT_IEEE802_16_MAC_CPS_RADIO ");
        }
		break;
        
		case DLT_IEEE802_15_4_WITHFCS: { //Appears
        	printf(" DLT_IEEE802_15_4_WITHFCS ");
		}
		break;
        
		case DLT_PPP_WITH_DIR: { 
			printf(" DLT_PPP_WITH_DIR ");
		}
		break;
        
		case DLT_IEEE802_15_4_NONASK_PHY: { 
			printf(" DLT_IEEE802_15_4_NONASK_PHY ");
		}
		break;	
        
		case DLT_IEEE802_15_4_TAP: { 
			printf(" DLT_IEEE802_15_4_TAP ");
		}
		break;
		default:
			printf("UNCHARTED_ETHER %d ", g_linktype);
    }    
#ifdef DEBUG
	if (len != 0)
		printf("[%d]", len);
		if (len < 0)
			exit(-1);
#endif 
}

static void handle_message(zmq_mf_t *ts_msg, zmq_mf_t *pkt_msg)
{
	unsigned int sec;
	unsigned int frac;
	char *period;

	sec = 0;
	frac = 0;

	period = strchr(ts_msg->buf, '.');
	if(period) {
		sec  = atol(ts_msg->buf);
		frac = atol(period+1);
		if(g_magic == 0xA1B2C3D4) { frac /= 1000; }
	}

	//printf("%d.%d", sec, frac);
	printf("%10d", sec);
	dissect_packet(pkt_msg->buf, pkt_msg->size);
	printf("\n");

	count_packet(1, pkt_msg->size);
}


static void decode_link_layer(zmq_mf_t *fh_msg)
{
	char *token, *line_saveptr;

	token = strtok_r(fh_msg->buf, "/", &line_saveptr);
	if(!token) { g_zmqerr_count++; return; }
	g_magic = strtoul(token, NULL, 10);

	// Override the default and convert timestamps
	if(g_us_ts) { g_magic = 0xA1B2C3D4; }
	if(g_ns_ts) { g_magic = 0xA1B23C4D; }

	token = strtok_r(NULL, "/", &line_saveptr);
	if(!token) { g_zmqerr_count++; return; }
	g_linktype = strtoul(token, NULL, 10);

	token = strtok_r(NULL, "/", &line_saveptr);
	if(!token) { g_zmqerr_count++; return; }
	//thiszone = strtoul(token, NULL, 10);

	token = strtok_r(NULL, "/", &line_saveptr);
	if(!token) { g_zmqerr_count++; return; }
	//sigfigs = strtoul(token, NULL, 10);

	token = strtok_r(NULL, "/", &line_saveptr);
	if(!token) { g_zmqerr_count++; return; }
	//snaplen = strtoul(token, NULL, 10);

}

/*
	as_zmq_pub_send(g_pktpub, ac->dev, strlen(ac->dev)+1, 1);

    snprintf(zbuf, sizeof(zbuf), "%u/%d/%d/%u/%u", ac->magic, ac->linktype, 0, 0, 262144);
	as_zmq_pub_send(g_pktpub, zbuf, strlen(zbuf)+1, 1);

	snprintf(zbuf, sizeof(zbuf), "%ld.%09ld", ts->tv_sec, ts->tv_usec);
	as_zmq_pub_send(g_pktpub, zbuf, strlen(zbuf)+1, 1);

	as_zmq_pub_send(g_pktpub, buf, len, 0);
*/
void pkt_cb(zmq_sub_t *s, zmq_mf_t **mpa, int msgcnt, void *user_data)
{
	zmq_mf_t *dev_msg;
	zmq_mf_t *fh_msg;
	zmq_mf_t *ts_msg;
	zmq_mf_t *pkt_msg;

	if(!mpa) { g_zmqerr_count++; return; }
	if(msgcnt != 4) { g_zmqerr_count++; return; }

	dev_msg = mpa[0];
	fh_msg = mpa[1];
	ts_msg = mpa[2];
	pkt_msg = mpa[3];

	if(!dev_msg) { g_zmqerr_count++; return; }
	if(!fh_msg) { g_zmqerr_count++; return; }
	if(!ts_msg) { g_zmqerr_count++; return; }
	if(!pkt_msg) { g_zmqerr_count++; return; }

	decode_link_layer(fh_msg);
	handle_message(ts_msg, pkt_msg);
	g_zmqpkt_count++;
}

int init_output(char *filename)
{
	return 0;
}

void fini_output(void)
{

}
