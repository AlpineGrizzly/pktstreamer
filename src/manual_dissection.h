/* Definitions for dissecting packets from data layer up
 *
 * Author Dalton Kinney
 * Created Sept. 22nd, 2023
 */

#include <stdio.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>

/* Ethertype definitions */
#define IPV4 0x0800
#define IPV6 0x86DD
#define ARP  0x0806

/* Address sizes (bytes) */
#define MAC_SIZE 6
#define IP4_SIZE 4
#define IP6_SIZE 16

/******** Link layer */
/**
 * eth2_t
 *
 * Packed structure to hold Ethernet II Layer 1 information
 * https://www.tcpdump.org/linktypes.html
 */
typedef struct
{						   // Are the src and dst in the right order ?
	uint8_t dst[MAC_SIZE]; /* Source mac address      [6 bytes] */
	uint8_t src[MAC_SIZE]; /* Destination mac address [6 bytes] */
	uint16_t proto;		   /* Ether type              [2 bytes] */
} __attribute__((packed)) eth_t;
#define ETH2_SIZE sizeof(eth_t)

/**
 * lsll_t
 *
 * Linux SSL cooked header
 *
 * Packed structure for holding linktype Linux SLL header
 * Reference (https://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL.html)
 */
typedef struct
{
	uint16_t type;		   /* Contains information on the purpose and origin of the packet */
	uint16_t arphrd_type;  /* ARPHRD_ value for link-layer device type */
	uint16_t len;		   /* Length of the link layer address of the sender of the packet (Can be zero)*/
	uint8_t src[MAC_SIZE]; /* Link-layer address of the sender of the packet */
	uint16_t proto;		   /* Protocol type */
} __attribute__((packed)) lsll_t;
#define LSLL_SIZE sizeof(lsll_t)

/******** Network layer */
/**
 * ipv4_t
 *
 * Packed structure contains all elements of ipv4 header
 */
typedef struct
{
	uint8_t vh;				   // Version [0-3], Header length [4-7]
	uint8_t dscp;			   // Differentiated services field [8-13], ECN [14-15]
	uint16_t length;		   // Total length [16-31]
	uint16_t id;			   // Identification [32-47]
	uint16_t flags;			   // Flags [48-50], Fragment offset [51-63]
	uint8_t ttl;			   // TTL [64-71]
	uint8_t proto;			   // Protocol [72-79]
	uint16_t checksum;		   // Header checksum [80-95]
	uint8_t src_ip[IP4_SIZE];  // Source ip address [96-127]
	uint8_t dest_ip[IP4_SIZE]; // Destination ip address [128-159]
} __attribute__((packed)) ipv4_t;
#define IPV4_T_SIZE sizeof(ipv4_t)
/* Ipv4 Protocol Specific defines */
#define IPV4_HEADER_MIN 20 /* Min header size in bytes */
#define IPV4_HEADER_MAX 32 /* Max header size in bytes */

/**
 * optrr_t
 *
 * Record route option structure
 * Reference https://www.rfc-editor.org/rfc/rfc791.html [Pg 20]
 */
typedef struct
{
	uint8_t type; /* Option type field */
	uint8_t len;  /* Length of option */
	uint8_t p;	  /* Pointer value */
} __attribute__((packed)) optrr_t;
#define OPTRR_T_SIZE sizeof(optrr_t)

/**
 * optl_t
 *
 * Case 2 option format for Ipv4 option header.
 * Reference https://www.rfc-editor.org/rfc/rfc791.html#section-2.2 [Pg 15]
 *
 */
typedef struct
{
	uint8_t type; /* Option type */
	uint8_t len;  /* Option length in bytes */
} __attribute__((packed)) optl_t;

/** Defines for OPTION types in Ipv4 header */
// Thanks Will! ->  ^([0-9]{3}).*\n\n([^-]+)- (.*) -> #define $2 $1// $3
#define OPT_EOOL      0		// End of Options List
#define OPT_NOP       1		// No Operation
#define OPT_RR        7		// Record Route
#define OPT_ZSU      10		// Experimental Measurement
#define OPT_MTUP     11		// MTU Probe
#define OPT_MTUR     12		// MTU Reply
#define OPT_ENCODE   15	// ???
#define OPT_QS       25	// Quick-Start
#define OPT_EXP1     30	// RFC3692-style Experiment [2]
#define OPT_TS       68	// Time Stamp
#define OPT_TR       82	// Traceroute
#define OPT_EXP2     94	// RFC3692-style Experiment [2]
#define OPT_SEC     130	// Security
#define OPT_LSR     131	// Loose Source Route
#define OPT_ESEC    133	// Extended Security
#define OPT_CIPSO   134	// Commercial Security
#define OPT_SID     136	// Stream ID
#define OPT_SSR     137	// Strict Source Route
#define OPT_VISA    142	// Experimental Access Control
#define OPT_IMITD   144	// IMI Traffic Descriptor
#define OPT_EIP     145	// Extended Internet Protocol
#define OPT_ADDEXT  147	// Address Extension
#define OPT_RTRALT  148	// Router Alert
#define OPT_SDB     149	// Selective Directed Broadcast
#define OPT_NOT_ASS 150 // Unassigned (Released 18 October 2005)
#define OPT_DPS     151		// Dynamic Packet State
#define OPT_UMP     152		// Upstream Multicast Pkt.
#define OPT_EXP3    158	// RFC3692-style Experiment [2]
#define OPT_FINN    205	// Experimental Flow Control
#define OPT_EXP4    222	// RFC3692-style Experiment [2]

/* Ip  numbers (next layer protocol numbers) */
/* Reference https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml#Internet_Assigned_Numbers_Authority */
/* Lazy with the comments */
#define IP_HOPOPT            0
#define IP_ICMP              1
#define IP_IGMP              2
#define IP_GGP               3
#define IP_IPV4              4
#define IP_ST                5
#define IP_TCP               6
#define IP_CBT               7
#define IP_EGP               8
#define IP_IGP               9
#define IP_BBN_RCC_MON      10
#define IP_NVP_II           11
#define IP_PUP              12
#define IP_ARGUS            13
#define IP_EMCON            14
#define IP_XNET             15
#define IP_CHAOS            16
#define IP_UDP              17
#define IP_MUX              18
#define IP_DCN_MEAS         19
#define IP_HMP              20
#define IP_PRM              21
#define IP_XNS_IDP          22
#define IP_TRUNK_1          23
#define IP_TRUNK_2          24
#define IP_LEAF_1           25
#define IP_LEAF_2           26
#define IP_RDP              27
#define IP_IRTP             28
#define IP_ISO_TP4          29
#define IP_NETBLT           30
#define IP_MFE_NSP          31
#define IP_MERIT_INP        32
#define IP_DCCP             33
#define IP_T3PC             34
#define IP_IDPR             35
#define IP_XTP              36
#define IP_DDP              37
#define IP_IDPR_CMTP        38
#define IP_TP               39
#define IP_IL               40
#define IP_IPV6             41
#define IP_SDRP             42
#define IP_IPV6_Route       43
#define IP_IPV6_Frag        44
#define IP_IDRP             45
#define IP_RSVP             46
#define IP_GRE              47
#define IP_DSR              48
#define IP_BNA              49
#define IP_ESP              50
#define IP_AH               51
#define IP_I_NLSP           52
#define IP_SWIPE            53
#define IP_NARP             54
#define IP_MOBILE           55
#define IP_TLSP             56
#define IP_SKIP             57
#define IP_IPV6_ICMP        58
#define IP_IPV6_NoNxt       59
#define IP_IPV6_Opts        60
#define IP_HOST_INTERNAL    61
#define IP_CFTP             62
#define IP_LOCAL_NET        63
#define IP_SAT_EXPAK        64
#define IP_KRYPTOLAN        65
#define IP_RVD              66
#define IP_IPPC             67
#define IP_DIST_FILE_SYS    68
#define IP_SAT_MON          69
#define IP_VISA             70
#define IP_IPCV             71
#define IP_CPNX             72
#define IP_CPHB             73
#define IP_WSN              74
#define IP_PVP              75
#define IP_BR_SAT_MON       76
#define IP_SUN_ND           77
#define IP_WB_MON           78
#define IP_WB_EXPAK         79
#define IP_ISO_IP           80
#define IP_VMTP             81
#define IP_SECURE_VMTP      82
#define IP_VINES            83
#define IP_IPTM             84
#define IP_NSFNET_IGP       85
#define IP_DGP              86
#define IP_TCF              87
#define IP_EIGRP            88
#define IP_OSPFIGP          89
#define IP_Sprite_RPC       90
#define IP_LARP             91
#define IP_MTP              92
#define IP_AX25             93
#define IP_IPIP             94
#define IP_MICP             95
#define IP_SCC_SP           96
#define IP_ETHERIP          97
#define IP_ENCAP            98
#define IP_PRIV_ENC         99
#define IP_GMTP            100
#define IP_IFMP            101
#define IP_PNNI            102
#define IP_PIM             103
#define IP_ARIS            104
#define IP_SCPS            105
#define IP_QNX             106
#define IP_AN              107
#define IP_IPComp          108
#define IP_SNP             109
#define IP_Compaq_Peer     110
#define IP_IPX_in_IP       111
#define IP_VRRP            112
#define IP_PGM             113
#define IP_ZERO_HOP        114
#define IP_L2TP            115
#define IP_DDX             116
#define IP_IATP            117
#define IP_STP             118
#define IP_SRP             119
#define IP_UTI             120
#define IP_SMP             121
#define IP_SM              122
#define IP_PTP             123
#define IP_ISIS_IPv4       124
#define IP_FIRE            125
#define IP_CRTP            126
#define IP_CRUDP           127
#define IP_SSCOPMCE        128
#define IP_IPLT            129
#define IP_SPS             130
#define IP_PIPE            131
#define IP_SCTP            132
#define IP_FC              133
#define IP_RSVP_E2E_IGNORE 134
#define IP_MOB_HEADER      135
#define IP_UDPLite         136
#define IP_MPLS_in_IP      137
#define IP_manet           138
#define IP_HIP             139
#define IP_Shim6           140
#define IP_WESP            141
#define IP_ROHC            142
#define IP_Ethernet        143
#define IP_AGGFRAG         144
#define IP_NSH             145

/**
 * udp_t
 *
 * Structure for representing UDP transport header
 * Reference https://www.rfc-editor.org/rfc/rfc768.html
 */
typedef struct
{
	uint16_t s_port; // Source port
	uint16_t d_port; // Destination port
	uint16_t len;	 // Length of udp packet data
	uint16_t check;	 // Checksum
} __attribute__((packed)) udp_t;
#define UDP_T_SIZE sizeof(udp_t)

/**
 * tcp_t
 *
 * Structure for representing tcp header
 * Reference https://www.rfc-editor.org/rfc/rfc9293.html
 */
typedef struct
{
	uint16_t s_port;  // Source port number
	uint16_t d_port;  // Destination port number
	uint32_t seq;	  // Sequence number
	uint32_t ack;	  // Acknowledgement number
	uint16_t do_rs_c; // Data offset (4 bits), Reserved (4 bits), Control bits (8)
	uint16_t win;	  // Windows (See note on using 32 bit window sizes and see if it applies to this)
	uint16_t check;	  // Checksum
	uint16_t p;		  // Urgent pointer
} __attribute__((packed)) tcp_t;
#define TCP_T_SIZE sizeof(tcp_t) /* Size of standard tcp header */

typedef struct
{
	uint8_t kind; /* Option identifier */
	uint8_t len;  /* Length of option */
} __attribute__((packed)) tcp_opt_t;
#define TCP_OPT_SIZE sizeof(tcp_opt_t)

/* List of TCP options (Not full list) */
#define TCP_EOOL  0	// End of Option List
#define TCP_NOP   1	// No-Operation
#define TCP_MSS   2 // Len - 4	Maximum Segment Size
#define TCP_WS    3	// Len - 3	Window Scale
#define TCP_SP    4	// Len - 2	SACK Permitted
#define TCP_S     5	// SACK
#define TCP_ECHO  6	// Len - 6	Echo (obsoleted by option 8)
#define TCP_ECHOR 7 // Len - 6	Echo Reply (obsoleted by option 8)
#define TCP_TS    8	// Len - 10	Timestamps

/**
 * ipv6_t
 *
 * Packed structure contains all elements of ipv6 header
 */
typedef struct
{
	uint32_t vers;			    /* Version [0-3], Traffic class [4-11], Flow Label [12-31] */
	uint16_t length;		    /* Payload length */
	uint8_t  proto;			    /* Specifies the type of the next header */
	uint8_t  limit;			    /* Hop limit */
	uint8_t  src_ip[IP6_SIZE];  /* Source Ip address */
	uint8_t  dest_ip[IP6_SIZE]; /* Destination Ip address */
} __attribute__((packed)) ipv6_t;
#define IPV6_T_SIZE sizeof(ipv6_t)

/** 
 * ipv6_rh_t 
 * 
 * Structure representing Ipv6 Extension routing header
 * 
*/
typedef struct { 
	uint8_t proto; /* Represents next header type */
	uint8_t len;   /* Size of header in octets - 1 (i.e. value of 6 = 56 bytes) */
} __attribute__((packed)) ipv6_rh_t;
#define RH_SIZE sizeof(ipv6_rh_t)

/**
 * arp_t 
 * 
 * Structure for arp header on link layer
 * Reference https://en.wikipedia.org/wiki/Address_Resolution_Protocol
 * In wikipedia we trust
*/
typedef struct
{
	uint16_t h_type;             /* Hardware Type */
	uint16_t p_type;             /* Protocol Type */
	uint8_t  h_len;              /* Hardware address length */
	uint8_t  p_len;              /* Protocol address length */
	uint16_t oper;               /* Operation the sender is performing */
	uint8_t  src_mac[MAC_SIZE];  /* Sender hardware address */
	uint8_t  src_ipv4[IP4_SIZE]; /* Sender IP address */  
	uint8_t  dst_mac[MAC_SIZE];  /* Destination MAC address */
	uint8_t  dst_ipv4[IP4_SIZE]; /* Destination IP address */
} __attribute__((packed)) arp_t; 
#define ARP_T_SIZE sizeof(arp_t) /* 28 bytes */

/* ARP Operation codes https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml */
#define ARP_REQUEST 1
#define ARP_REPLY   2

/* ARP Hardware Types  https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml#arp-parameters-2 */
#define ARP_ETHERNET 1

/**
 * eigrp_h_t
 * 
 * Structure for EIGRP packet header
 * Reference https://datatracker.ietf.org/doc/html/rfc7868
*/
typedef struct { 
	uint8_t  vers;  /* Header version */
	uint8_t  op;    /* Opcode */
	uint16_t cksum; /* Checksum */
	uint32_t flags; /* INIT-FLAG (0x01) 
					   CR-FLAG   (0x02) 
					   RS-FLAG   (0x04) 
					   EOT-FLAG  (0x08) */
	uint32_t seq;   /* Sequence number */
	uint32_t ack;   /* Acknowledgement number */
	uint16_t v_id;  /* Virtual router ID */
	uint16_t asn;   /* Autonomous system number */
} __attribute__ ((packed)) eigrp_h_t;
#define EIGRP_H_SIZE sizeof(eigrp_h_t)

/**
 * eigrp_param_t
 * 
 * Structure for holding type and length field
 * associated with eigrp parameters following header
*/
typedef struct { 
	uint16_t type; /* High represents protocol classification, low defines the tlv opcode */
	uint16_t len;
} __attribute__ ((packed)) eigrp_param_t;
#define EIGRP_PARAM_SIZE sizeof(eigrp_param_t)

/* EIGRP header opcodes */
#define EIGRP_OPC_UPDATE    1
#define EIGRP_OPC_REQUEST   2
#define EIGRP_OPC_QUERY     3
#define EIGRP_OPC_REPLY     4
#define EIGRP_OPC_HELLO     5
#define EIGRP_OPC_IPXSAP    6
#define EIGRP_OPC_PROBE     7
#define EIGRP_OPC_ACK       8
#define EIGRP_RESERVED      9
#define EIGRP_OPC_SIAQUERY 10
#define EIGRP_OPC_SIAREPLY 11

/* Virtual Router Identifier (VRID) definitions */
#define Unicast Address Family   0x0000          
#define Multicast Address Family 0x0001        
//#define Reserved 0x0002-0x7FF
#define Unicast Service Family   0x8000          
//#define Reserved 0x8001-0xFFFF

/* TLV definitions for EIGRP */
#define TLV_PARAMETER_TYPE          0x0001
#define TLV_AUTHENTICATION_TYPE     0x0002
#define TLV_SEQUENCE_TYPE           0x0003
#define TLV_SOFTWARE_VERSION_TYPE   0x0004
#define TLV_MULTICAST_SEQUENCE_TYPE 0x0005
#define TLV_PEER_INFORMATION_TYPE   0x0006
#define TLV_PEER_TERMINATION_TYPE   0x0007
#define TLV_PEER_TID_LIST_TYPE      0x0008

/* IPv4-Specific TLVs */
#define TLV_INTERNAL_TYPE       	0x0102
#define TLV_EXTERNAL_TYPE       	0x0103
#define TLV_COMMUNITY_TYPE      	0x0104

/**
 * ieee80211_radiotap_header
 * (Reference http://www.radiotap.org/)
 *
 * Packed structure containing radio tap header for IEEE 802.11
 * 
 * Present Flags
 * Flags https://www.radiotap.org/fields/Flags.html
 *
 */
typedef struct
{
	uint8_t it_version;   /* set to 0 */
	uint8_t it_pad;
	uint16_t it_len;	  /* entire length */
} __attribute__((packed)) rth_t;
#define RTH_SIZE sizeof(rth_t)

/* Define for extracting a value from a bit position */
#define GET_BIT(flag, pos) flag >> pos & 0x1 

typedef struct { 
	uint8_t tsft;             /* Specifies if the Time synchronization Function time field is present */
	uint8_t flags;            /* Specifies if the channel flags field is present */
	uint8_t rate;             /* Specifies if the transmit/receive field is present */
	uint8_t channel;          /* Specifies if the transmit/receive freq field is present */
	uint8_t fhss;             /* Specifies if he hop set an pattern is present for frequency hopping radios */
	uint8_t dbm_ant_sig;      /* Specifies if the antenna signal strength in dBm is present */
	uint8_t dbm_ant_ns;       /* Specifies if the RF noise power at antenna field is present */
	uint8_t lock_q;           /* Specifies if the signal quality field is present */
	uint8_t tx_ant;           /* Specifies if the transmit power distance from max power field is present */
	uint8_t db_tx_ant;        /* Specifies if the power distance from max power (in dB) field is present */
	uint8_t db_m_tx_pow;      /* Specifies if the transmit power (in dBm) field is present */
	uint8_t ant;              /* Specifies if the antenna number field is present */
	uint8_t db_antsignal;     /* Specifies if the RF signal power at antenna in dB field is present */	
	uint8_t db_antnoise;      /* Specifies if the RF signal power at antenna in dBm field is present */
	uint8_t rx_flags;         /* Specifes if the RX flags field is present */
	uint8_t tx_flags;         /* Specifes if the TX flags field is present */
	uint8_t data_retries;     /* Specifies if the data retries field is present */
	uint8_t present_xchannel; /* Specifies if te extended channel info field is present */	
	uint8_t mcs;              /* ... mcs field is present */
	uint8_t ampdu;            /* ... A-MPDU status field is present */
	uint8_t vht;              /* .... */
	uint8_t frame_ts; 
	uint8_t heinfo;
	uint8_t hemuinfo;
	uint8_t psdu;             /* Specifies whether or not the 0-Length PSDU field is present */
	uint8_t l_sig;
	uint8_t tlvs; 
	uint8_t rt_ns;            /* Specifies a reset to the radiotap namespace */
	uint8_t ven_ns;           /* ... the next bitmap is in a vendor namespace */
	uint8_t ext;              /* Specifies if there are any extensions to the header present (Believe a boolean on this to recurse through present headers is the approach ) */
} __attribute__ ((packed)) rth_flags_t;
#define RTH_FLAG_WORD 4 

/**
 * ppp_t
 *
 * (Reference https://www.rfc-editor.org/rfc/rfc1661.html#section-3.1)
 *
 * Point to Point header structure
 */
typedef struct
{

} __attribute__((packed)) ppp_t;
#define PPP_SIZE sizeof(ppp_t)

/**
 * ppp_hdlc_t
 * (Reference https://www.rfc-editor.org/rfc/rfc1662.html)
 *
 * Point to Point header structure with HDLC-like framing
 */
typedef struct
{
	uint8_t addr;	/* All stations address, always contains 0xff */
	uint8_t ctrl;	/* Always contains 0x03 */
	uint16_t proto; /* PPP protocol used */
} __attribute__((packed)) ppp_hdlc_t;
#define PPP_HDLC_SIZE sizeof(ppp_hdlc_t)
#define HDLC_FRAMING 0xff03 /* If present in first two bytes, uses HDLC-like framing */

/* PPP IANA assigned numbers */
/* https://www.iana.org/assignments/ppp-numbers/ppp-numbers.xhtml */
#define PPP_IPV4 0x0021
#define PPP_IPV6 0x0057
#define PPP_MPLS_UNICAST 0x0281

/* Host byte order defines */
/* Used to translate network byte order to host byte order */
#define H_16(x) ntohs(x)
#define H_32(x) ntohl(x)