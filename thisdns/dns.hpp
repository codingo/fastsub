#pragma once

#ifdef _MSC_VER
#include <ws2tcpip.h>
#pragma warning(disable : 4996)
#endif

#include <string>
#include <cstring>
#include <map>
#include <inttypes.h>

#define elements(a) (sizeof(a) / sizeof((a)[0]))

#define DNSLIB_PKTHEADER_BITFIELD_QR 0xF
#define DNSLIB_PKTHEADER_BITFIELD_OPCODE 0x7800
#define DNSLIB_PKTHEADER_BITFIELD_AA 0xA
#define DNSLIB_PKTHEADER_BITFIELD_TC 0x9
#define DNSLIB_PKTHEADER_BITFIELD_RD 0x8
#define DNSLIB_PKTHEADER_BITFIELD_RA 0x7
#define DNSLIB_PKTHEADER_BITFIELD_RCODE 0x000F
#define DNSLIB_RCODE_NOERROR 0x0000
#define DNSLIB_RCODE_FMTERROR 0x0001
#define DNSLIB_RCODE_SRVFAIL 0x0002
#define DNSLIB_RCODE_NONAME 0x0003
#define DNSLIB_RCODE_REFUSED 0x0005
#define DNSLIB_ERRNO_RECVFAULT 1
#define DNSLIB_ERRNO_DSTPORTFAULT 2
#define DNSLIB_ERRNO_PKTSIZEFAULT 3
#define DNSLIB_ERRNO_REPLYNOTQR 4
#define DNSLIB_ERRNO_REPLYIDMISMATCH 5
#define DNSLIB_ERRNO_REPLYNOANSWERS 6
#define DNSLIB_ERRNO_REPLYRCODE 7
#define DNSLIB_ERRNO_ARPTIMEOUT 8
#define DNSLIB_ERRNO_BADNAME 9
#define DNSLIB_ERRNO_NOREPLY 10
#define DNSLIB_ERRNO_NOTARECORD 11
#define DNSLIB_ERRNO_NOTINETCLASS 12
#define DNSLIB_ERRNO_REPLYINVALIDSIZE 13
#define DNSLIB_ERRNO_PARSE_TRUNCATED 14
#define DNSLIB_ERRNO_SENDTOFAULT 15
#define DNSLIB_ERRNO_BINDFAULT 16
#define DNSLIB_ERRNO_MAX 16

namespace fastsub
{
	template<typename T, typename U>
	auto minimum( T const & t, U const& u )
	{
		return t < u ? t : u;
	}

	template<typename T, typename U>
	auto maximum( T const & t, U const& u )
	{
		return t < u ? u : t;
	}

	enum class dns_record_type : std::uint16_t
	{
		DNS_REC_INVALID = 0xFFFF, // Error code
		DNS_REC_UNDEFINED = 0,
		DNS_REC_A = 1,
		DNS_REC_AAAA = 28,
		DNS_REC_AFSDB = 18,
		DNS_REC_ANY = 255,
		DNS_REC_APL = 42,
		DNS_REC_CAA = 257,
		DNS_REC_CDNSKEY = 60,
		DNS_REC_CDS = 59,
		DNS_REC_CERT = 37,
		DNS_REC_CNAME = 5,
		DNS_REC_DHCID = 49,
		DNS_REC_DLV = 32769,
		DNS_REC_DNAME = 39,
		DNS_REC_DNSKEY = 48,
		DNS_REC_DS = 43,
		DNS_REC_HIP = 55,
		DNS_REC_IPSECKEY = 45,
		DNS_REC_KEY = 25,
		DNS_REC_KX = 36,
		DNS_REC_LOC = 29,
		DNS_REC_MX = 15,
		DNS_REC_NAPTR = 35,
		DNS_REC_NS = 2,
		DNS_REC_NSEC = 47,
		DNS_REC_NSEC3 = 50,
		DNS_REC_NSEC3PARAM = 51,
		DNS_REC_OPENPGPKEY = 61,
		DNS_REC_PTR = 12,
		DNS_REC_RP = 17,
		DNS_REC_RRSIG = 46,
		DNS_REC_SIG = 24,
		DNS_REC_SOA = 6,
		DNS_REC_SRV = 33,
		DNS_REC_SSHFP = 44,
		DNS_REC_TA = 32768,
		DNS_REC_TKEY = 249,
		DNS_REC_TLSA = 52,
		DNS_REC_TSIG = 250,
		DNS_REC_TXT = 16,
		DNS_REC_URI = 256
	};

	enum class dns_section
	{
		DNS_SECTION_QUESTION = 0,
		DNS_SECTION_ANSWER = 1,
		DNS_SECTION_AUTHORITY = 2,
		DNS_SECTION_ADDITIONAL = 3
	};

	enum class dns_rcode
	{
		DNS_RCODE_OK = 0,
		DNS_RCODE_FORMERR = 1,
		DNS_RCODE_SERVFAIL = 2,
		DNS_RCODE_NXDOMAIN = 3,
		DNS_RCODE_NOTIMP = 4,
		DNS_RCODE_REFUSED = 5,
		DNS_RCODE_YXDOMAIN = 6,
		DNS_RCODE_YXRRSET = 7,
		DNS_RCODE_NOTAUTH = 9,
		DNS_RCODE_NOTZONE = 10,
		DNS_RCODE_BADVERS = 16,
		DNS_RCODE_BADKEY = 17,
		DNS_RCODE_BADTIME = 18,
		DNS_RCODE_BADMODE = 19,
		DNS_RCODE_BADNAME = 20,
		DNS_RCODE_BADALG = 21,
		DNS_RCODE_BADTRUNC = 22,
		DNS_RCODE_BADCOOKIE = 23
	};

	enum class dns_class
	{
		DNS_CLS_IN = 0x0001, // DNS Class Internet
		DNS_CLS_CH = 0x0003, // DNS Class Chaos
		DNS_CLS_HS = 0x0004, // DNS Class Hesiod
		DNS_CLS_QCLASS_NONE = 0x00FE, // DNS Class QCLASS None
		DNS_CLS_QCLASS_ANY = 0x00FF // DNS Class QCLASS Any
	};

#define DNS_RCODE_BADSIG DNS_RCODE_BADVERS

#ifdef _WIN32
#define strcasecmp _stricmp
#endif // _WIN32

	enum class dns_opcode
	{
		DNS_OPCODE_QUERY = 0,
		DNS_OPCODE_IQUERY = 1, // Inverse Query
		DNS_OPCODE_STATUS = 2,
		DNS_OPCODE_NOTIFY = 4,
		DNS_OPCODE_UPDATE = 5
	};

	const size_t DNS_PACKET_MINIMUM_SIZE = 17; // as we handle them
	// 12 bytes header + 1 byte question name + 2 bytes question class + 2 bytes question type

	/*
								   1  1  1  1  1  1
				 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
				+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
				|                      ID                       |
				+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
				|QR|   Opcode  |AA|TC|RD|RA| Z|AD|CD|   RCODE   |
				+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
				|                QDCOUNT/ZOCOUNT                |
				+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
				|                ANCOUNT/PRCOUNT                |
				+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
				|                NSCOUNT/UPCOUNT                |
				+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
				|                    ARCOUNT                    |
				+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	The ID field identifies the query and is echoed in the response so
	   they can be matched.

	   The QR bit indicates whether the header is for a query or a response.

	   The AA, TC, RD, RA, AD, and CD bits are each theoretically meaningful
	   only in queries or only in responses, depending on the bit.  However,
	   many DNS implementations copy the query header as the initial value
	   of the response header without clearing bits.  Thus any attempt to
	   use a "query" bit with a different meaning in a response or to define
	   a query meaning for a "response" bit is dangerous given existing
	   implementation.  Such meanings may only be assigned by an IETF
	   Standards Action.

	   The unsigned fields query count (QDCOUNT), answer count (ANCOUNT),
	   authority count (NSCOUNT), and additional information count (ARCOUNT)
	   express the number of records in each section for all opcodes except
	   Update.  These fields have the same structure and data type for
	   Update but are instead the counts for the zone (ZOCOUNT),
	   prerequisite (PRCOUNT), update (UPCOUNT), and additional information
	   (ARCOUNT) sections.
	*/
	struct dns_header_t
	{
		uint16_t id;
		bool rd;
		bool tc;
		bool aa;
		uint8_t opcode;
		bool qr;
		uint8_t rcode;
		bool ad;
		bool z;
		bool cd;
		bool ra;

		uint16_t q_count; // query count
		uint16_t ans_count; // answer count
		uint16_t auth_count; // authority count
		uint16_t add_count; // additional information count
	};

	struct dns_name_t
	{
		unsigned char name[0xFF];
		uint8_t length;
	};

	struct dns_question_t
	{
		dns_name_t name;
		dns_record_type type;
		unsigned int dns_class_;
	};

	struct dns_head_t
	{
		dns_header_t header;
		dns_question_t question;
	};

	struct dns_record_t
	{
		dns_name_t name;    // Resource Record(RR) name
		dns_record_type type;      // RR TYPE (2 octets)
		uint16_t dns_class_;// RR CLASS codes(2 octets)
		uint32_t ttl;       // time to live(4 octets)
		uint16_t length;    // length in octets of the RDATA field.
		union
		{
			uint8_t *raw;
			dns_name_t name;
            in_addr in_addr_;
            in6_addr in6_addr_;
		} data; // RData
	};

	struct dns_filtered_body_t
	{
		dns_record_t ans[0x100];
		dns_record_t auth[0x100];
		dns_record_t add[0x100];
	};

	struct dns_pkt_t
	{
		dns_head_t head;
		dns_filtered_body_t body;
	};

	struct dns_query_result
	{
		std::string name{};
		std::string class_{};
		std::string record{};
		std::string raw_record{};
		unsigned int ttl{};

		friend std::ostream& operator<<( std::ostream& os, dns_query_result const& r )
		{
			return os << "[" << r.name << "," << r.class_ << "," << r.record << ","
				<< r.raw_record << "," << r.ttl << "]";
		}
	};

	dns_record_type dns_str_to_record_type( const char *str );
    bool parse_name( uint8_t *begin, uint8_t *buf, const uint8_t *end, unsigned char *name, uint8_t *len, uint8_t **next );
    char const *dns_class2str( dns_class cls );
	char const* dns_rcode2str( dns_rcode rcode );
	char const* dns_record_type2str( dns_record_type type );
	bool dns_parse_question( uint8_t *buf, size_t len, dns_head_t *head, uint8_t **body_begin );
	bool dns_parse_record_raw( uint8_t *begin, uint8_t *buf, const uint8_t *end, uint8_t **next, dns_record_t *record );
	bool dns_parse_record( uint8_t *begin, uint8_t *buf, const uint8_t *end, uint8_t **next, dns_record_t *record );
	bool dns_parse_body( uint8_t *buf, uint8_t *begin, const uint8_t *end, dns_pkt_t *packet );
	bool dns_print_readable( char **buf, size_t buflen, unsigned char const *source, size_t len );
	char* dns_name2str( dns_name_t *name );
	void dns_question2str( dns_question_t *question, char *buf, size_t len );
	char* dns_raw_record_data2str( dns_record_t *record, uint8_t *begin, uint8_t *end );
	dns_section dns_get_section( uint16_t index, dns_header_t *header );
	std::vector<std::string> dns_extract_ip_addresses( dns_pkt_t& packet, uint8_t *begin, size_t len, uint8_t *next );
	std::vector<dns_query_result> dns_extract_query_result( dns_pkt_t& packet, uint8_t *begin, size_t len, uint8_t *next );
}
