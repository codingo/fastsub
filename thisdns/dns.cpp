#define ASIO_STANDALONE
#define ASIO_HEADER_ONLY

#include <vector>
#include <asio.hpp>
#include "dns.hpp"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>

int inet_pton( int af, const char *src, void *dst )
{
	sockaddr_storage ss;
	int size = sizeof( ss );
	char src_copy[INET6_ADDRSTRLEN + 1];

	ZeroMemory( &ss, sizeof( ss ) );
	/* stupid non-const API */
	strncpy( src_copy, src, INET6_ADDRSTRLEN + 1 );
	src_copy[INET6_ADDRSTRLEN] = 0;

	if( WSAStringToAddressA( src_copy, af, NULL, (sockaddr *) &ss, &size ) == 0 ){
		switch( af ){
		case AF_INET:
			*(in_addr *) dst = ( (sockaddr_in *) &ss )->sin_addr;
			return 1;
		case AF_INET6:
			*(in6_addr *) dst = ( (sockaddr_in6 *) &ss )->sin6_addr;
			return 1;
		}
	}
	return 0;
}

const char *inet_ntop( int af, const void *src, char *dst, socklen_t size )
{
	sockaddr_storage ss;
	unsigned long s = size;

	ZeroMemory( &ss, sizeof( ss ) );
	ss.ss_family = af;

	switch( af ){
	case AF_INET:
		( (sockaddr_in *) &ss )->sin_addr = *(in_addr *) src;
		break;
	case AF_INET6:
		( (sockaddr_in6 *) &ss )->sin6_addr = *(in6_addr *) src;
		break;
	default:
		return NULL;
	}
	/* cannot direclty use &size because of strict aliasing rules */
	return ( WSAAddressToStringA( (sockaddr *) &ss, sizeof( ss ), NULL, dst, &s ) == 0 ) ?
		dst : NULL;
}
#endif // _WIN32

namespace fastsub
{
	char const *dns_class2str( dns_class cls )
	{
		static char numbuf[16];

		switch( cls ){
		case dns_class::DNS_CLS_IN:
			return "IN";
		case dns_class::DNS_CLS_CH:
			return "H";
		case dns_class::DNS_CLS_HS:
			return "HS";
		case dns_class::DNS_CLS_QCLASS_NONE:
			return "QNONE";
		case dns_class::DNS_CLS_QCLASS_ANY:
			return "QANY";
		default:
			snprintf( numbuf, sizeof( numbuf ), "%" PRIu16, (uint16_t) cls );
			return numbuf;
		}
	}

	char const* dns_record_type2str( dns_record_type type )
	{
		static char numbuf[16]{};

		switch( type ){
		case dns_record_type::DNS_REC_A:
			return "A";
		case dns_record_type::DNS_REC_AAAA:
			return "AAAA";
		case dns_record_type::DNS_REC_AFSDB:
			return "AFSDB";
		case dns_record_type::DNS_REC_ANY:
			return "ANY";
		case dns_record_type::DNS_REC_APL:
			return "APL";
		case dns_record_type::DNS_REC_CAA:
			return "CAA";
		case dns_record_type::DNS_REC_CDNSKEY:
			return "CDNSKEY";
		case dns_record_type::DNS_REC_CDS:
			return "CDS";
		case dns_record_type::DNS_REC_CERT:
			return "CERT";
		case dns_record_type::DNS_REC_CNAME:
			return "CNAME";
		case dns_record_type::DNS_REC_DHCID:
			return "DHCID";
		case dns_record_type::DNS_REC_DLV:
			return "DLV";
		case dns_record_type::DNS_REC_DNAME:
			return "DNAME";
		case dns_record_type::DNS_REC_DNSKEY:
			return "DNSKEY";
		case dns_record_type::DNS_REC_DS:
			return "DS";
		case dns_record_type::DNS_REC_HIP:
			return "HIP";
		case dns_record_type::DNS_REC_IPSECKEY:
			return "IPSECKEY";
		case dns_record_type::DNS_REC_KEY:
			return "KEY";
		case dns_record_type::DNS_REC_KX:
			return "KX";
		case dns_record_type::DNS_REC_LOC:
			return "LOC";
		case dns_record_type::DNS_REC_MX:
			return "MX";
		case dns_record_type::DNS_REC_NAPTR:
			return "NAPTR";
		case dns_record_type::DNS_REC_NS:
			return "NS";
		case dns_record_type::DNS_REC_NSEC:
			return "NSEC";
		case dns_record_type::DNS_REC_NSEC3:
			return "NSEC3";
		case dns_record_type::DNS_REC_NSEC3PARAM:
			return "NSEC3PARAM";
		case dns_record_type::DNS_REC_OPENPGPKEY:
			return "OPENPGPKEY";
		case dns_record_type::DNS_REC_PTR:
			return "PTR";
		case dns_record_type::DNS_REC_RRSIG:
			return "RRSIG";
		case dns_record_type::DNS_REC_RP:
			return "RP";
		case dns_record_type::DNS_REC_SIG:
			return "SIG";
		case dns_record_type::DNS_REC_SOA:
			return "SOA";
		case dns_record_type::DNS_REC_SRV:
			return "SRV";
		case dns_record_type::DNS_REC_SSHFP:
			return "SSHFP";
		case dns_record_type::DNS_REC_TA:
			return "TA";
		case dns_record_type::DNS_REC_TKEY:
			return "TKEY";
		case dns_record_type::DNS_REC_TLSA:
			return "TLSA";
		case dns_record_type::DNS_REC_TSIG:
			return "TSIG";
		case dns_record_type::DNS_REC_TXT:
			return "TXT";
		case dns_record_type::DNS_REC_URI:
			return "URI";
		default:
			snprintf( numbuf, sizeof( numbuf ), "%" PRIu16, (uint16_t) type );
			return numbuf;
		}
	}
	bool parse_name( uint8_t *begin, uint8_t *buf, const uint8_t *end, unsigned char *name, uint8_t *len, uint8_t **next )
	{
		uint8_t first{};
		int label_type{};
		int label_len{};
		int name_len{};
		uint8_t *pointer{ nullptr };

		while( true ){
			if( buf >= end ){
				return false;
			}
			first = *buf;
			label_type = ( first & 0xC0 );
			if( label_type == 0xC0 ) // Compressed
			{
				if( next && !pointer ){
					*next = buf + 2;
				}
				pointer = begin + ( htons( *( (uint16_t *) buf ) ) & 0x3FFF );
				if( pointer >= buf ){
					return false;
				}
				buf = pointer;
			} else if( label_type == 0x00 ) // Uncompressed
			{
				label_len = ( first & 0x3F );
				name_len += label_len + 1;
				if( name_len >= 0xFF ){
					return false;
				}
				if( label_len == 0 ){
					if( name_len == 1 ){
						*( name++ ) = '.';
					}
					*name = 0;
					if( next && !pointer ){
						*next = buf + label_len + 1;
					}
					if( name_len <= 1 ){
						*len = (uint8_t) name_len;
					} else{
						*len = (uint8_t) ( name_len - 1 );
					}
					return true;
				} else{
					if( buf + label_len + 1 > end ){
						return false;
					}
					memcpy( name, buf + 1, (size_t) label_len );
					*( name + label_len ) = '.';
					name += label_len + 1;
					buf += label_len + 1;
				}
			} else{
				return false;
			}
		}
	}

	bool dns_parse_question( uint8_t *buf, size_t len, dns_head_t *head, uint8_t **body_begin )
	{
		uint8_t *end{}; // exclusive
		bool name_parsed{};
		uint8_t *qname_end{};

		end = buf + len;
		if( len < DNS_PACKET_MINIMUM_SIZE ){
			return false;
		}

		head->header.id = ntohs( ( *(uint16_t *) buf ) );
		head->header.qr = (bool) ( buf[2] & 0x80 );
		head->header.opcode = (uint8_t) ( ( buf[2] & ( 0x78 ) ) >> 3 );
		head->header.aa = (bool) ( buf[2] & 0x04 );
		head->header.tc = (bool) ( buf[2] & 0x02 );
		head->header.rd = (bool) ( buf[2] & 0x01 );
		head->header.ra = (bool) ( buf[3] & 0x80 );
		head->header.z = (bool) ( buf[4] & 0x40 );
		head->header.ad = (bool) ( buf[3] & 0x20 );
		head->header.cd = (bool) ( buf[3] & 0x10 );
		head->header.rcode = (uint8_t) ( buf[3] & 0x0F );

		head->header.ans_count = ntohs( ( *(uint16_t *) ( buf + 6 ) ) );
		head->header.auth_count = ntohs( ( *(uint16_t *) ( buf + 8 ) ) );
		head->header.add_count = ntohs( ( *(uint16_t *) ( buf + 10 ) ) );
		head->header.q_count = ntohs( ( *(uint16_t *) ( buf + 4 ) ) );
		if( head->header.q_count != 1 ){
			return false;
		}
		name_parsed = parse_name( buf, buf + 12, end, head->question.name.name, &head->question.name.length, &qname_end );
		if( qname_end + 2 > end ){
			return false;
		}
		if( !name_parsed ){
			return false;
		}
		head->question.type = (dns_record_type) ntohs( ( *(uint16_t *) qname_end ) );
		head->question.dns_class_ = ntohs( ( *(uint16_t *) ( qname_end + 2 ) ) );
		if( body_begin ){
			*body_begin = qname_end + 4;
		}
		return true;
	}

	bool dns_parse_record_raw( uint8_t *begin, uint8_t *buf, const uint8_t *end, uint8_t **next, dns_record_t *record )
	{
		if( !parse_name( begin, buf, end, record->name.name, &record->name.length, next ) ){
			return false;
		}
		if( *next + 10 > end ){
			return false;
		}

		record->type = (dns_record_type) ntohs( ( *(uint16_t *) ( *next ) ) );
		record->dns_class_ = ntohs( ( *(uint16_t *) ( *next + 2 ) ) );
		record->ttl = ntohl( ( *(uint32_t *) ( *next + 4 ) ) );
		record->length = ntohs( ( *(uint16_t *) ( *next + 8 ) ) );
		*next = *next + 10;

		record->data.raw = *next;

		*next = *next + record->length;
		if( *next > end ){
			return false;
		}
		return true;
	}

	bool dns_parse_record( uint8_t *begin, uint8_t *buf, const uint8_t *end, uint8_t **next, dns_record_t *record )
	{
		if( !dns_parse_record_raw( begin, buf, end, next, record ) ){
			return false;
		}

		if( record->type == dns_record_type::DNS_REC_A ){
			if( record->length != 4 ){
				return false;
			}
			memcpy( &record->data.in_addr_, record->data.raw, 4 );
		} else if( record->type == dns_record_type::DNS_REC_AAAA ){
			if( record->length != 16 ){
				return false;
			}
			memcpy( &record->data.in6_addr_, record->data.raw, 16 );
		} else if( record->type == dns_record_type::DNS_REC_NS ){
			if( record->length > 0xFF ){
				return false;
			}
			if( !parse_name( begin, record->data.raw, end, record->data.name.name, &record->data.name.length, NULL ) ){
				return false;
			}
		}

		// We don't care about any other records.

		return true;
	}

	bool dns_parse_body( uint8_t *buf, uint8_t *begin, const uint8_t *end, dns_pkt_t *packet )
	{
		uint8_t *next = buf;
		static uint16_t i;

		for( i = 0; i < minimum( packet->head.header.ans_count, elements( packet->body.ans ) - 1 ); i++ ){
			if( !dns_parse_record( begin, next, end, &next, &packet->body.ans[i] ) ){
				return false;
			}
		}
		packet->body.ans[i].type = dns_record_type::DNS_REC_UNDEFINED;

		for( i = 0; i < minimum( packet->head.header.auth_count, elements( packet->body.auth ) - 1 ); i++ ){
			if( !dns_parse_record( begin, next, end, &next, &packet->body.auth[i] ) ){
				return false;
			}
		}
		packet->body.auth[i].type = dns_record_type::DNS_REC_UNDEFINED;

		for( i = 0; i < minimum( packet->head.header.add_count, elements( packet->body.add ) - 1 ); i++ ){
			if( !dns_parse_record( begin, next, end, &next, &packet->body.add[i] ) ){
				return false;
			}
		}
		packet->body.add[i].type = dns_record_type::DNS_REC_UNDEFINED;

		// TODO: Check whether overly long packets are valid. If not, discard them here.

		return true;
	}

	bool dns_print_readable( char **buf, size_t buflen, unsigned char const *source, size_t len )
	{
		char *endbuf = *buf + buflen;
		for( size_t i = 0; i < len; i++ ){
			if( source[i] >= ' ' && source[i] <= '~' && source[i] != '\\' ){
				if( *buf >= endbuf - 1 ){
					**buf = 0;
					return false;
				}
				*( ( *buf )++ ) = source[i];
			} else{
				if( *buf >= endbuf - 4 ){
					**buf = 0;
					return false;
				}
				*( ( *buf )++ ) = '\\';
				*( ( *buf )++ ) = 'x';
				char hex1 = (char) ( ( source[i] >> 8 ) & 0xF );
				char hex2 = (char) ( source[i] & 0xF );
				*( ( *buf )++ ) = (char) ( hex1 + ( hex1 < 10 ? '0' : ( 'a' - 10 ) ) );
				*( ( *buf )++ ) = (char) ( hex2 + ( hex2 < 10 ? '0' : ( 'a' - 10 ) ) );
			}
		}
		**buf = 0;
		return true;
	}

	char* dns_name2str( dns_name_t *name )
	{
		static char buf[0xFF * 4];

		char *ptr = buf;
		dns_print_readable( &ptr, sizeof( buf ), name->name, name->length );
		return buf;
	}

	void dns_question2str( dns_question_t *question, char *buf, size_t len )
	{
		snprintf( buf, len, "%s %s %s",
			dns_name2str( &question->name ),
			dns_class2str( (dns_class) question->dns_class_ ),
			dns_record_type2str( question->type ) );
	}

	char* dns_raw_record_data2str( dns_record_t *record, uint8_t *begin, uint8_t *end )
	{
		static char buf[0xFFFF0];
		dns_name_t name;

		char *ptr = buf;

		switch( record->type ){
		case dns_record_type::DNS_REC_NS:
		case dns_record_type::DNS_REC_CNAME:
		case dns_record_type::DNS_REC_DNAME:
		case dns_record_type::DNS_REC_PTR:
			parse_name( begin, record->data.raw, end, name.name, &name.length, NULL );
			dns_print_readable( &ptr, sizeof( buf ), name.name, name.length );
			break;
		case dns_record_type::DNS_REC_MX:
		{
			if( record->length < 3 ){
				goto raw;
			}
			parse_name( begin, record->data.raw + 2, end, name.name, &name.length, NULL );
			int no = sprintf( buf, "%" PRIu16 " ", ntohs( *( (uint16_t*) record->data.raw ) ) );
			ptr += no;
			dns_print_readable( &ptr, sizeof( buf ), name.name, name.length );
		}
		break;
		case dns_record_type::DNS_REC_TXT:
		{
			uint8_t *record_end = record->data.raw + record->length;
			uint8_t *data_ptr = record->data.raw;
			while( data_ptr < record_end ){
				uint8_t length = *( data_ptr++ );
				if( data_ptr + length <= record_end ){
					*( ptr++ ) = '"';
					dns_print_readable( &ptr, sizeof( buf ), data_ptr, length );
					data_ptr += length;
					*( ptr++ ) = '"';
					*( ptr++ ) = ' ';
				} else{
					break;
				}
			}
			*ptr = 0;
			break;
		}
		case dns_record_type::DNS_REC_SOA:
		{
			uint8_t *next;
			// We have 5 32-bit values plus two names.
			if( record->length < 22 ){
				goto raw;
			}

			parse_name( begin, record->data.raw, end, name.name, &name.length, &next );
			dns_print_readable( &ptr, sizeof( buf ), name.name, name.length );
			*( ptr++ ) = ' ';

			if( next + 20 >= record->data.raw + record->length ){
				goto raw;
			}
			parse_name( begin, next, end, name.name, &name.length, &next );
			dns_print_readable( &ptr, sizeof( buf ), name.name, name.length );
			*( ptr++ ) = ' ';
			if( next + 20 > record->data.raw + record->length ){
				goto raw;
			}

			sprintf( ptr, "%" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32,
				ntohl( *( (uint32_t*) next ) ),
				ntohl( *( ( (uint32_t*) next ) + 1 ) ),
				ntohl( *( ( (uint32_t*) next ) + 2 ) ),
				ntohl( *( ( (uint32_t*) next ) + 3 ) ),
				ntohl( *( ( (uint32_t*) next ) + 4 ) ) );
			break;
		}
		case dns_record_type::DNS_REC_A:
		{

			if( record->length != 4 ){
				goto raw;
			}
			inet_ntop( AF_INET, record->data.raw, buf, sizeof( buf ) );
		}
		break;
		case dns_record_type::DNS_REC_AAAA:
		{
			if( record->length != 16 ){
				goto raw;
			}
			inet_ntop( AF_INET6, record->data.raw, buf, sizeof( buf ) );
		}
		break;
		case dns_record_type::DNS_REC_CAA:
		{
			if( record->length < 2 || record->data.raw[1] < 1 || record->data.raw[1] > 15
				|| record->data.raw[1] + 2 > record->length ){
				goto raw;
			}
			int written = sprintf( ptr, "%" PRIu8 " ", (uint8_t) ( record->data.raw[0] >> 7 ) );
			if( written < 0 ){
				return buf;
			}
			ptr += written;
			dns_print_readable( &ptr, sizeof( buf ), record->data.raw + 2, record->data.raw[1] );
			*( ptr++ ) = ' ';
			*( ptr++ ) = '"';
			dns_print_readable( &ptr, sizeof( buf ), record->data.raw + 2 + record->data.raw[1],
				(size_t) ( record->length - record->data.raw[1] - 2 ) );
			*( ptr++ ) = '"';
			*ptr = 0;
		}
		break;
	raw:
		default:
			dns_print_readable( &ptr, sizeof( buf ), record->data.raw, record->length );
			*ptr = 0;
		}
		return buf;
	}

	dns_section dns_get_section( uint16_t index, dns_header_t *header )
	{
		if( index < header->ans_count ){
			return dns_section::DNS_SECTION_ANSWER;
		} else if( index < header->ans_count + header->auth_count ){
			return dns_section::DNS_SECTION_AUTHORITY;
		} else{
			return dns_section::DNS_SECTION_ADDITIONAL;
		}
	}

	char const* dns_rcode2str( dns_rcode rcode )
	{
		static char numbuf[16];

		switch( rcode ) {
		case dns_rcode::DNS_RCODE_OK:
			return "NOERROR";
		case dns_rcode::DNS_RCODE_FORMERR:
			return "FORMERR";
		case dns_rcode::DNS_RCODE_SERVFAIL:
			return "SERVFAIL";
		case dns_rcode::DNS_RCODE_NXDOMAIN:
			return "NXDOMAIN";
		case dns_rcode::DNS_RCODE_NOTIMP:
			return "NOTIMP";
		case dns_rcode::DNS_RCODE_REFUSED:
			return "REFUSED";
		case dns_rcode::DNS_RCODE_YXDOMAIN:
			return "YXDOMAIN";
		case dns_rcode::DNS_RCODE_YXRRSET:
			return "YXRRSET";
		case dns_rcode::DNS_RCODE_NOTAUTH:
			return "NOTAUTH";
		case dns_rcode::DNS_RCODE_NOTZONE:
			return "NOTZONE";
		case dns_rcode::DNS_RCODE_BADVERS:
			return "BADVERS";
		case dns_rcode::DNS_RCODE_BADKEY:
			return "BADKEY";
		case dns_rcode::DNS_RCODE_BADTIME:
			return "BADTIME";
		case dns_rcode::DNS_RCODE_BADMODE:
			return "BADMODE";
		case dns_rcode::DNS_RCODE_BADNAME:
			return "BADNAME";
		case dns_rcode::DNS_RCODE_BADALG:
			return "BADALG";
		case dns_rcode::DNS_RCODE_BADTRUNC:
			return "BADTRUNC";
		case dns_rcode::DNS_RCODE_BADCOOKIE:
			return "BADCOOKIE";
		default:
			snprintf( numbuf, sizeof( numbuf ), "%" PRIu16, (uint16_t) rcode );
			return numbuf;
		}
	}

	std::vector<std::string> dns_extract_ip_addresses( dns_pkt_t& packet, uint8_t *begin, size_t len, uint8_t *next )
	{
		thread_local char buf[0xFFFF]{};
		thread_local dns_record_t rec;

		dns_question2str( &packet.head.question, buf, sizeof( buf ) );

		uint16_t i = 0;
		dns_section section = dns_section::DNS_SECTION_QUESTION;
		std::vector<std::string> ip_addresses{};
		ip_addresses.reserve( 10 );
		while( dns_parse_record_raw( begin, next, begin + len, &next, &rec ) ){
			dns_section new_section = dns_get_section( i++, &packet.head.header );
			if( new_section != section ){
				section = new_section;
			}
			char const *raw_data_str = dns_raw_record_data2str( &rec, begin, begin + len );
			if( section == dns_section::DNS_SECTION_ANSWER ){
				std::string data{ raw_data_str };
				if( data.find_first_not_of( "0123456789." ) == std::string::npos ){
					ip_addresses.emplace_back( std::move( data ));
				}
			}
		}
		return ip_addresses;
	}

	std::vector<dns_query_result> dns_extract_query_result( dns_pkt_t& packet, uint8_t *begin,  size_t len, uint8_t *next )
	{
		thread_local char buf[0xFFFF];
		thread_local dns_record_t rec;

		dns_question2str( &packet.head.question, buf, sizeof( buf ) );
		std::vector<dns_query_result> query_results{};
		uint16_t i = 0;
		dns_section section = dns_section::DNS_SECTION_QUESTION;
		while( dns_parse_record_raw( begin, next, begin + len, &next, &rec ) ){
			dns_section new_section = dns_get_section( i++, &packet.head.header );
			if( new_section != section ){
				section = new_section;
			}
			if( section == dns_section::DNS_SECTION_ANSWER ){
				std::string dns_name{ dns_name2str( &rec.name ) };
				std::string dns_class_s{ dns_class2str( static_cast<dns_class>( rec.dns_class_ ) ) };
				std::string dns_record_s{ dns_record_type2str( static_cast<dns_record_type>( rec.type )) };
				std::string raw_record{ dns_raw_record_data2str( &rec, begin, begin + len ) };
				unsigned int ttl = rec.ttl;
				query_results.push_back( dns_query_result{ dns_name, dns_class_s, dns_record_s, raw_record, ttl } );
			}
		}
		return query_results;
	}

	dns_record_type dns_str_to_record_type( const char *str )
	{
		// Performance is important here because we may want to use this when reading
		// large numbers of DNS queries from a file.

		switch( tolower( str[0] ) ){
		case 'a':
			switch( tolower( str[1] ) ){
			case 0:
				return dns_record_type::DNS_REC_A;
			case 'a':
				if( tolower( str[2] ) == 'a' && tolower( str[3] ) == 'a' && str[4] == 0 ){
					return dns_record_type::DNS_REC_AAAA;
				}
				return dns_record_type::DNS_REC_INVALID;
			case 'f':
				if( tolower( str[2] ) == 's' && tolower( str[3] ) == 'd' && tolower( str[4] ) == 'b' && str[5] == 0 ){
					return dns_record_type::DNS_REC_AFSDB;
				}
				return dns_record_type::DNS_REC_INVALID;
			case 'n':
				if( tolower( str[2] ) == 'y' && str[3] == 0 ){
					return dns_record_type::DNS_REC_ANY;
				}
				return dns_record_type::DNS_REC_INVALID;
			case 'p':
				if( tolower( str[2] ) == 'l' && str[3] == 0 ){
					return dns_record_type::DNS_REC_APL;
				}
				return dns_record_type::DNS_REC_INVALID;
			default:
				return dns_record_type::DNS_REC_INVALID;
			}
		case 'c':
			switch( tolower( str[1] ) ){
			case 'a':
				if( tolower( str[2] ) == 'a' && str[3] == 0 ){
					return dns_record_type::DNS_REC_CAA;
				}
				return dns_record_type::DNS_REC_INVALID;
			case 'd':
				switch( tolower( str[2] ) ){
				case 's':
					if( str[3] == 0 ){
						return dns_record_type::DNS_REC_CDS;
					}
					return dns_record_type::DNS_REC_INVALID;
				case 'n':
					if( tolower( str[3] ) == 's' && tolower( str[4] ) == 'k' && tolower( str[5] ) == 'e'
						&& tolower( str[6] ) == 'y' && str[7] == 0 ){
						return dns_record_type::DNS_REC_CDNSKEY;
					}
				default:
					return dns_record_type::DNS_REC_INVALID;
				}
			case 'e':
				if( tolower( str[2] ) == 'r' && tolower( str[3] ) == 't' && str[4] == 0 ){
					return dns_record_type::DNS_REC_CERT;
				}
				return dns_record_type::DNS_REC_INVALID;
			case 'n':
				if( tolower( str[2] ) == 'a' && tolower( str[3] ) == 'm' && tolower( str[4] ) == 'e' && str[5] == 0 ){
					return dns_record_type::DNS_REC_CNAME;
				}
				return dns_record_type::DNS_REC_INVALID;
			default:
				return dns_record_type::DNS_REC_INVALID;
			}
		case 'd':
			switch( tolower( str[1] ) ){
			case 'h':
				if( tolower( str[2] ) == 'c' && tolower( str[3] ) == 'i' && tolower( str[4] ) == 'd' && str[5] == 0 ){
					return dns_record_type::DNS_REC_DHCID;
				}
				return dns_record_type::DNS_REC_INVALID;
			case 'l':
				if( tolower( str[2] ) == 'v' && str[3] == 0 ){
					return dns_record_type::DNS_REC_DLV;
				}
				return dns_record_type::DNS_REC_INVALID;
			case 'n':
				switch( tolower( str[2] ) ){
				case 'a':
					if( tolower( str[3] ) == 'm' && tolower( str[4] ) == 'e' && str[5] == 0 ){
						return dns_record_type::DNS_REC_DNAME;
					}
					return dns_record_type::DNS_REC_INVALID;
				case 's':
					if( tolower( str[3] ) == 'k' && tolower( str[4] ) == 'e' && tolower( str[5] ) == 'y' && str[6] == 0 ){
						return dns_record_type::DNS_REC_DNSKEY;
					}
					return dns_record_type::DNS_REC_INVALID;
				default:
					return dns_record_type::DNS_REC_INVALID;
				}
			case 's':
				if( str[2] == 0 ){
					return dns_record_type::DNS_REC_DS;
				}
				return dns_record_type::DNS_REC_INVALID;
			default:
				return dns_record_type::DNS_REC_INVALID;
			}
		case 'h':
			if( tolower( str[1] ) == 'i' && tolower( str[2] ) == 'p' && str[3] == 0 ){
				return dns_record_type::DNS_REC_HIP;
			}
			return dns_record_type::DNS_REC_INVALID;
		case 'i':
			if( tolower( str[1] ) == 'p' && tolower( str[2] ) == 's' && tolower( str[3] ) == 'e' && tolower( str[4] ) == 'c'
				&& tolower( str[5] ) == 'k' && tolower( str[6] ) == 'e' && tolower( str[7] ) == 'y' && str[8] == 0 ){
				return dns_record_type::DNS_REC_IPSECKEY;
			}
			return dns_record_type::DNS_REC_INVALID;
		case 'k':
			switch( tolower( str[1] ) ){
			case 'e':
				if( tolower( str[2] ) == 'y' && str[3] == 0 ){
					return dns_record_type::DNS_REC_KEY;
				}
				return dns_record_type::DNS_REC_INVALID;
			case 'x':
				if( str[2] == 0 ){
					return dns_record_type::DNS_REC_KX;
				}
				return dns_record_type::DNS_REC_INVALID;
			default:
				return dns_record_type::DNS_REC_INVALID;
			}
		case 'l':
			if( tolower( str[1] ) == 'o' && tolower( str[2] ) == 'c' && str[3] == 0 ){
				return dns_record_type::DNS_REC_LOC;
			}
			return dns_record_type::DNS_REC_INVALID;
		case 'm':
			if( tolower( str[1] ) == 'x' && str[2] == 0 ){
				return dns_record_type::DNS_REC_MX;
			}
			return dns_record_type::DNS_REC_INVALID;
		case 'n':
			switch( tolower( str[1] ) ){
			case 'a':
				if( tolower( str[2] ) == 'p' && tolower( str[3] ) == 't' && tolower( str[4] ) == 'r' && str[5] == 0 ){
					return dns_record_type::DNS_REC_NAPTR;
				}
				return dns_record_type::DNS_REC_INVALID;
			case 's':
				switch( tolower( str[2] ) ){
				case 0:
					return dns_record_type::DNS_REC_NS;
				case 'e':
					if( tolower( str[3] ) == 'c' ){
						switch( tolower( str[4] ) ){
						case 0:
							return dns_record_type::DNS_REC_NSEC;
						case '3':
							if( str[5] == 0 ){
								return dns_record_type::DNS_REC_NSEC3;
							}
							if( tolower( str[5] ) == 'p' && tolower( str[6] ) == 'a' && tolower( str[7] ) == 'r'
								&& tolower( str[8] ) == 'a' && tolower( str[9] ) == 'm' && str[10] == 0 ){
								return dns_record_type::DNS_REC_NSEC3PARAM;
							}
							return dns_record_type::DNS_REC_INVALID;
						default:
							return dns_record_type::DNS_REC_INVALID;
						}
					}
					return dns_record_type::DNS_REC_INVALID;
				default:
					return dns_record_type::DNS_REC_INVALID;
				}
			default:
				return dns_record_type::DNS_REC_INVALID;
			}
		case 'o':
			if( tolower( str[1] ) == 'p' && tolower( str[2] ) == 'e' && tolower( str[3] ) == 'n' && tolower( str[4] ) == 'p'
				&& tolower( str[5] ) == 'g' && tolower( str[6] ) == 'p' && tolower( str[7] ) == 'k' && tolower( str[8] ) == 'e'
				&& tolower( str[9] ) == 'y' && str[10] == 0 ){
				return dns_record_type::DNS_REC_OPENPGPKEY;
			}
			return dns_record_type::DNS_REC_INVALID;
		case 'p':
			if( tolower( str[1] ) == 't' && tolower( str[2] ) == 'r' && str[3] == 0 ){
				return dns_record_type::DNS_REC_PTR;
			}
			return dns_record_type::DNS_REC_INVALID;
		case 'r':
			switch( tolower( str[1] ) ){
			case 'p':
				if( str[2] == 0 ){
					return dns_record_type::DNS_REC_RP;
				}
				return dns_record_type::DNS_REC_INVALID;
			case 'r':
				if( tolower( str[2] ) == 's' && tolower( str[3] ) == 'i' && tolower( str[4] ) == 'g' && str[5] == 0 ){
					return dns_record_type::DNS_REC_RRSIG;
				}
				return dns_record_type::DNS_REC_INVALID;
			default:
				return dns_record_type::DNS_REC_INVALID;
			}
		case 's':
			switch( tolower( str[1] ) ){
			case 'i':
				if( tolower( str[2] ) == 'g' && tolower( str[3] ) == 0 ){
					return dns_record_type::DNS_REC_SIG;
				}
				return dns_record_type::DNS_REC_INVALID;
			case 'o':
				if( tolower( str[2] ) == 'a' && tolower( str[3] ) == 0 ){
					return dns_record_type::DNS_REC_SOA;
				}
				return dns_record_type::DNS_REC_INVALID;
			case 'r':
				if( tolower( str[2] ) == 'v' && tolower( str[3] ) == 0 ){
					return dns_record_type::DNS_REC_SRV;
				}
				return dns_record_type::DNS_REC_INVALID;
			case 's':
				if( tolower( str[2] ) == 'h' && tolower( str[3] ) == 'f' && tolower( str[4] ) == 'p' && str[5] == 0 ){
					return dns_record_type::DNS_REC_SSHFP;
				}
				return dns_record_type::DNS_REC_INVALID;
			default:
				return dns_record_type::DNS_REC_INVALID;
			}
		case 't':
			switch( tolower( str[1] ) ){
			case 'a':
				if( str[2] == 0 ){
					return dns_record_type::DNS_REC_TA;
				}
				return dns_record_type::DNS_REC_INVALID;
			case 'k':
				if( tolower( str[2] ) == 'e' && tolower( str[3] ) == 'y' && str[4] == 0 ){
					return dns_record_type::DNS_REC_TKEY;
				}
				return dns_record_type::DNS_REC_INVALID;
			case 'l':
				if( tolower( str[2] ) == 's' && tolower( str[3] ) == 'a' && str[4] == 0 ){
					return dns_record_type::DNS_REC_TLSA;
				}
				return dns_record_type::DNS_REC_INVALID;
			case 's':
				if( tolower( str[2] ) == 'i' && tolower( str[3] ) == 'g' && str[4] == 0 ){
					return dns_record_type::DNS_REC_TSIG;
				}
				return dns_record_type::DNS_REC_INVALID;
			case 'x':
				if( tolower( str[2] ) == 't' && str[3] == 0 ){
					return dns_record_type::DNS_REC_TXT;
				}
				return dns_record_type::DNS_REC_INVALID;
			default:
				return dns_record_type::DNS_REC_INVALID;
			}
		case 'u':
			switch( tolower( str[1] ) ){
			case 'r':
				if( tolower( str[2] ) == 'i' && str[3] == 0 ){
					return dns_record_type::DNS_REC_URI;
				}
				return dns_record_type::DNS_REC_INVALID;
			default:
				return dns_record_type::DNS_REC_INVALID;
			}
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			return (dns_record_type) atoi( str );
		default:
			return dns_record_type::DNS_REC_INVALID;
		}
	}
}
