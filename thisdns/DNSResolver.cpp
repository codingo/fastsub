#include "DNSResolver.hpp"
#include <vector>
#include <stdlib.h>
#include <string.h>

#include <asio/deadline_timer.hpp>
#include "ares_dns.hpp"

namespace fastsub
{
	std::atomic<std::size_t> Query::processed(0UL);
	std::atomic<std::size_t> Query::successful(0UL);

	int create_query( const char *name, int type, unsigned short id, unsigned char *bufp, 
		int *buflenp )
	{
		unsigned char *q;
		const char *p;
		size_t buflen;
		
		/* Set our results early, in case we bail out early with an error. */
		*buflenp = 0;

		/* Allocate a memory area for the maximum size this packet might need. +2
		 * is for the length byte and zero termination if no dots or ecscaping is
		 * used.
		 */
		size_t len = strlen( name ) + 18; // 2 + 12 + 4
		std::memset( bufp, 0, len );
		
		/* Set up the header. */
		q = bufp;
		memset( q, 0, HEADER_FIXED_SZ ); // zero-out the first 12 bytes
		DNS_HEADER_SET_QID( q, id );
		DNS_HEADER_SET_OPCODE( q, QUERY );
		DNS_HEADER_SET_RD( q, 1 );
		DNS_HEADER_SET_QDCOUNT( q, 1 );

		/* A name of "." is a screw case for the loop below, so adjust it. */
		if( strcmp( name, "." ) == 0 )
			name++;

		/* Start writing out the name after the header. */
		q += HEADER_FIXED_SZ;
		
		while( *name ){
			if( *name == '.' ) return ARES_EBADNAME;

			/* Count the number of bytes in this label. */
			len = 0;
			for( p = name; *p && *p != '.'; p++ ){
				if( *p == '\\' && *( p + 1 ) != 0 )
					p++;
				len++;
			}
			if( len > MAXLABEL ) return ARES_EBADNAME;

			/* Encode the length and copy the data. */
			*q++ = (unsigned char) len;
			for( p = name; *p && *p != '.'; p++ ){
				if( *p == '\\' && *( p + 1 ) != 0 )
					p++;
				*q++ = *p;
			}

			/* Go to the next label and repeat, unless we hit the end. */
			if( !*p )
				break;
			name = p + 1;
		}

		/* Add the zero-length label at the end. */
		*q++ = 0;

		/* Finish off the question with the type and class. */
		DNS_QUESTION_SET_TYPE( q, type );
		DNS_QUESTION_SET_CLASS( q, 1 ); // DNS Class IN

		q += QFIXEDSZ;
		buflen = ( q - bufp );

		/* Reject names that are longer than the maximum of 255 bytes that's
		 * specified in RFC 1035 ("To simplify implementations, the total length of
		 * a domain name (i.e., label octets and label length octets) is restricted
		 * to 255 octets or less."). */
		if( buflen > (size_t) ( MAXCDNAME + HEADER_FIXED_SZ + QFIXEDSZ ) ){
			return ARES_EBADNAME;
		}

		/* we know this fits in an int at this point */
		*buflenp = (int) buflen;
		return 0;
	}
}
