#include "uri.hpp"
#include <algorithm>
#include <cctype>

namespace fastsub
{
	uri::uri( const std::string & url_s )
	{
		parse( url_s );
	}

	std::string uri::host() const
	{
		return host_;
	}

	void uri::parse( const std::string& url_s )
	{
		std::string const prot_end{ "://" };
		std::string::const_iterator prot_i = std::search( url_s.begin(), url_s.end(),
			prot_end.begin(), prot_end.end() );
		protocol_.reserve( distance( url_s.begin(), prot_i ) );
		std::transform( url_s.begin(), prot_i,
			std::back_inserter( protocol_ ), []( int c ){ return std::tolower( c ); } );
		if( prot_i == url_s.end() )
			return;
		std::advance( prot_i, prot_end.length() );
		std::string::const_iterator path_i = std::find( prot_i, url_s.end(), '/' );
		host_.reserve( distance( prot_i, path_i ) );
		std::transform( prot_i, path_i,
			std::back_inserter( host_ ), []( int c ){ return std::tolower( c ); } );
		std::string::const_iterator query_i = find( path_i, url_s.end(), '?' );
		path_.assign( path_i, query_i );
		if( query_i != url_s.end() )
			++query_i;
		query_.assign( query_i, url_s.end() );
	}
}