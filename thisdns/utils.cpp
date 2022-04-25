#include "utils.hpp"
#include <algorithm>
#include <cctype>
#include <spdlog/spdlog.h>

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
			std::back_inserter( protocol_ ), []( int c ) { return std::tolower( c ); } );
		if( prot_i == url_s.end() )
			return;
		std::advance( prot_i, prot_end.length() );
		std::string::const_iterator path_i = std::find( prot_i, url_s.end(), '/' );
		host_.reserve( distance( prot_i, path_i ) );
		std::transform( prot_i, path_i,
			std::back_inserter( host_ ), []( int c ) { return std::tolower( c ); } );
		std::string::const_iterator query_i = find( path_i, url_s.end(), '?' );
		path_.assign( path_i, query_i );
		if( query_i != url_s.end() )
			++query_i;
		query_.assign( query_i, url_s.end() );
	}

	char *trim_start( char *str )
	{
		while( 0 != *str ) {
			if( !isspace( *str ) ) {
				return str;
			}
			str++;
		}
		return str;
	}

	void trim_end( char* str )
	{
		char *last = str + strlen( str ) - 1;
		while( last >= str ) {
			if( !isspace( *last ) ) {
				return;
			}
			*last = 0;
			last--;
		}
	}

	bool startswith( std::string const & str, std::string const & test )
	{
		if( test.size() > str.size() ) return false;
		for( std::size_t i = 0; i != test.size(); ++i )
			if( test[i] != str[i] ) return false;
		return true;
	}

	StringList split_string( std::string const & str, char const *sep )
	{
		std::size_t previous{};
		std::size_t current{ str.find( sep ) };
		StringList result{};
		while( current != std::string::npos ) {
			result.push_back( str.substr( previous, current - previous ) );
			previous = current + 1;
			current = str.find( sep, previous );
		}
		result.push_back( str.substr( previous, current - previous ) );
		return result;
	}

	StringList parse_json_file( std::string const & filename )
	{
		json json_object{};
		try {
			{
				std::ifstream in_file{ filename };
				in_file >> json_object;
			}
			json::array_t root = json_object.get<json::array_t>();
			json::object_t elements = root[0].get<json::object_t>();
			if( root.empty() ) return{};

			StringList names{};
			names.reserve( root.size() ); // delay constant reallocation until it can't
			for( auto const &r : elements ) {
				names.emplace_back( r.first );
			}
			return names;
		} catch( std::exception const & ) {
			spdlog::critical( "[x] Unable to read data from file" );
			return {};
		}
	}

	void print_header()
	{
		// courtesy of http://www.patorjk.com/software/taag/#p=display&f=Epic&t=FastSub
		std::string header = R"sep(
 _______  _______  _______ _________ _______           ______
(  ____ \(  ___  )(  ____ \\__   __/(  ____ \|\     /|(  ___ \
| (    \/| (   ) || (    \/   ) (   | (    \/| )   ( || (   ) )
| (__    | (___) || (_____    | |   | (_____ | |   | || (__/ / 
|  __)   |  ___  |(_____  )   | |   (_____  )| |   | ||  __ (  
| (      | (   ) |      ) |   | |         ) || |   | || (  \ \
| )      | )   ( |/\____) |   | |   /\____) || (___) || )___) )
|/       |/     \|\_______)   )_(   \_______)(_______)|/ \___/ 

)sep";
		std::printf( "%s", header.c_str() );
	}
}