#pragma once

#include <string>
#include <fstream>
#include <vector>
#include <iostream>
#include <mutex>
#include <nlohmann_json.hpp>

using StringList = std::vector<std::string>;

namespace fastsub
{
	using json = nlohmann::json;

	struct uri
	{
		uri( const std::string& url_s );
		std::string host() const;
	private:
		void parse( const std::string& url_s );
	private:
		std::string protocol_{};
		std::string host_{};
		std::string path_{};
		std::string query_{};
	};

	struct command_args
	{
		std::string sub_domain_filename{};
		std::string resolver_filename{};
		std::vector<std::string> domain_names{};
		std::string output_file{};
		std::string record_type{};
		std::size_t thread_count{};
		std::size_t max_retries{};
		std::size_t max_sockets{};
		std::size_t timeout_ms{}; // connection timeout in milliseconds
		bool using_word_list;
		bool sober;
		bool total_silence;
	};

	struct file_close
	{
		void operator()( FILE *f ) const {
			if( f ) fclose( f );
		}
	};

	enum class dns_record_type : std::uint16_t;
	char const* dns_record_type2str( dns_record_type );

	template<typename T>
	class QueryResult
	{
		struct Result
		{
			std::string name;
			std::string server_response_code;
			T data;
		};
		std::mutex mutex_;
		std::vector<Result> results_;
	public:
		QueryResult( std::size_t const reserve_size ) : mutex_{}, results_{}
		{
			results_.reserve( reserve_size );
		}

		friend void to_json( json& j, Result const & result )
		{
			j = json{ {"name", result.name }, {"status", result.server_response_code},
			{ "data", result.data } };
		}

		auto& get_result() const {
			return results_;
		}
		void add_domain_data( std::string const & domain_name, char const *server_rcode, T && data )
		{
			std::lock_guard<std::mutex> custom_lock{ mutex_ };
			results_.emplace_back( Result{ domain_name, server_rcode, std::move( data ) } );
		}

		template<typename U>
		void display_domain_data( std::string const & current_name, dns_record_type type,
			char const *server_rcode, U const & data_list )
		{
			std::lock_guard<std::mutex> custom_lock{ mutex_ };
			std::cerr << current_name << ", [";
			if( !data_list.empty() ) {
				for( std::size_t i = 0; i < data_list.size() - 1; ++i )
					std::cerr << data_list[i] << ", ";
				std::cerr << data_list.back();
			}
			std::cerr << "], " << dns_record_type2str( type )
				<< ", " << server_rcode << "\n";
		}
	};

	struct empty_container_exception : public std::runtime_error
	{
		empty_container_exception() : std::runtime_error( "container is empty" ) {}
	};

	template<typename T>
	struct threadsafe_vector
	{
	private:
		std::mutex mutex_{};
		std::vector<T> container_;
		std::size_t const total_;
	public:
		threadsafe_vector( std::vector<T> && container ) : container_{ std::move( container ) },
			total_{ container_.size() }{
		}

		T get() {
			std::lock_guard<std::mutex> lock{ mutex_ };
			if( container_.empty() ) throw empty_container_exception{};
			T value = container_.back();
			container_.pop_back();
			return value;
		}
		std::size_t get_total() const
		{
			return total_;
		}
	};

	template<typename T, typename Deleter = std::default_delete<T>>
	class smart_pointer
	{
	private:
		T* data;
	public:
		smart_pointer() = default;
		smart_pointer( T * d ) : data( d ) {}
		smart_pointer( smart_pointer const & ) = delete;
		smart_pointer& operator=( smart_pointer const & ) = delete;
		void reset( T *p = nullptr ) {
			if( data ) Deleter{}( data );
			data = p;
		}
		operator bool() {
			return data;
		}
		operator T*( ) {
			return data;
		}
		~smart_pointer() {
			if( data ) Deleter{}( data );
		}
	};

	void print_header();
	char *trim_start( char *str );
	void trim_end( char* str );
	bool startswith( std::string const & str, std::string const & test );
	StringList split_string( std::string const & str, char const * sep );
	StringList parse_json_file( std::string const & filename );

	template<typename T, typename U>
	StringList get_domain_names( smart_pointer<T, U>& domain_file )
	{
		char buffer[0x200]{};
		StringList domains{};
		while( fgets( buffer, sizeof( buffer ), domain_file ) ) {
			trim_end( buffer );
			char const *address = trim_start( buffer );
			if( strlen( address ) == 0 ) continue;
			domains.emplace_back( address );
		}
		return domains;
	}
}