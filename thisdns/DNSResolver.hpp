#pragma once
#define ASIO_STANDALONE
#define ASIO_HEADER_ONLY

#include <asio.hpp>
#include <chrono>
#include <string>
#include <vector>
#include <atomic>
#include <spdlog/spdlog.h>
#include "utils.hpp"
#include "dns.hpp"

namespace asio_ip = asio::ip;
using asio_ip::udp;

namespace fastsub
{
	struct Resolver
	{
		udp::endpoint endpoint;
		bool is_active;
	};

	struct Query
	{
		static std::atomic<std::size_t> processed;
		static std::atomic<std::size_t> successful;
	};

	int create_query( const char *name, int type, unsigned short id, unsigned char *bufp, int *buflenp );

	template<typename T>
	using result_callback = std::vector<T>(*)( dns_pkt_t&, uint8_t *, size_t, uint8_t* );

	template<typename T>
	class custom_socket : std::enable_shared_from_this<custom_socket<T>>
	{
		asio::io_service &io_;
		std::shared_ptr<udp::socket> udp_socket_;
		std::shared_ptr<asio::steady_timer> timer_;
		QueryResult<std::vector<T>>& result_;
		threadsafe_vector<std::string>& subdomains_;
		command_args const & args_;
		std::vector<Resolver>& dns_resolvers_;
		dns_record_type record_type{};
		result_callback<T> callback_;
		unsigned char receiver_buf[2048];
		unsigned char query_buffer[2048];
		int query_len{};
		std::string current_name;
		std::size_t retries{}, index{};
		uint16_t dns_id = rand() % 2345; // warning!!! Simply for testing purpose
	private:
		void send_data()
		{
			if( retries >= args_.max_retries ) {
				process_next_request();
				return;
			}

			++retries;
			index = 0;
			while( !dns_resolvers_[index].is_active && index < dns_resolvers_.size() ) ++index;
			if( index == dns_resolvers_.size() ) { // this should rarely(but hopefully never) happen
				std::printf( "[x] We ran out of active resolvers to use, recovering" );
				for( auto& resolver : dns_resolvers_ ) resolver.is_active = true; // make them all active again
				index = 0;
			}
			udp_socket_->async_send_to( asio::buffer( query_buffer, query_len ), dns_resolvers_[index].endpoint, 0,
				[=]( asio::error_code const & ec, std::size_t bytes_sent )
			{
				on_data_sent( ec, bytes_sent );
			});
		}

		void on_data_sent( asio::error_code const &, std::size_t )
		{
			receive_data();
		}

		void receive_data()
		{
			static udp::endpoint default_endpoint{};
			udp_socket_->async_receive_from( asio::buffer( receiver_buf, 0x200 ), default_endpoint,
				[=]( asio::error_code const & err_code, std::size_t bytes_received )
			{
				on_data_received( err_code, bytes_received );
			});
			timer_ = std::make_shared<asio::steady_timer>( io_, std::chrono::milliseconds( args_.timeout_ms ) );
			timer_->async_wait( [=]( asio::error_code const & err_code ) 
			{
				on_timer_expired( err_code );
			});
		}

		void on_data_received( asio::error_code const & ec, std::size_t bytes_received )
		{
			if( bytes_received == 0 || ec == asio::error::operation_aborted ) {
				send_data();
			} else if( !ec && bytes_received != 0 ) {
				read_result( ec, bytes_received );
			}
		}

		void on_timer_expired( asio::error_code const & error )
		{
			if( !error ) {
				udp_socket_->cancel();
				dns_resolvers_[index].is_active = false;
			}
		}

		void read_result( asio::error_code const & receiver_err, std::size_t bytes_read )
		{
			static std::size_t const sizeof_packet_header = 12;

			if( bytes_read < sizeof_packet_header || receiver_err ) {
				process_next_request();
				return;
			}

			fastsub::dns_pkt_t packet{};
			unsigned char *body_begin{}; // beginning of the answer body

			if( !fastsub::dns_parse_question( receiver_buf, bytes_read, &packet.head, &body_begin ) ) {
				process_next_request();
				return;
			}

			auto &header = packet.head.header;

			if( header.id != dns_id || header.rcode != 0 || header.rd != 1 || !header.ans_count ) {
				process_next_request();
				return;
			}
			std::vector<T> data_list{ callback_( packet, receiver_buf, bytes_read, body_begin ) };
			char const *server_response_code = dns_rcode2str( static_cast<dns_rcode>( packet.head.header.rcode ) );

			if( args_.total_silence ) {
				stdout_display_result( server_response_code, data_list );
			} else {
				result_.add_domain_data( current_name, server_response_code, std::move( data_list ) );
			}
			++Query::successful;
			std::memset( receiver_buf, 0, 0x200 );
			process_next_request();
		}

		void stdout_display_result( char const * server_rcode, std::vector<T> const & data_list )
		{
			result_.display_domain_data( current_name, record_type, server_rcode, data_list );
		}

		void process_next_request()
		{
			try {
				current_name = subdomains_.get();
				++Query::processed;
				int const result_code = create_query( current_name.c_str(),
					static_cast<uint16_t>( record_type ), dns_id, query_buffer, &query_len );

				if( result_code != 0 ) {
					return;
				}
				retries = 0;
				send_data();
			} catch( empty_container_exception const & ) {
				//spdlog::error( "[x] Jail break" );
			}
		}
	public:
		custom_socket( asio::io_service& io_service, QueryResult<std::vector<T>>& result,
			threadsafe_vector<std::string>& subdomains, std::vector<Resolver>& dns_resolvers,
			command_args const & args ) : io_{ io_service }, udp_socket_{ std::make_shared<udp::socket>( io_ ) },
			result_{ result }, subdomains_{ subdomains },
			dns_resolvers_{ dns_resolvers }, args_{ args }
		{
			udp_socket_->open( udp::v4() );
			udp_socket_->set_option( udp::socket::reuse_address( true ) );
		}

		void set_callback( result_callback<T> callback )
		{
			callback_ = callback;
		}

		void start( dns_record_type type )
		{
			record_type = type;
			process_next_request();
		}
	};


	template<typename T, typename U>
	std::vector<Resolver> get_dns_resolvers( smart_pointer<T, U>& resolver_file )
	{
		char buffer[0x200]{};
		unsigned short const port = 53;
		bool const is_active = true;
		std::vector<Resolver> endpoints{};
		while( std::fgets( buffer, sizeof( buffer ), resolver_file ) ) {
			asio::error_code ec;
			trim_end( buffer );
			auto address = asio::ip::make_address( trim_start( buffer ), ec );
			if( !ec ) endpoints.emplace_back( Resolver{ udp::endpoint{ address, port }, is_active } );
		}
		return endpoints;
	}

	struct DNSResolver
	{
		static asio::io_service& GetIOService()
		{
			static asio::io_service io{};
			return io;
		}
	};
}
