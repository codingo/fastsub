#define ASIO_STANDALONE
#define ASIO_HEADER_ONLY

#include <tclap/CmdLine.h>
#include <tclap/ValueArg.h>
#include <tclap/SwitchArg.h>

#include <thread>
#include <fstream>
#include <atomic>
#include <spdlog/spdlog.h>
#include "DNSResolver.hpp"

#ifdef _MSC_VER
#pragma warning(disable : 4996)
#endif

namespace tc = TCLAP;

namespace fastsub
{
	void to_json( json& j, dns_query_result const & result )
	{
		j = json{ {"name", result.name }, {"class", result.class_}, {"record", result.record},
			{ "raw_record", result.raw_record}, {"ttl", result.ttl} };
	}

	void to_json( json& j, std::pair<std::string, std::vector<dns_query_result>> const & r )
	{
		j = json{ {"name", r.first}, { "result", json{r.second} } };
	}

	void display_progress( std::size_t const total_elements )
	{
		auto callback = [=] {
			while( true ) {
				std::this_thread::sleep_for( std::chrono::milliseconds( 100 ) );
				auto const currently_processed = Query::processed.load();
				double const percentage = ( static_cast<double>( currently_processed ) * 100.0 ) / total_elements;
				std::printf( "\r[+] Progress: %.2f%%(processed %zu of %zu)", percentage,
					currently_processed, total_elements );
				std::fflush( stdout );
				if( currently_processed == total_elements ) break;

			}
		};

		std::thread notifier_thread{ callback };
		notifier_thread.detach();
	}

	void grab_dns_record_a( command_args const & args, threadsafe_vector<std::string>& container,
		std::vector<Resolver> &resolvers, QueryResult<StringList>& query_result )
	{
		auto& io_service{ DNSResolver::GetIOService() };
		using custom_string_socket = custom_socket<std::string>;

		std::vector<custom_string_socket> socket_list{};
		std::size_t const socket_count{ std::min( args.max_sockets / args.thread_count, container.get_total() ) };
		socket_list.reserve( socket_count );
		for( std::size_t i = 0; i != socket_count; ++i ) {
			socket_list.emplace_back( custom_string_socket{ io_service, query_result, container, resolvers,
				args } );
			socket_list.back().set_callback( dns_extract_ip_addresses );
			socket_list[i].start( dns_record_type::DNS_REC_A );
		}
		io_service.run();
	}

	void grab_dns_record_others( command_args const & args, threadsafe_vector<std::string>& container,
		std::vector<Resolver> &resolvers, QueryResult<std::vector<dns_query_result>>& result_list,
		dns_record_type type )
	{
		auto& io_service{ DNSResolver::GetIOService() };
		using socket = custom_socket<dns_query_result>;
		using socket_ptr = std::shared_ptr<custom_socket<dns_query_result>>;

		std::vector<socket_ptr> socket_list{};
		std::size_t const socket_count{ std::min( args.max_sockets / args.thread_count, container.get_total() ) };
		socket_list.reserve( socket_count );
		for( std::size_t i = 0; i != socket_count; ++i ) {
			socket_list.emplace_back( std::make_shared<socket>( io_service, result_list, container,
				resolvers, args ) );
			socket_list.back()->set_callback( dns_extract_query_result );
			socket_list[i]->start( type );
		}
		io_service.run();
	}

	void generate_other_records_output( QueryResult<std::vector<dns_query_result>> const &dns_result,
		std::string const & record_type, std::string const & out_file )
	{
		auto const & query_results = dns_result.get_result();
		json result{ std::pair<std::string, decltype( query_results )>{ record_type, query_results} };
		if( out_file == "stdout" ) {
			std::cout << result.dump( 2 ) << std::endl;
		} else {
			std::ofstream out_stream{ out_file };
			out_stream << result.dump( 2 ) << std::endl;
		}
	}

	void generate_a_record_output( QueryResult<StringList> const & result, std::string const &out_file )
	{
		auto const & domain_ips = result.get_result();
		json::object_t data{};
		for( int i = 0; i != domain_ips.size(); ++i ) {
			data[domain_ips[i].name] = domain_ips[i].data;
		}
		json json_value{ data };
		if( out_file == "stdout" ) {
			std::cout << json_value.dump( 2 ) << std::endl;;
		} else {
			std::ofstream file{ out_file };
			file << json_value.dump( 2 ) << std::endl;
		}
	}

	template<typename Func, typename ...Args>
	void start_enumeration( command_args& command_args, Func func, Args&& ...args )
	{
		asio::thread_pool tpool{ command_args.thread_count };
		if( !command_args.total_silence ) {
			spdlog::info( "[+] Launching {} worker threads", command_args.thread_count );
		}
		for( std::size_t i = 0; i != command_args.thread_count; ++i ) {
			asio::post( tpool, std::bind( func, std::ref( std::forward<Args>( args ) )... ) );
		}

		std::chrono::time_point<std::chrono::system_clock> start, end;
		start = std::chrono::system_clock::now();
		tpool.join();
		end = std::chrono::system_clock::now();

		std::chrono::duration<double> elapsed_seconds = end - start;
		auto const seconds = elapsed_seconds.count();
		int minutes = seconds / 60, hours = minutes / 60;
		if( !command_args.sober ) std::putc( '\n', stdout );
		if( !command_args.total_silence ) {
			spdlog::info( "[+] Elapsed {}hr: {}min: {}sec(s)", hours, minutes % 60,
				( std::size_t )seconds % 60 );
		}
	}

	void find_dns_class_a_records( command_args& args, std::vector<Resolver>& resolvers,
		smart_pointer<FILE, file_close>& domain_file )
	{
		StringList subdomains{};
		if( !domain_file ) {
			std::string data{};
			while( std::cin >> data ) {
				subdomains.emplace_back( std::move( data ) );
			}
		} else {
			subdomains = get_domain_names( domain_file );
			domain_file.reset();
		}
		if( subdomains.empty() ) {
			spdlog::error( "[-] No domain names was found" );
			return;
		}

		for( auto& domain : args.domain_names ) {
			if( startswith( domain, "http" ) || startswith( domain, "ftp" ) ) {
				uri domain_uri{ domain };
				domain = domain_uri.host();
			}
		}

		std::size_t const total_size = ( subdomains.size() * ( args.using_word_list ? args.domain_names.size() : 1 ) )
			+ args.domain_names.size();
		std::vector<std::string> names{};
		// let's reserve enough space from the onset
		names.reserve( total_size );
		if( args.using_word_list ) {
			for( auto const & domain_name : args.domain_names ) {
				for( std::size_t i = 0; i != subdomains.size(); ++i ) {
					names.emplace_back( subdomains[i] + "." + domain_name );
				}
				names.emplace_back( std::move( domain_name ) );
			}
		} else {
			names = std::move( subdomains );
		}
		if( !args.total_silence ) {
			spdlog::info( "[+] Trying to validate {} names.", names.size() );
		}
		// at least one in 2 of those names would be valid, so reserve memory ahead 
		// to avoid constant reallocation
		QueryResult<StringList> result( total_size / 2 );
		threadsafe_vector<std::string> name_list{ std::move( names ) };
		if( args.total_silence == false && !args.sober ) display_progress( total_size );
		start_enumeration( args, grab_dns_record_a, args, name_list, resolvers, result );
		auto successful = Query::successful.load(), unsucessful = total_size + 1 - successful;
		if( !args.total_silence ) {
			spdlog::info( "[+] Successful: {}, Unsuccessful: {}.", successful, unsucessful );
			generate_a_record_output( result, args.output_file );
		}
	}

	void find_other_dns_records( command_args &args, std::vector<Resolver>& resolvers )
	{
		dns_record_type record_type = dns_str_to_record_type( args.record_type.c_str() );
		if( record_type == dns_record_type::DNS_REC_INVALID ) {
			spdlog::error( "[x] Invalid DNS record type specified" );
			return;
		}
		StringList subdomains{ parse_json_file( args.sub_domain_filename ) };
		std::size_t const total_subdomain = subdomains.size();
		if( total_subdomain == 0 ) {
			spdlog::error( "[x] Could not find subdomains to enumerate" );
			return;
		}
		if( !args.total_silence ) {
			spdlog::info( "[+] Finding {} records for {} name(s).", args.record_type, total_subdomain );
		}
		QueryResult<std::vector<dns_query_result>> result( total_subdomain );
		threadsafe_vector<std::string> names{ std::move( subdomains ) };
		if( args.total_silence == false && !args.sober ) display_progress( total_subdomain );
		start_enumeration( args, grab_dns_record_others, args, names, resolvers, result, record_type );
		auto successful = Query::successful.load(), unsucessful = total_subdomain + 1 - successful;
		if( !args.total_silence ) {
			spdlog::info( "[+] Successful: {}, Unsuccessful: {}.", successful, unsucessful );
			generate_other_records_output( result, args.record_type, args.output_file );
		}
	}

	void run_dns( command_args & args )
	{
		using fastsub::smart_pointer;
		using fastsub::file_close;
		if( !args.total_silence ) {
			if( args.output_file != "stdout" ) {
				smart_pointer<FILE, file_close> out_file{ fopen( args.output_file.c_str(), "w" ) };
				if( !out_file ) {
					spdlog::error( "[-] Unable to open `{}` for write.", args.output_file );
					return;
				}
			}
		}

		smart_pointer<FILE, file_close> domain_file{ fopen( args.sub_domain_filename.c_str(), "r" ) };
		if( args.using_word_list ) {
			if( !domain_file ) {
				spdlog::error( "[-] Unable to open the domain file" );
				return;
			}
		}
		smart_pointer<FILE, file_close> resolver_file{ fopen( args.resolver_filename.c_str(), "r" ) };
		if( !resolver_file ) {
			spdlog::error( "[-] Unable to open resolver file" );
			return;
		}

		auto resolvers{ get_dns_resolvers( resolver_file ) };

		if( resolvers.empty() ) {
			spdlog::error( "[-] No valid resolver was found" );
			return;
		}

		/*
		if( args.using_word_list && ( args.domain_names.empty() && args.record_type.empty() ) ) {
			spdlog::error( "[x] You need to specify a domain name or use -t/--type to specify a record type" );
			return;
		}
		*/

		if( args.using_word_list && args.domain_names.empty() ) {
			find_other_dns_records( args, resolvers );
		} else {
			find_dns_class_a_records( args, resolvers, domain_file );
		}
	}
}

using namespace fmt::v5::literals;

void print_header()
{
	// courtesy of http://www.patorjk.com/software/taag/#p=display&f=Epic&t=FastSub
	std::string header = R"sep(
·▄▄▄ ▄▄▄· .▄▄ · ▄▄▄▄▄.▄▄ · ▄• ▄▌▄▄▄▄· 
▐▄▄·▐█ ▀█ ▐█ ▀. •██  ▐█ ▀. █▪██▌▐█ ▀█▪
██▪ ▄█▀▀█ ▄▀▀▀█▄ ▐█.▪▄▀▀▀█▄█▌▐█▌▐█▀▀█▄
██▌.▐█ ▪▐▌▐█▄▪▐█ ▐█▌·▐█▄▪▐█▐█▄█▌██▄▪▐█
▀▀▀  ▀  ▀  ▀▀▀▀  ▀▀▀  ▀▀▀▀  ▀▀▀ ·▀▀▀▀  
Michael Skelton (@codingo_)
Luke Stephens (@hakluke)
Sajeeb Lohani (@sml555_))sep";
	spdlog::info("{}\n", header);
}

int main( int argc, char **argv )
{
	std::size_t const max_thread_count = std::thread::hardware_concurrency();

	tc::CmdLine command_line{ "fastsub -> a fast subdomain finder", ' ', "0.6-alpha" };
	tc::ValueArg<std::string> resolver_file{
		"r", "resolver", "A file containing the list of resolvers", true, "", "filename"
	};
	tc::ValueArg<std::string> sub_domain_file{
		"s", "sub-domain", "File containing a list of names(or a previously generated"
		" JSON file in case -t flag is specified)", false, "", "filename"
	};
	tc::ValueArg<int> max_retries{ "x", "retries", "Max retries(default: 10)", false, 10, "integer" };

	tc::ValueArg<std::size_t> thread_count{ "c", "threads", "Number of threads to use(default: {})"_format( max_thread_count ),
		false, max_thread_count, "integer" };
	tc::UnlabeledMultiArg<std::string> domain_name{ "domain", "a list of domain names", false, "", "names" };

	tc::ValueArg<int> timeout_ms{ "i", "timeout", "Connection timeout for a request before it is "
		"disconnected and retried(default: 3,000ms)", false, 3'000, "timeout in milliseconds" };
	tc::ValueArg<std::string> output_format{ "o", "output", "Output format{filename(json format), "
		"stdout}(default: stdout)", false, "stdout", "filename" };
	tc::ValueArg<std::string> record_type{ "t", "type", "DNS record type(e.g. CNAME, TXT, AAAA, SOA, NS, MX)",
		false, "", "string" };
	tc::SwitchArg using_word_list{ "d", "using-wordlist", "treat the -s flag as if it specifies filename with "
		"list of domain names", false };
	tc::ValueArg<unsigned int> max_socket_arg{ "", "max-socket", "set the maximum number of open sockets",
		false, 1'000, "integer" };
	tc::SwitchArg silent_arg{ "", "silent", "Mute every thing and display data to STDOUT instead", false };
	tc::SwitchArg sober{ "", "sober", "Do not display the progress made", false };

	command_line.add( resolver_file );
	command_line.add( sub_domain_file );
	command_line.add( max_retries );
	command_line.add( thread_count );
	command_line.add( timeout_ms );
	command_line.add( output_format );
	command_line.add( sober );
	command_line.add( using_word_list );
	command_line.add( domain_name );
	command_line.add( record_type );
	command_line.add( silent_arg );
	command_line.add( max_socket_arg );

	print_header();
	try {
		command_line.parse( argc, argv );
	} catch( std::exception & e ) {
		spdlog::error( e.what() );
		return -1;
	}

	fastsub::command_args cli_args{};

	cli_args.max_retries = max_retries.getValue();
	cli_args.resolver_filename = resolver_file.getValue();
	cli_args.thread_count = thread_count.getValue();
	cli_args.timeout_ms = timeout_ms.getValue();
	cli_args.output_file = output_format.getValue();
	cli_args.sub_domain_filename = sub_domain_file.getValue();
	cli_args.sober = sober.getValue();
	cli_args.using_word_list = using_word_list.getValue();
	cli_args.domain_names = domain_name.getValue();
	cli_args.record_type = record_type.getValue();
	cli_args.total_silence = silent_arg.getValue();
	cli_args.max_sockets = max_socket_arg.getValue();

	if( !cli_args.total_silence ) {
		spdlog::info( "[+] Executing program..." );
	}

	fastsub::run_dns( cli_args );
	return 0;
}
