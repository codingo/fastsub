#pragma once

#include <string>

namespace fastsub
{
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
}