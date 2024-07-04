#pragma once

namespace proxy
{
#pragma pack(push,1)
	static constexpr uint8_t socks5_protocol_version = 5;
	static constexpr uint8_t socks5_username_auth_version = 1;
	static constexpr uint8_t socks5_username_max_length = 255;

	template <uint8_t NumberOfMethods = 1>
	struct socks5_ident_req
	{
		unsigned char version = socks5_protocol_version;
		unsigned char number_of_methods = NumberOfMethods;
		unsigned char methods[NumberOfMethods]{};
	};

	struct socks5_ident_resp
	{
		unsigned char version = socks5_protocol_version;
		unsigned char method;
	};

	struct socks5_username_auth
	{
		socks5_username_auth() = default;

		socks5_username_auth(const std::string& username, const std::string& password)
		{
			if (0 == init(username, password))
				throw std::runtime_error("SOCKS5: username or password length exceeds the limits");
		}

		[[nodiscard]] uint32_t init(const std::string& username, const std::string& password)
		{
			if (username.length() > 255 || password.length() > 255)
				return 0;

			username_length = static_cast<unsigned char>(username.length());

			unsigned char* password_length_ptr = reinterpret_cast<unsigned char*>(username_reserved) + username_length;
			char* password_ptr = reinterpret_cast<char*>(password_length_ptr) + 1;

			strcpy_s(username_reserved, 255, username.c_str());

			*password_length_ptr = static_cast<unsigned char>(password.length());
			strcpy_s(password_ptr, 255, password.c_str());

			return (3 + static_cast<int>(username.length()) + static_cast<int>(password.length()));
		}

		unsigned char version = socks5_username_auth_version;
		unsigned char username_length{};
		char username_reserved[socks5_username_max_length + 1 + socks5_username_max_length]{}; // RFC 1929
	};

	template <typename T>
	struct socks5_req
	{
		unsigned char version = socks5_protocol_version;
		unsigned char cmd{};
		unsigned char reserved{};
		unsigned char address_type{};
		/*union {
			in_addr ip_v4;
				in6_addr ip_v6;
				struct {
					unsigned char domain_len;
					char domain[256];
				};
		} dest_address;*/
		T dest_address;
		unsigned short dest_port{};
	};

	template <typename T>
	struct socks5_resp
	{
		unsigned char version = socks5_protocol_version;
		unsigned char reply{};
		unsigned char reserved{};
		unsigned char address_type{};
		/*union {
			in_addr ip_v4;
			in6_addr ip_v6;
			struct {
				unsigned char domain_len;
				char domain[256];
			};
		} bind_address;*/
		T bind_address;
		unsigned short bind_port{};
	};

	template <typename T>
	struct socks5_udp_header
	{
		unsigned short reserved;
		unsigned char fragment;
		unsigned char address_type;
		/*union {
			in_addr ip_v4;
			in6_addr ip_v6;
			struct {
				unsigned char domain_len;
				char domain[256];
			};
		} dest_address;*/
		T dest_address;
		unsigned short dest_port;
	};
#pragma pack(pop)

	template <typename T>
	struct socks5_negotiate_context final : negotiate_context<T>
	{
		socks5_negotiate_context(const T& remote_address, uint16_t remote_port)
			: negotiate_context<T>(remote_address, remote_port)
		{
		}

		socks5_negotiate_context(const T& remote_srv_address, uint16_t remote_srv_port,
		                         std::optional<std::string> socks5_username, std::optional<std::string> socks5_password)
			: negotiate_context<T>(remote_srv_address, remote_srv_port),
			  socks5_username(std::move(socks5_username)),
			  socks5_password(std::move(socks5_password))
		{
		}

		socks5_negotiate_context(const T& remote_address, uint16_t remote_port,
		                         std::string socks5_username, std::string socks5_password)
			: negotiate_context<T>(remote_address, remote_port),
			  socks5_username(std::move(socks5_username)),
			  socks5_password(std::move(socks5_password))
		{
		}

		std::optional<std::string> socks5_username{std::nullopt};
		std::optional<std::string> socks5_password{std::nullopt};
	};
}
