// --------------------------------------------------------------------------------
/// <summary>
/// Module Name:  ip_address.h
/// Abstract: IP address wrappers definitions
/// </summary>
// --------------------------------------------------------------------------------

#pragma once

#include <in6addr.h>
#include <ip2string.h>
#include <cassert>

#pragma comment(lib, "ntdll.lib")

#pragma warning( push )
#pragma warning( disable : 26490 ) // disable reinterpret_cast warning

namespace net
{
	// --------------------------------------------------------------------------------
	/// <summary>
	/// Wrapper for in_addr. Represents IP version 4 address.
	/// </summary>
	// --------------------------------------------------------------------------------
	struct ip_address_v4 : in_addr
	{
		/// <summary>
		/// Maximum size of IPv4 address string representation
		/// </summary>
		static constexpr size_t ipv4_address_max_length = 16;

		/// <summary>
		/// IPv4 address family
		/// </summary>
		static constexpr ADDRESS_FAMILY af_type = AF_INET;

		/// <summary>
		/// Constructs from 32 bit unsigned (by default initializes to 0.0.0.0).
		/// </summary>
		/// <param name="address">IPv4 address as unsigned 32 bit in network byte order</param>
		explicit constexpr ip_address_v4(const uint32_t address = 0) noexcept: in_addr() { S_un.S_addr = address; }

		/// <summary>
		/// Constructs object from in_addr.
		/// </summary>
		/// <param name="ip">IPv4 address as in_addr</param>
		// ReSharper disable once CppNonExplicitConvertingConstructor
		ip_address_v4(const in_addr& ip) noexcept: in_addr(ip)
		{
		}

		/// <summary>
		/// Constructs from std::string if possible to parse
		/// </summary>
		/// <param name="ip">IPv4 address represented as std::string</param>
		explicit ip_address_v4(const std::string& ip) noexcept: in_addr()
		{
			PCSTR terminator = nullptr;

			[[maybe_unused]] const auto result = RtlIpv4StringToAddressA(ip.c_str(), TRUE, &terminator, this);
		}

		/// <summary>
		/// Constructs from std::wstring if possible to parse
		/// </summary>
		/// <param name="ip">IPv4 address represented as std::wstring</param>
		explicit ip_address_v4(const std::wstring& ip) noexcept: in_addr()
		{
			LPCWSTR terminator = nullptr;

			[[maybe_unused]] const auto result = RtlIpv4StringToAddressW(ip.c_str(), TRUE, &terminator, this);
		}

		/// <summary>
		/// Converts IPv4 address to the string representation
		/// </summary>
		explicit operator std::string() const
		{
			std::vector<char> ip_vec(ipv4_address_max_length, 0);
			RtlIpv4AddressToStringA(this, &gsl::at(ip_vec, 0));

			return {&gsl::at(ip_vec, 0)};
		}

		/// <summary>
		/// Converts IPv4 address to the wide char string representation
		/// </summary>
		explicit operator std::wstring() const
		{
			std::vector<wchar_t> ip_vec(ipv4_address_max_length, 0);
			RtlIpv4AddressToStringW(this, &gsl::at(ip_vec, 0));

			return {&gsl::at(ip_vec, 0)};
		}

		/// <summary>
		/// Attempts to parse std::string and create ip_address_v4 object value
		/// </summary>
		/// <param name="ip">IPv4 address represented as std::string</param>
		/// <returns>pair of boolean and ip_address_v4, if boolean is true</returns>
		static std::pair<bool, ip_address_v4> from_string(const std::string& ip) noexcept
		{
			PCSTR terminator = nullptr;
			ip_address_v4 address{};

			[[maybe_unused]] const auto result = RtlIpv4StringToAddressA(ip.c_str(), TRUE, &terminator, &address);

			return {0 == result, address};
		}

		/// <summary>
		/// Attempts to parse std::wstring and create ip_address_v4 object value
		/// </summary>
		/// <param name="ip">IPv4 address represented as std::wstring</param>
		/// <returns>pair of boolean and ip_address_v4, if boolean is true</returns>
		static std::pair<bool, ip_address_v4> from_wstring(const std::wstring& ip) noexcept
		{
			LPCWSTR terminator = nullptr;
			ip_address_v4 address{};

			[[maybe_unused]] const auto result = RtlIpv4StringToAddressW(ip.c_str(), TRUE, &terminator, &address);

			return {0 == result, address};
		}

		/// <summary>
		/// Equality operator (compares as 32 bit unsigned in network byte order)
		/// </summary>
		/// <param name="rhs">Value reference to compare to</param>
		/// <returns>true if equal</returns>
		bool operator ==(const ip_address_v4& rhs) const noexcept { return (S_un.S_addr == rhs.S_un.S_addr); }

		/// <summary>
		/// Non-equality operator (compares as 32 bit unsigned in network byte order)
		/// </summary>
		/// <param name="rhs">Value reference to compare to</param>
		/// <returns>true if non-equal</returns>
		bool operator !=(const ip_address_v4& rhs) const noexcept { return (S_un.S_addr != rhs.S_un.S_addr); }

		/// <summary>
		/// Less operator (compares as 32 bit unsigned in network byte order)
		/// </summary>
		/// <param name="rhs">Value reference to compare to</param>
		/// <returns>true if less</returns>
		bool operator <(const ip_address_v4& rhs) const noexcept { return (S_un.S_addr < rhs.S_un.S_addr); }

		/// <summary>
		/// Checks if contains an IPv4 auto-configuration address(169.254.xxx.xxx)
		/// </summary>
		/// <returns>true if assigned IPv4 is auto-configuration address</returns>
		[[nodiscard]] bool is_auto_config() const noexcept
		{
			if (S_un.S_un_b.s_b1 == 169 && S_un.S_un_b.s_b2 == 254)
				return true;

			return false;
		}

		/// <summary>
		/// Char stream output operator
		/// </summary>
		/// <param name="os">stream instance reference</param>
		/// <param name="dt">ip_address_v4 value</param>
		/// <returns>stream instance reference</returns>
		friend std::ostream& operator<<(std::ostream& os, const ip_address_v4& dt);

		/// <summary>
		/// Wide char stream output operator
		/// </summary>
		/// <param name="os">stream instance reference</param>
		/// <param name="dt">ip_address_v4 value</param>
		/// <returns>stream instance reference</returns>
		friend std::wostream& operator<<(std::wostream& os, const ip_address_v4& dt);
	};

	inline std::ostream& operator<<(std::ostream& os, const ip_address_v4& dt)
	{
		os << std::string(dt);
		return os;
	}

	inline std::wostream& operator<<(std::wostream& os, const ip_address_v4& dt)
	{
		os << std::wstring(dt);
		return os;
	}

	// --------------------------------------------------------------------------------
	/// <summary>
	/// Wrapper for in_addr6. Represents IP version 6 address.
	/// </summary>
	// --------------------------------------------------------------------------------
	struct ip_address_v6 : in6_addr
	{
		/// <summary>
		/// Maximum size of IPv6 address string representation
		/// </summary>
		static constexpr size_t ipv6_address_max_string_length = 48;

		/// <summary>
		/// Size of IPv6 address in bytes
		/// </summary>
		static constexpr size_t ipv6_address_max_length = 16;

		/// <summary>
		/// IPv6 address family
		/// </summary>
		static constexpr ADDRESS_FAMILY af_type = AF_INET6;

		/// <summary>
		/// Constructs zero IPv6 address
		/// </summary>
		constexpr ip_address_v6() noexcept : in6_addr()
		{
			this->u.Word[0] = 0;
			this->u.Word[1] = 0;
			this->u.Word[2] = 0;
			this->u.Word[3] = 0;
			this->u.Word[4] = 0;
			this->u.Word[5] = 0;
			this->u.Word[6] = 0;
			this->u.Word[7] = 0;
		}

		/// <summary>
		/// Constructs IPv6 address from the provided byte array
		/// </summary>
		/// <param name="address">16 bytes array</param>
		explicit ip_address_v6(const uint8_t (&address)[ipv6_address_max_length]) noexcept: in6_addr()
		{
			memmove(this, address, sizeof(in_addr6));
		}

		/// <summary>
		/// Constructs IPv6 address from in_addr6
		/// </summary>
		/// <param name="ip">in_addr6 object reference</param>
		// ReSharper disable once CppNonExplicitConvertingConstructor
		ip_address_v6(const in_addr6& ip) noexcept : in6_addr(ip)
		{
		}

		/// <summary>
		/// Constructs IPv6 address from std::string representation
		/// </summary>
		/// <param name="ip">IPv6 address in string representation</param>
		explicit ip_address_v6(const std::string& ip) noexcept : in6_addr()
		{
			PCSTR terminator = nullptr;

			[[maybe_unused]] const auto result = RtlIpv6StringToAddressA(ip.c_str(), &terminator, this);

			assert(0 == result);
		}

		/// <summary>
		/// Constructs IPv6 address from std::wstring representation
		/// </summary>
		/// <param name="ip">IPv6 address in wide char string representation</param>
		explicit ip_address_v6(const std::wstring& ip) noexcept : in6_addr()
		{
			LPCWSTR terminator = nullptr;

			[[maybe_unused]] const auto result = RtlIpv6StringToAddressW(ip.c_str(), &terminator, this);

			assert(0 == result);
		}

		/// <summary>
		/// Converts IPv6 address into the string representation
		/// </summary>
		explicit operator std::string() const
		{
			std::vector<char> ip_vec(ipv6_address_max_string_length, 0);
			RtlIpv6AddressToStringA(this, &gsl::at(ip_vec, 0));

			return {&gsl::at(ip_vec, 0)};
		}

		/// <summary>
		/// Converts IPv6 address into the wide char string representation
		/// </summary>
		explicit operator std::wstring() const
		{
			std::vector<wchar_t> ip_vec(ipv6_address_max_string_length, 0);
			RtlIpv6AddressToStringW(this, &gsl::at(ip_vec, 0));

			return {&gsl::at(ip_vec, 0)};
		}

		/// <summary>
		/// Tries to parse IPv6 address string to ip_address_v6
		/// </summary>
		/// <param name="ip">IPv6 address represented as std::string</param>
		/// <returns>pair of boolean and ip_address_v6, if boolean is true</returns>
		static std::pair<bool, ip_address_v6> from_string(const std::string& ip) noexcept
		{
			PCSTR terminator = nullptr;
			ip_address_v6 address{};

			[[maybe_unused]] const auto result = RtlIpv6StringToAddressA(ip.c_str(), &terminator, &address);

			return {0 == result, address};
		}

		/// <summary>
		/// Tries to parse IPv6 address wide char string to ip_address_v6
		/// </summary>
		/// <param name="ip">IPv6 address represented as std::wstring</param>
		/// <returns>pair of boolean and ip_address_v6, if boolean is true</returns>
		static std::pair<bool, ip_address_v6> from_wstring(const std::wstring& ip) noexcept
		{
			LPCWSTR terminator = nullptr;
			ip_address_v6 address{};

			[[maybe_unused]] const auto result = RtlIpv6StringToAddressW(ip.c_str(), &terminator, &address);

			return {0 == result, address};
		}

		/// <summary>
		/// Equality operator (compares as array of bytes)
		/// </summary>
		/// <param name="rhs">Value reference to compare to</param>
		/// <returns>true if equal</returns>
		bool operator ==(const ip_address_v6& rhs) const noexcept
		{
			return !memcmp(this, &rhs, sizeof(ip_address_v6));
		}

		/// <summary>
		/// Non-equality operator (compares as array of bytes)
		/// </summary>
		/// <param name="rhs">Value reference to compare to</param>
		/// <returns>true if non-equal</returns>
		bool operator !=(const ip_address_v6& rhs) const noexcept
		{
			return memcmp(this, &rhs, sizeof(ip_address_v6));
		}

		/// <summary>
		/// Less operator (compares as array of bytes)
		/// </summary>
		/// <param name="rhs">Value reference to compare to</param>
		/// <returns>true if less</returns>
		bool operator <(const ip_address_v6& rhs) const noexcept { return (memcmp(this, &rhs, sizeof(in_addr6)) < 0); }

		/// <summary>
		/// Calculates 32 bit hash from IPv6 address
		/// </summary>
		explicit operator uint32_t() const noexcept
		{
			const auto sp = gsl::span(reinterpret_cast<const uint32_t*>(this), sizeof(*this) / sizeof(uint32_t));
			return sp[0] ^ sp[1] ^ sp[2] ^ sp[3];
		}

		/// <summary>
		/// Checks if IPv6 address is global unicast
		/// </summary>
		/// <returns>true if IPv6 address is global unicast</returns>
		[[nodiscard]] bool is_global_unicast() const noexcept
		{
			return ((u.Byte[0] & 0x3F) == u.Byte[0]);
		}

		/// <summary>
		/// Char stream output operator
		/// </summary>
		/// <param name="os">stream instance reference</param>
		/// <param name="dt">ip_address_v6 value</param>
		/// <returns>stream instance reference</returns>
		friend std::ostream& operator<<(std::ostream& os, const ip_address_v6& dt);

		/// <summary>
		/// Wide char stream output operator
		/// </summary>
		/// <param name="os">stream instance reference</param>
		/// <param name="dt">ip_address_v6 value</param>
		/// <returns>stream instance reference</returns>
		friend std::wostream& operator<<(std::wostream& os, const ip_address_v6& dt);
	};

	inline std::ostream& operator<<(std::ostream& os, const ip_address_v6& dt)
	{
		os << std::string(dt);
		return os;
	}

	inline std::wostream& operator<<(std::wostream& os, const ip_address_v6& dt)
	{
		os << std::wstring(dt);
		return os;
	}

	/// <summary>
	/// Zero value IPv4 address
	/// </summary>
	static constexpr ip_address_v4 zero_ip_address_v4;

	/// <summary>
	/// Zero value IPv6 address
	/// </summary>
	static constexpr ip_address_v6 zero_ip_address_v6;
}

namespace std
{
	/// <summary>
	/// Hash for net::ip_address_v6
	/// </summary>
	template <>
	struct hash<net::ip_address_v6>
	{
		using argument_type = net::ip_address_v6;
		using result_type = size_t;

		result_type operator()(const argument_type& ip) const noexcept
		{
			const auto h1(std::hash<uint32_t>{}(static_cast<uint32_t>(ip)));

			return h1;
		}
	};

	/// <summary>
	/// Hash for net::ip_address_v4
	/// </summary>
	template <>
	struct hash<net::ip_address_v4>
	{
		using argument_type = net::ip_address_v4;
		using result_type = size_t;

		result_type operator()(const argument_type& ip) const noexcept
		{
			const auto h1(std::hash<uint32_t>{}(ip.S_un.S_addr));

			return h1;
		}
	};
}

#pragma warning( pop )
