#pragma once

namespace net
{
	// --------------------------------------------------------------------------------
	/// <summary>
	/// Represents IPv4 TCP/UDP endpoint
	/// </summary>
	/// <typeparam name="T">net::ip_address_v4 or net::ip_address_v6</typeparam>
	// --------------------------------------------------------------------------------
	template <typename T>
	struct ip_endpoint
	{
		/// <summary>
		/// Default constructor
		/// </summary>
		ip_endpoint() = default;

		/// <summary>
		/// Constructs endpoint from provided IP address and port
		/// </summary>
		/// <param name="ip">IP address</param>
		/// <param name="port">TCP/UDP port number</param>
		/// <param name="scope">interface scope ID</param>
		ip_endpoint(const T& ip, const unsigned short port,
		            const std::optional<uint32_t> scope = std::nullopt) : ip(ip), port(port)
		{
			if (scope)
			{
				scope_id = scope;
			}
		}

		/// <summary>
		/// Returns endpoint IP address as string
		/// </summary>
		/// <returns>endpoint IP address as string</returns>
		[[nodiscard]] std::string ip_to_string() const noexcept { return std::string(ip); }

		/// <summary>
		/// Returns endpoint port as string
		/// </summary>
		/// <returns>endpoint port as string</returns>
		[[nodiscard]] std::string port_to_string() const noexcept { return std::to_string(port); }

		/// <summary>
		/// Returns endpoint as string (e.g. '192.168.1.1:443')
		/// </summary>
		/// <returns>endpoint as string</returns>
		[[nodiscard]] std::string to_string() const noexcept { return ip_to_string() + ":" + port_to_string(); }

		/// <summary>
		/// Equality operator
		/// </summary>
		/// <param name="rhs">endpoint to compare to</param>
		/// <returns>true if endpoints are equal</returns>
		bool operator ==(const ip_endpoint& rhs) const noexcept
		{
			return (ip == rhs.ip) && (port == rhs.port) && (scope_id == rhs.scope_id);
		}

		/// <summary>
		/// Non-equality operator
		/// </summary>
		/// <param name="rhs">endpoint to compare to</param>
		/// <returns>true if endpoints are not equal</returns>
		bool operator !=(const ip_endpoint& rhs) const
		{
			return (ip != rhs.ip) || (port != rhs.port) || (scope_id != rhs.scope_id);
		}

		/// <summary>
		/// Endpoint IP address
		/// </summary>
		T ip;

		/// <summary>
		/// Endpoint port value
		/// </summary>
		uint16_t port{0};

		/// <summary>
		/// Optional interface scope ID
		/// </summary>
		std::optional<uint32_t> scope_id;
	};

	// --------------------------------------------------------------------------------
	/// <summary>
	/// Represents IPv4 TCP/UDP session
	/// </summary>
	/// <typeparam name="T">net::ip_address_v4 or net::ip_address_v6</typeparam>
	// --------------------------------------------------------------------------------
	template <typename T>
	struct ip_session
	{
		/// <summary>
		/// Constructs object from provided local and remote IP addresses and ports
		/// </summary>
		/// <param name="local_ip">local IP address</param>
		/// <param name="remote_ip">remote IP address</param>
		/// <param name="local_port">local port</param>
		/// <param name="remote_port">remote port</param>
		/// <param name="local_scope">local scope ID</param>
		/// <param name="remote_scope">remote scope ID</param>
		ip_session(
			const T& local_ip,
			const T& remote_ip,
			const unsigned short local_port,
			const unsigned short remote_port,
			const std::optional<uint32_t> local_scope = std::nullopt,
			const std::optional<uint32_t> remote_scope = std::nullopt) :
			local(local_ip, local_port, local_scope),
			remote(remote_ip, remote_port, remote_scope)
		{
		}

		/// <summary>
		/// Constructs object from provided local and remote endpoints
		/// </summary>
		/// <param name="local_endpoint">local endpoint</param>
		/// <param name="remote_endpoint">remote endpoint</param>
		ip_session(
			const ip_endpoint<T>& local_endpoint,
			const ip_endpoint<T>& remote_endpoint) :
			local{local_endpoint},
			remote{remote_endpoint}
		{
		}

		/// <summary>
		/// Equality operator for ip_session
		/// </summary>
		/// <param name="rhs">ip_session to compare to</param>
		/// <returns>true if endpoints are equal</returns>
		bool operator ==(const ip_session& rhs) const noexcept
		{
			return (local == rhs.local) && (remote == rhs.remote);
		}

		/// <summary>
		/// Non-equality operator for ip_session
		/// </summary>
		/// <param name="rhs">ip_session to compare to</param>
		/// <returns>true if endpoints are not equal</returns>
		bool operator !=(const ip_session& rhs) const { return (local != rhs.local) || (remote != rhs.remote); }

		/// <summary>
		/// Local endpoint
		/// </summary>
		ip_endpoint<T> local;

		/// <summary>
		/// Remote endpoint
		/// </summary>
		ip_endpoint<T> remote;
	};
}

namespace std
{
	/// <summary>
	/// Hash function for ip_endpoint
	/// </summary>
	/// <typeparam name="T">net::ip_address_v4 or net::ip_address_v6</typeparam>
	template <typename T>
	struct hash<net::ip_endpoint<T>>  // NOLINT(cert-dcl58-cpp)
	{
		using argument_type = net::ip_endpoint<T>;
		using result_type = std::size_t;

		result_type operator()(const argument_type& endpoint) const noexcept
		{
			const auto h1(std::hash<std::size_t>{}(
				std::hash<T>{}(endpoint.ip) ^
				static_cast<unsigned long>(endpoint.port) ^
				std::hash<std::optional<uint32_t>>{}(endpoint.scope_id.value_or(0))
			));

			return h1;
		}
	};

	/// <summary>
	/// Hash for ip_session
	/// </summary>
	/// <typeparam name="T">net::ip_address_v4 or net::ip_address_v6</typeparam>
	template <typename T>
	struct hash<net::ip_session<T>>  // NOLINT(cert-dcl58-cpp)
	{
		using argument_type = net::ip_session<T>;
		using result_type = std::size_t;

		result_type operator()(const argument_type& endpoint) const noexcept
		{
			const auto h1(std::hash<std::size_t>{}(
				std::hash<net::ip_endpoint<T>>{}(endpoint.local) ^
				static_cast<unsigned long>(endpoint.local.port) ^
				std::hash<net::ip_endpoint<T>>{}(endpoint.remote) ^
				static_cast<unsigned long>(endpoint.remote.port) ^
				std::hash<std::optional<uint32_t>>{}(endpoint.local.scope_id.value_or(0)) ^
				std::hash<std::optional<uint32_t>>{}(endpoint.remote.scope_id.value_or(0))
			));

			return h1;
		}
	};
}
