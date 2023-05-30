#pragma once

namespace iphelper
{
	// --------------------------------------------------------------------------------
	/// <summary>
	/// Represents a networking application
	/// </summary>
	// --------------------------------------------------------------------------------
	struct network_process
	{
		/// <summary>
		/// Default constructor
		/// </summary>
		network_process() = default;

		/// <summary>
		/// Constructs object instance from provided process ID, name and path
		/// </summary>
		/// <param name="id">process ID</param>
		/// <param name="name">process name</param>
		/// <param name="path">path to the executable</param>
		network_process(const unsigned long id, std::wstring name, std::wstring path) :
			id(id), name(std::move(name)), path_name(std::move(path))
		{
		}

		unsigned long id{};
		std::wstring name;
		std::wstring path_name;
	};

	// --------------------------------------------------------------------------------
	/// <summary>
	/// process_lookup class utilizes IP Helper API to match TCP/UDP network packet to local process
	/// Designed as a singleton
	/// </summary>
	/// <typeparam name="T">net::ip_address_v4 or net::ip_address_v6</typeparam>
	// --------------------------------------------------------------------------------
	template <typename T>
	class process_lookup final
	{
		/// <summary>
		/// Type to store TCP sessions
		/// </summary>
		using tcp_hashtable_t = std::unordered_map<net::ip_session<T>, std::shared_ptr<network_process>>;
		/// <summary>
		/// Type to store UDP sessions
		/// </summary>
		using udp_hashtable_t = std::unordered_map<net::ip_endpoint<T>, std::shared_ptr<network_process>>;

		/// <summary>
		/// Private constructor. Initializes current state of TCP/UDP connections.
		/// </summary>
		process_lookup()
		{
			default_process_ = std::make_shared<network_process>(0, L"SYSTEM", L"SYSTEM");

			initialize_tcp_table();
			initialize_udp_table();
		}

	public:
		/// <summary>
		/// Deleted copy constructor
		/// </summary>
		process_lookup(const process_lookup& other) = delete;
		/// <summary>
		/// deleted move constructor
		/// </summary>
		process_lookup(process_lookup&& other) noexcept = delete;
		/// <summary>
		/// Deleted copy assignment
		/// </summary>
		process_lookup& operator=(const process_lookup& other) = delete;
		/// <summary>
		/// Deleted move assignment
		/// </summary>
		process_lookup& operator=(process_lookup&& other) noexcept = delete;

	private:
		/// <summary>
		/// TCP sessions hashtable
		/// </summary>
		tcp_hashtable_t tcp_to_app_;
		/// <summary>
		/// UDP sessions hashtable
		/// </summary>
		udp_hashtable_t udp_to_app_;

		/// <summary>
		/// Lock to control access to TCP sessions hashtable
		/// </summary>
		std::shared_mutex tcp_to_app_lock_;
		/// <summary>
		/// Lock to control access to UDP sessions hashtable
		/// </summary>
		std::shared_mutex udp_to_app_lock_;
		/// <summary>
		/// Default process used when process lookup in not possible via IP Helper API
		/// Usually IP Helper API fails for system processes
		/// </summary>
		std::shared_ptr<network_process> default_process_;
		/// <summary>
		/// Memory buffer to query TCP connection tables
		/// </summary>
		std::unique_ptr<char[]> table_buffer_tcp_{};
		/// <summary>
		/// Memory buffer to query UDP connection tables
		/// </summary>
		std::unique_ptr<char[]> table_buffer_udp_{};
		/// <summary>
		/// Current size of the memory buffer to query TCP connection tables
		/// </summary>
		DWORD table_buffer_size_tcp_{0};
		/// <summary>
		/// Current size of the memory buffer to query UDP connection tables
		/// </summary>
		DWORD table_buffer_size_udp_{0};

	public:
		/// <summary>
		/// Constructs (only once) and returns process_lookup object reference
		/// </summary>
		/// <returns>process_lookup object reference</returns>
		static process_lookup& get_process_helper()
		{
			static process_lookup instance;
			return instance;
		}

		/// <summary>
		/// Default destructor
		/// </summary>
		~process_lookup() = default;

		/// <summary>
		/// Searches process by provided TCP session information
		/// </summary>
		/// <typeparam name="SetToDefault">when true and fail to lookup the process sets to default</typeparam>
		/// <param name="session">TCP session to lookup</param>
		/// <returns>shared pointer to network_process instance</returns>
		template <bool SetToDefault>
		std::shared_ptr<network_process> lookup_process_for_tcp(const net::ip_session<T>& session)
		{
			// Try to lookup in the current table
			std::shared_lock slock(tcp_to_app_lock_);

			if (auto it_first = tcp_to_app_.find(session); it_first != tcp_to_app_.end())
			{
				return it_first->second;
			}

			if constexpr (SetToDefault)
			{
				slock.unlock();

				std::unique_lock<std::shared_mutex> lock(tcp_to_app_lock_);
				tcp_to_app_[session] = default_process_;
				return default_process_;
			}
			else
			{
				return nullptr;
			}
		}

		/// <summary>
		/// Searches process by provided UDP endpoint information
		/// </summary>
		/// <typeparam name="SetToDefault">when true and fail to lookup the process sets to default</typeparam>
		/// <param name="endpoint">UDP endpoint to lookup</param>
		/// <returns>shared pointer to network_process instance</returns>
		template <bool SetToDefault>
		std::shared_ptr<network_process> lookup_process_for_udp(const net::ip_endpoint<T>& endpoint)
		{
			// UDP endpoints may have 0.0.0.0:137 form
			auto zero_ip_endpoint = endpoint;
			zero_ip_endpoint.ip = T{};

			// Try to lookup in the current table
			std::shared_lock<std::shared_mutex> slock(udp_to_app_lock_);

			if (auto it_first = udp_to_app_.find(endpoint); it_first != udp_to_app_.end())
			{
				return it_first->second;
			}
			else
			{
				// Search for 0.0.0.0:port
				it_first = udp_to_app_.find(zero_ip_endpoint);

				if (it_first != udp_to_app_.end())
				{
					return it_first->second;
				}
				if constexpr (SetToDefault)
				{
					slock.unlock();

					std::unique_lock<std::shared_mutex> lock(udp_to_app_lock_);
					udp_to_app_[endpoint] = default_process_;
					return default_process_;
				}
				else
				{
					return nullptr;
				}
			}
		}

		/// <summary>
		/// Updates TCP/UDP hash tables
		/// </summary>
		/// <param name="tcp">set to true to update TCP table</param>
		/// <param name="udp">set to true to update UDP table</param>
		/// <returns>true if successful, false if error occurred</returns>
		bool actualize(const bool tcp, const bool udp)
		{
			auto ret_tcp = true, ret_udp = true;

			if (tcp)
			{
				std::lock_guard<std::shared_mutex> lock(tcp_to_app_lock_);
				ret_tcp = initialize_tcp_table();
			}

			if (udp)
			{
				std::lock_guard<std::shared_mutex> lock(udp_to_app_lock_);
				ret_udp = initialize_udp_table();
			}

			return (ret_udp && ret_tcp);
		}

		/// <summary>
		/// Returns current TCP hash table string representation
		/// </summary>
		/// <returns>string with TCP hash table entries dumped</returns>
		std::string dump_tcp_table()
		{
			std::ostringstream oss;

			std::shared_lock<std::shared_mutex> lock(tcp_to_app_lock_);
			std::for_each(tcp_to_app_.begin(), tcp_to_app_.end(), [&oss](auto&& entry)
			{
				oss << std::string(entry.first.local.ip) << " : " << entry.first.local.port <<
					" <---> " << std::string(entry.first.remote.ip) << " : " << entry.first.remote.port <<
					" : " << entry.second->id << " : " << wstring_to_string(entry.second->name) << std::endl;
			});

			return oss.str();
		}

		/**
		* Retrieve TCP sessions that belong to a process matching a regular expression.
		*
		* @param process Regular expression pattern to match process name.
		*
		* @return A vector of ip_session objects of type T.
		*/
		std::vector<net::ip_session<T>> get_tcp_sessions_for_process(const std::wregex& process)
		{
			std::vector<net::ip_session<T>> sessions;
			std::shared_lock<std::shared_mutex> lock(tcp_to_app_lock_);
			std::for_each(tcp_to_app_.begin(), tcp_to_app_.end(), [&sessions, &process](auto&& entry)
			{
				if (std::regex_match(std::wstring(entry.second->name.begin(), entry.second->name.end()), process))
					sessions.push_back(entry.first);
			});
			return sessions;
		}

		/// <summary>
		/// Returns current UDP hash table string representation
		/// </summary>
		/// <returns>string with UDP hash table entries dumped</returns>
		std::string dump_udp_table()
		{
			std::ostringstream oss;

			std::shared_lock<std::shared_mutex> lock(udp_to_app_lock_);
			std::for_each(udp_to_app_.begin(), udp_to_app_.end(), [&oss](auto&& entry)
			{
				oss << std::string(entry.first.ip) << " : " << entry.first.port <<
					" : " << entry.second->id << " : " << wstring_to_string(entry.second->name) << std::endl;
			});

			return oss.str();
		}

	private:
		/// <summary>
		/// Convert wide char string to char string. Valid only for ASCII strings
		/// </summary>
		/// <param name="s">wide char string to convert</param>
		/// <returns></returns>
		static std::string wstring_to_string(const std::wstring& s)
		{
			std::string result;
			std::transform(s.begin(), s.end(), std::back_inserter(result),
			               [](auto&& e) { return static_cast<char>(e); });
			return result;
		}

		/// @brief Processes a TCP table entry for IPv4 and retrieves the owner module information.
		/// @details This function takes a PMIB_TCPROW_OWNER_MODULE entry for IPv4, retrieves owner module information, 
		///          and constructs a shared_ptr<network_process> object with the obtained information.
		/// @param table_entry The PMIB_TCPROW_OWNER_MODULE entry to be processed.
		/// @return A shared_ptr<network_process> object with the owner module information, or nullptr if the operation fails.
		std::shared_ptr<network_process> process_tcp_entry_v4(const PMIB_TCPROW_OWNER_MODULE table_entry) const
		{
			DWORD size = 0;
			std::shared_ptr<network_process> process_ptr(nullptr);

			if (ERROR_INSUFFICIENT_BUFFER == GetOwnerModuleFromTcpEntry(
				table_entry, TCPIP_OWNER_MODULE_INFO_BASIC, nullptr, &size))
			{
				const auto module_ptr = std::make_unique<char[]>(size);

				if (auto* info = reinterpret_cast<PTCPIP_OWNER_MODULE_BASIC_INFO>(module_ptr.get());
					GetOwnerModuleFromTcpEntry(table_entry, TCPIP_OWNER_MODULE_INFO_BASIC, info, &size) == NO_ERROR &&
					info->pModuleName && info->pModulePath)
				{
					process_ptr = std::make_shared<network_process>(table_entry->dwOwningPid, info->pModuleName,
					                                                info->pModulePath);
				}
			}

			return process_ptr;
		}

		/// @brief Processes a TCP table entry for IPv6 and retrieves the owner module information.
		/// @details This function takes a PMIB_TCP6ROW_OWNER_MODULE entry for IPv6, retrieves owner module information,
		///          and constructs a shared_ptr<network_process> object with the obtained information.
		/// @param table_entry The PMIB_TCP6ROW_OWNER_MODULE entry to be processed.
		/// @return A shared_ptr<network_process> object with the owner module information, or nullptr if the operation fails.
		std::shared_ptr<network_process> process_tcp_entry_v6(const PMIB_TCP6ROW_OWNER_MODULE table_entry) const
		{
			DWORD size = 0;
			std::shared_ptr<network_process> process_ptr(nullptr);

			if (ERROR_INSUFFICIENT_BUFFER == GetOwnerModuleFromTcp6Entry(
				table_entry, TCPIP_OWNER_MODULE_INFO_BASIC, nullptr, &size))
			{
				const auto module_ptr = std::make_unique<char[]>(size);

				if (auto* info = reinterpret_cast<PTCPIP_OWNER_MODULE_BASIC_INFO>(module_ptr.get());
					GetOwnerModuleFromTcp6Entry(table_entry, TCPIP_OWNER_MODULE_INFO_BASIC, info, &size) == NO_ERROR &&
					info->pModuleName && info->pModulePath)
				{
					process_ptr = std::make_shared<network_process>(table_entry->dwOwningPid, info->pModuleName,
					                                                info->pModulePath);
				}
			}

			return process_ptr;
		}

		/// @brief Initializes or updates the TCP hashtable by retrieving the extended TCP table for the selected IP address type.
		/// @details This function retrieves the extended TCP table and processes each entry to obtain owner module information. 
		///          It then updates the tcp_to_app_ map with the network_process information for each IP session.
		/// @returns true if successful, false otherwise.
		bool initialize_tcp_table()
		{
			try
			{
				auto table_size = table_buffer_size_tcp_;
				tcp_to_app_.clear();

				while (true)
				{
					if (const uint32_t result = ::GetExtendedTcpTable(table_buffer_tcp_.get(), &table_size, FALSE,
					                                                  T::af_type,
					                                                  TCP_TABLE_OWNER_MODULE_CONNECTIONS, 0); result ==
						ERROR_INSUFFICIENT_BUFFER)
					{
						table_size *= 2;
						table_buffer_tcp_ = std::make_unique<char[]>(table_size);
						table_buffer_size_tcp_ = table_size;
					}
					else if (result == NO_ERROR)
					{
						break;
					}
					else
					{
						return false;
					}
				}
				if constexpr (std::is_same_v<T, net::ip_address_v4>)
				{
					auto* table = reinterpret_cast<PMIB_TCPTABLE_OWNER_MODULE>(table_buffer_tcp_.get());

					for (size_t i = 0; i < table->dwNumEntries; i++)
					{
						if (auto process_ptr = process_tcp_entry_v4(&table->table[i]))
						{
							tcp_to_app_[net::ip_session<T>(T{table->table[i].dwLocalAddr},
							                               T{table->table[i].dwRemoteAddr},
							                               ntohs(static_cast<uint16_t>(table->table[i].dwLocalPort)),
							                               ntohs(static_cast<uint16_t>(table->table[i].dwRemotePort)))]
								= std::move(process_ptr);
						}
					}
				}
				else
				{
					auto* table = reinterpret_cast<PMIB_TCP6TABLE_OWNER_MODULE>(table_buffer_tcp_.get());

					for (size_t i = 0; i < table->dwNumEntries; i++)
					{
						if (auto process_ptr = process_tcp_entry_v6(&table->table[i]))
						{
							tcp_to_app_[net::ip_session<T>(T{table->table[i].ucLocalAddr},
							                               T{table->table[i].ucRemoteAddr},
							                               ntohs(static_cast<uint16_t>(table->table[i].dwLocalPort)),
							                               ntohs(static_cast<uint16_t>(table->table[i].dwRemotePort)),
							                               table->table[i].dwLocalScopeId,
							                               table->table[i].dwRemoteScopeId)] = std::move(process_ptr);
						}
					}
				}
			}
			catch (...)
			{
				return false;
			}

			return true;
		}

		/// @brief Processes an IPv4 UDP table entry
		/// @param entry An IPv4 UDP table entry
		/// @return A shared_ptr to a network_process object if successful, nullptr otherwise
		std::shared_ptr<network_process> process_udp_entry_v4(const PMIB_UDPROW_OWNER_MODULE entry) const
		{
			DWORD size = 0;
			std::shared_ptr<network_process> process_ptr(nullptr);

			if (ERROR_INSUFFICIENT_BUFFER == GetOwnerModuleFromUdpEntry(
				entry, TCPIP_OWNER_MODULE_INFO_BASIC, nullptr, &size))
			{
				const auto module_ptr = std::make_unique<char[]>(size);

				if (auto* info = reinterpret_cast<PTCPIP_OWNER_MODULE_BASIC_INFO>(module_ptr.get());
					GetOwnerModuleFromUdpEntry(entry, TCPIP_OWNER_MODULE_INFO_BASIC, info, &size) == NO_ERROR &&
					info->pModuleName && info->pModulePath)
				{
					process_ptr = std::make_shared<network_process>(entry->dwOwningPid, info->pModuleName,
					                                                info->pModulePath);
				}
			}

			return process_ptr;
		}

		/// @brief Processes an IPv6 UDP table entry
		/// @param entry An IPv6 UDP table entry
		/// @return A shared_ptr to a network_process object if successful, nullptr otherwise
		std::shared_ptr<network_process> process_udp_entry_v6(const PMIB_UDP6ROW_OWNER_MODULE entry) const
		{
			DWORD size = 0;
			std::shared_ptr<network_process> process_ptr(nullptr);

			if (ERROR_INSUFFICIENT_BUFFER == GetOwnerModuleFromUdp6Entry(
				entry, TCPIP_OWNER_MODULE_INFO_BASIC, nullptr, &size))
			{
				const auto module_ptr = std::make_unique<char[]>(size);

				if (auto* info = reinterpret_cast<PTCPIP_OWNER_MODULE_BASIC_INFO>(module_ptr.get());
					GetOwnerModuleFromUdp6Entry(entry, TCPIP_OWNER_MODULE_INFO_BASIC, info, &size) == NO_ERROR &&
					info->pModuleName && info->pModulePath)
				{
					process_ptr = std::make_shared<network_process>(entry->dwOwningPid, info->pModuleName,
					                                                info->pModulePath);
				}
			}

			return process_ptr;
		}

		/// @brief Initializes/updates UDP hashtable
		/// @details This function initializes or updates the UDP hashtable with network_process objects,
		///          mapping IP endpoints to their owner processes.
		/// @return true if successful, false otherwise
		bool initialize_udp_table()
		{
			auto table_size = table_buffer_size_udp_;
			udp_to_app_.clear();

			try
			{
				do
				{
					const uint32_t result = ::GetExtendedUdpTable(table_buffer_udp_.get(), &table_size, FALSE,
					                                              T::af_type,
					                                              UDP_TABLE_OWNER_MODULE, 0);

					if (result == ERROR_INSUFFICIENT_BUFFER)
					{
						table_size *= 2;
						table_buffer_udp_ = std::make_unique<char[]>(table_size);
						table_buffer_size_udp_ = table_size;
						continue;
					}

					if (result == NO_ERROR)
					{
						break;
					}

					return false;
				}
				while (true);

				if constexpr (std::is_same_v<T, net::ip_address_v4>)
				{
					auto* table = reinterpret_cast<PMIB_UDPTABLE_OWNER_MODULE>(table_buffer_udp_.get());

					for (size_t i = 0; i < table->dwNumEntries; i++)
					{
						if (auto process_ptr = process_udp_entry_v4(&table->table[i]))
						{
							udp_to_app_[net::ip_endpoint<T>(
								T{table->table[i].dwLocalAddr},
								ntohs(static_cast<uint16_t>(table->table[i].dwLocalPort)))] = std::move(process_ptr);
						}
					}
				}
				else
				{
					auto* table = reinterpret_cast<PMIB_UDP6TABLE_OWNER_MODULE>(table_buffer_udp_.get());

					for (size_t i = 0; i < table->dwNumEntries; i++)
					{
						if (auto process_ptr = process_udp_entry_v6(&table->table[i]))
						{
							udp_to_app_[net::ip_endpoint<T>(
								T{table->table[i].ucLocalAddr},
								ntohs(static_cast<uint16_t>(table->table[i].dwLocalPort)), 0)] = std::move(process_ptr);
						}
					}
				}
			}
			catch (...)
			{
				return false;
			}

			return true;
		}
	};
}
