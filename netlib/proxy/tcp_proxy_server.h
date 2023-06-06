#pragma once
namespace proxy
{
	template <typename T>
	class tcp_proxy_server
	{
	public:
		using negotiate_context_t = typename T::negotiate_context_t;
		using address_type_t = typename T::address_type_t;
		using per_io_context_t = typename T::per_io_context_t;

		using query_remote_peer_t = std::tuple<address_type_t, uint16_t, std::unique_ptr<negotiate_context_t>>(
			address_type_t, uint16_t);

	private:
		constexpr static size_t connections_array_size = 64;

		uint16_t proxy_port_;
		winsys::io_completion_port& completion_port_;
		std::function<query_remote_peer_t> query_remote_peer_;

		/// <summary>message logging function</summary>
		std::function<void(const char*)> log_printer_;
		/// <summary>logging level</summary>
		netlib::log::log_level log_level_;

		std::shared_mutex lock_;

		std::thread proxy_server_;
		std::thread check_clients_thread_;
		std::thread connect_to_remote_host_thread_;

		std::vector<std::unique_ptr<T>> proxy_sockets_;
		std::vector<std::tuple<WSAEVENT, SOCKET, SOCKET, std::unique_ptr<negotiate_context_t>>> sock_array_events_;

		std::atomic_bool end_server_{true}; // set to true on proxy termination
		SOCKET server_socket_{INVALID_SOCKET};

		ULONG_PTR completion_key_{0};

	public:
		tcp_proxy_server(const uint16_t proxy_port, winsys::io_completion_port& completion_port,
		                 const std::function<query_remote_peer_t> query_remote_peer_fn,
		                 std::function<void(const char*)> log_printer, const netlib::log::log_level log_level)
			: proxy_port_(proxy_port),
			  completion_port_(completion_port),
			  query_remote_peer_(query_remote_peer_fn),
			  log_printer_(std::move(log_printer)), log_level_(log_level)
		{
			if (!create_server_socket())
			{
				throw std::runtime_error("tcp_proxy_server: failed to create server socket.");
			}
		}

		~tcp_proxy_server()
		{
			if (server_socket_ != INVALID_SOCKET)
			{
				shutdown(server_socket_, SD_BOTH);
				closesocket(server_socket_);
				server_socket_ = INVALID_SOCKET;
			}

			if (end_server_ == false)
				stop();
		}

		tcp_proxy_server(const tcp_proxy_server& other) = delete;

		tcp_proxy_server(tcp_proxy_server&& other) noexcept = delete;

		tcp_proxy_server& operator=(const tcp_proxy_server& other) = delete;

		tcp_proxy_server& operator=(tcp_proxy_server&& other) noexcept = delete;

		[[nodiscard]] uint16_t proxy_port() const
		{
			return proxy_port_;
		}

		bool start()
		{
			if (end_server_ == false)
			{
				// already running
				return true;
			}

			end_server_ = false;

			sock_array_events_.reserve(connections_array_size);

			sock_array_events_.push_back(std::make_tuple(WSACreateEvent(),
			                                             WSASocket(address_type_t::af_type, SOCK_STREAM,
			                                                       IPPROTO_TCP, nullptr, 0,
			                                                       WSA_FLAG_OVERLAPPED), INVALID_SOCKET, nullptr));

			if (std::get<1>(sock_array_events_[0]) != INVALID_SOCKET)
			{
				auto [success, io_key] = completion_port_.associate_socket(
					std::get<1>(sock_array_events_[0]),
					[this](const DWORD num_bytes, OVERLAPPED* povlp, const BOOL status)
					{
						if (end_server_)
							return false;

						auto io_context = static_cast<per_io_context_t*>(povlp);

						if (!status || (status && (num_bytes == 0)))
						{
							if ((io_context->io_operation == proxy_io_operation::relay_io_read) ||
								(io_context->io_operation == proxy_io_operation::negotiate_io_read))
							{
								io_context->proxy_socket_ptr->close_client(true, io_context->is_local);
								return false;
							}

							if (!status)
							{
								io_context->proxy_socket_ptr->close_client(false, io_context->is_local);
								return false;
							}
						}

						switch (io_context->io_operation)
						{
						case proxy_io_operation::relay_io_read:
							io_context->proxy_socket_ptr->process_receive_buffer_complete(num_bytes, io_context);
							break;

						case proxy_io_operation::relay_io_write:
							io_context->proxy_socket_ptr->process_send_buffer_complete(num_bytes, io_context);
							break;

						case proxy_io_operation::negotiate_io_read:
							io_context->proxy_socket_ptr->process_receive_negotiate_complete(num_bytes, io_context);
							break;

						case proxy_io_operation::negotiate_io_write:
							io_context->proxy_socket_ptr->process_send_negotiate_complete(num_bytes, io_context);
							break;

						case proxy_io_operation::inject_io_write:
							T::process_inject_buffer_complete(io_context);
							break;
						default: break; // NOLINT(clang-diagnostic-covered-switch-default)
						}

						return true;
					});

				if (success == true)
				{
					completion_key_ = io_key;
				}
				else
				{
					if (std::get<0>(sock_array_events_[0]) != INVALID_HANDLE_VALUE)
					{
						WSACloseEvent(std::get<0>(sock_array_events_[0]));
					}

					if (std::get<1>(sock_array_events_[0]) != INVALID_SOCKET)
					{
						closesocket(std::get<1>(sock_array_events_[0]));
					}

					sock_array_events_.clear();
					end_server_ = true;
					return false;
				}
			}

			proxy_server_ = std::thread(&tcp_proxy_server<T>::start_proxy_thread, this);
			check_clients_thread_ = std::thread(&tcp_proxy_server<T>::clear_thread, this);
			connect_to_remote_host_thread_ = std::thread(&tcp_proxy_server<T>::connect_to_remote_host_thread, this);

			return true;
		}

		void stop()
		{
			if (end_server_ == true)
			{
				// already stopped
				return;
			}

			end_server_ = true;

			closesocket(server_socket_);
			server_socket_ = INVALID_SOCKET;

			{
				std::shared_lock<std::shared_mutex> lock(lock_);
				::WSASetEvent(std::get<0>(sock_array_events_[0]));
			}

			if (proxy_server_.joinable())
			{
				proxy_server_.join();
			}

			if (check_clients_thread_.joinable())
			{
				check_clients_thread_.join();
			}

			if (connect_to_remote_host_thread_.joinable())
			{
				connect_to_remote_host_thread_.join();
			}

			if (!sock_array_events_.empty())
			{
				sock_array_events_.clear();
			}

			if (!proxy_sockets_.empty())
			{
				proxy_sockets_.clear();
			}
		}

		std::vector<negotiate_context_t> query_current_sessions_ctx()
		{
			std::shared_lock lock(lock_);
			std::vector<negotiate_context_t> result;
			result.reserve(proxy_sockets_.size());

			std::transform(proxy_sockets_.cbegin(), proxy_sockets_.cend(), std::back_inserter(result), [](auto&& e)
			{
				return *reinterpret_cast<negotiate_context_t*>(e->get_negotiate_ctx());
			});

			return result;
		}

	private:
		// ********************************************************************************
		/// <summary>
		/// Queries remote host information for outgoing connection by locally accepted socket
		/// </summary>
		/// <param name="accepted">locally accepted TCP socket</param>
		/// <returns>tuple of information required to connect to the remote peer</returns>
		// ********************************************************************************
		std::tuple<address_type_t, uint16_t, std::unique_ptr<negotiate_context_t>> get_remote_peer(
			const SOCKET accepted) const
		{
			SOCKADDR_STORAGE name;
			int len = sizeof(SOCKADDR_STORAGE);

			if (!getpeername(accepted, reinterpret_cast<sockaddr*>(&name), &len))
			{
				uint16_t accepted_peer_port = 0;
				address_type_t accepted_peer_address{};

				if constexpr (address_type_t::af_type == AF_INET)
				{
					accepted_peer_port = ntohs(reinterpret_cast<sockaddr_in*>(&name)->sin_port);
					accepted_peer_address = address_type_t(reinterpret_cast<sockaddr_in*>(&name)->sin_addr);
				}
				else if constexpr (address_type_t::af_type == AF_INET6)
				{
					accepted_peer_port = ntohs(reinterpret_cast<sockaddr_in6*>(&name)->sin6_port);
					accepted_peer_address = address_type_t(reinterpret_cast<sockaddr_in6*>(&name)->sin6_addr);
				}
				else
				{
					static_assert(false_v<T>, "Unsupported address family used as a template parameter!");
				}

				if (query_remote_peer_)
				{
					return query_remote_peer_(accepted_peer_address, accepted_peer_port);
				}
			}
			else
			{
				return std::make_tuple(address_type_t{}, 0, nullptr);
			}

			return std::make_tuple(address_type_t{}, 0, nullptr);
		}

		bool create_server_socket()
		{
			server_socket_ = WSASocket(address_type_t::af_type, SOCK_STREAM, IPPROTO_TCP, nullptr, 0,
			                           WSA_FLAG_OVERLAPPED);

			if (server_socket_ == INVALID_SOCKET)
			{
				return false;
			}

			if constexpr (address_type_t::af_type == AF_INET)
			{
				sockaddr_in service{};
				service.sin_family = address_type_t::af_type;
				service.sin_addr.s_addr = INADDR_ANY;
				service.sin_port = htons(proxy_port_);

				if (const auto status = bind(server_socket_, reinterpret_cast<SOCKADDR*>(&service), sizeof(service));
					status == SOCKET_ERROR)
				{
					closesocket(server_socket_);
					server_socket_ = INVALID_SOCKET;
					return false;
				}

				if (proxy_port_ == 0)
				{
					int name_length = sizeof(service);
					if (0 == getsockname(server_socket_, reinterpret_cast<SOCKADDR*>(&service), &name_length))
					{
						proxy_port_ = ntohs(service.sin_port);
					}
					else
					{
						closesocket(server_socket_);
						server_socket_ = INVALID_SOCKET;
						return false;
					}
				}
			}
			else
			{
				sockaddr_in6 service{};
				service.sin6_family = address_type_t::af_type;
				service.sin6_addr = in6addr_any;
				service.sin6_port = htons(proxy_port_);

				if (const auto status = bind(server_socket_, reinterpret_cast<SOCKADDR*>(&service), sizeof(service));
					status == SOCKET_ERROR)
				{
					closesocket(server_socket_);
					server_socket_ = INVALID_SOCKET;
					return false;
				}

				if (proxy_port_ == 0)
				{
					int name_length = sizeof(service);
					if (0 == getsockname(server_socket_, reinterpret_cast<SOCKADDR*>(&service), &name_length))
					{
						proxy_port_ = ntohs(service.sin6_port);
					}
					else
					{
						closesocket(server_socket_);
						server_socket_ = INVALID_SOCKET;
						return false;
					}
				}
			}

			if (const auto status = listen(server_socket_, SOMAXCONN); status == SOCKET_ERROR)
			{
				closesocket(server_socket_);
				server_socket_ = INVALID_SOCKET;
				return false;
			}

			return true;
		}

		bool connect_to_remote_host(SOCKET accepted)
		{
			auto [remote_ip, remote_port, negotiate_ctx] = get_remote_peer(accepted);

			if (!remote_port)
				return false;

			if (log_level_ > netlib::log::log_level::debug)
				log_printer(std::string("connect_to_remote_host:  ") + std::string{remote_ip} + " : " +
					std::to_string(remote_port));

			auto remote_socket = WSASocket(address_type_t::af_type, SOCK_STREAM, IPPROTO_TCP, nullptr, 0,
			                               WSA_FLAG_OVERLAPPED);

			if (remote_socket == INVALID_SOCKET)
			{
				return false;
			}

			if constexpr (address_type_t::af_type == AF_INET)
			{
				sockaddr_in sa_local{};
				sa_local.sin_family = address_type_t::af_type;
				sa_local.sin_port = htons(0);
				sa_local.sin_addr.s_addr = htonl(INADDR_ANY);

				// bind socket's name
				const auto status = bind(remote_socket, reinterpret_cast<sockaddr*>(&sa_local), sizeof(sockaddr));

				if (status == SOCKET_ERROR)
				{
					shutdown(remote_socket, SD_BOTH);
					closesocket(remote_socket);

					return false;
				}
			}
			else
			{
				sockaddr_in6 sa_local{};
				sa_local.sin6_family = address_type_t::af_type;
				sa_local.sin6_port = htons(0);
				sa_local.sin6_addr = in6addr_any;

				// bind socket's name
				const auto status = bind(remote_socket, reinterpret_cast<sockaddr*>(&sa_local), sizeof(sockaddr));

				if (status == SOCKET_ERROR)
				{
					shutdown(remote_socket, SD_BOTH);
					closesocket(remote_socket);

					return false;
				}
			}

			// enable non-blocking mode
			u_long mode = 1;
			auto ret = ioctlsocket(remote_socket, FIONBIO, &mode);

			// The client_service structure specifies the address family,
			// IP address, and port of the server to be connected to.
			{
				std::lock_guard lock(lock_);

				sock_array_events_.push_back(
					std::make_tuple(WSACreateEvent(), accepted, remote_socket, std::move(negotiate_ctx)));

				WSAEventSelect(remote_socket, std::get<0>(sock_array_events_.back()), FD_CONNECT);

				WSASetEvent(std::get<0>(sock_array_events_[0]));
			}

			// connect to server
			if constexpr (address_type_t::af_type == AF_INET)
			{
				sockaddr_in sa_service{};
				sa_service.sin_family = address_type_t::af_type;
				sa_service.sin_addr = remote_ip;
				sa_service.sin_port = htons(remote_port);

				if (connect(remote_socket, reinterpret_cast<SOCKADDR*>(&sa_service), sizeof(sa_service)) ==
					SOCKET_ERROR)
				{
					if (WSAGetLastError() != WSAEWOULDBLOCK)
					{
						shutdown(remote_socket, SD_BOTH);
						closesocket(remote_socket);

						return false;
					}
				}
			}
			else
			{
				sockaddr_in6 sa_service{};
				sa_service.sin6_family = address_type_t::af_type;
				sa_service.sin6_addr = remote_ip;
				sa_service.sin6_port = htons(remote_port);

				if (connect(remote_socket, reinterpret_cast<SOCKADDR*>(&sa_service), sizeof(sa_service)) ==
					SOCKET_ERROR)
				{
					if (WSAGetLastError() != WSAEWOULDBLOCK)
					{
						shutdown(remote_socket, SD_BOTH);
						closesocket(remote_socket);

						return false;
					}
				}
			}

			return true;
		}

		void start_proxy_thread()
		{
			while (end_server_ == false)
			{
				//
				// loop accepting connections from clients until proxy shuts down
				//
				const auto accepted = WSAAccept(server_socket_, nullptr, nullptr, nullptr, 0);

				if ((accepted == static_cast<UINT_PTR>(SOCKET_ERROR)) || end_server_)
				{
					break;
				}

				if (const auto connected = connect_to_remote_host(accepted); !connected)
				{
					closesocket(accepted);
				}
			}
		}

		void connect_to_remote_host_thread()
		{
			std::vector<WSAEVENT> wait_events;
			wait_events.reserve(connections_array_size);

			while (end_server_ == false)
			{
				// initialize wait events array
				wait_events.clear();

				{
					std::shared_lock lock(lock_);

					std::transform(sock_array_events_.cbegin(), sock_array_events_.cend(),
					               std::back_inserter(wait_events), [](auto&& e)
					               {
						               return std::get<0>(e);
					               });
				}

				const auto event_index = wait_for_multiple_objects(static_cast<DWORD>(wait_events.size()),
				                                                  wait_events.data(), INFINITE);

				if (end_server_ == true)
					break;

				if (event_index != 0)
				{
					std::lock_guard<std::shared_mutex> lock(lock_);

					WSACloseEvent(wait_events[event_index]);

					proxy_sockets_.push_back(std::make_unique<T>(
						std::get<1>(sock_array_events_[event_index]),
						std::get<2>(sock_array_events_[event_index]),
						std::move(std::get<3>(sock_array_events_[event_index])),
						log_printer_, log_level_));

					proxy_sockets_.back()->associate_to_completion_port(completion_key_, completion_port_);
					proxy_sockets_.back()->start();

					sock_array_events_.erase(sock_array_events_.begin() + event_index);
				}
				else
				{
					WSAResetEvent(wait_events[event_index]);
				}
			}

			// cleanup on exit
			std::shared_lock lock(lock_);

			for (auto&& a : sock_array_events_)
			{
				if (std::get<0>(a) != INVALID_HANDLE_VALUE)
				{
					WSACloseEvent(std::get<0>(a));
				}

				if (std::get<1>(a) != INVALID_SOCKET)
				{
					shutdown(std::get<1>(a), SD_BOTH);
					closesocket(std::get<1>(a));
					std::get<1>(a) = INVALID_SOCKET;
				}

				if (std::get<2>(a) != INVALID_SOCKET)
				{
					shutdown(std::get<2>(a), SD_BOTH);
					closesocket(std::get<2>(a));
					std::get<2>(a) = INVALID_SOCKET;
				}
			}
		}

		void clear_thread()
		{
			while (end_server_ == false)
			{
				{
					std::lock_guard lock(lock_);

					proxy_sockets_.erase(std::remove_if(proxy_sockets_.begin(), proxy_sockets_.end(), [](auto&& a)
					{
						return a->is_ready_for_removal();
					}), proxy_sockets_.end());
				}

				using namespace std::chrono_literals;
				std::this_thread::sleep_for(1000ms);
			}
		}

		void log_printer(const std::string& message) const
		{
			if (log_printer_)
			{
				log_printer_((std::string("tcp_proxy_server: ") + message).c_str());
			}
		}

		/**
		 * Function that waits for multiple objects (e.g. threads or processes)
		 * @param count Number of objects to wait for
		 * @param handles Array of handles to the objects
		 * @param ms Maximum time to wait for, in milliseconds
		 * @return WAIT_OBJECT_0 if the function succeeds, WAIT_TIMEOUT if the function times out
		 */
		static DWORD wait_for_multiple_objects(const DWORD count, const HANDLE* handles, const DWORD ms)
		{
			// Thread local seed for rand_r
			static thread_local auto seed = static_cast<uint32_t>(time(nullptr));

			// Initial result set to timeout
			DWORD result = WAIT_TIMEOUT;

			// If the number of objects is greater than the maximum allowed...
			if (count >= MAXIMUM_WAIT_OBJECTS)
			{
				// Loop until a handle is signaled or until the timeout is reached if timeout is infinite
				do
				{
					// Divide the number of handles in half
					const DWORD split = count / 2;

					// Divide the wait time in half, if timeout is infinite, use a default wait time of 2000ms
					const DWORD wait = (ms == INFINITE ? 2000 : ms) / 2;
					const int random = rand_s(&seed);

					// Recurse on both halves in a random order until a handle is signaled or all handles are checked
					for (short branch = 0; branch < 2 && result == WAIT_TIMEOUT; branch++)
					{
						if (random % 2 == branch)
						{
							// Wait for the lower half of handles
							result = wait_for_multiple_objects(split, handles, wait);
						}
						else
						{
							// Wait for the upper half of handles, adjust result if a handle is signaled
							result = wait_for_multiple_objects(count - split, handles + split, wait);
							if (result >= WAIT_OBJECT_0 && result < WAIT_OBJECT_0 + split) result += split;
						}
					}
				} while (ms == INFINITE && result == WAIT_TIMEOUT);
			}
			else
			{
				// If the number of handles is within limit, use the native win32 function
				result = ::WaitForMultipleObjects(count, handles, FALSE, ms);
			}

			// Return the result
			return result;
		}

	};
}
