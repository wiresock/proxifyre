#pragma once

namespace proxy
{
	template <typename T>
	class socks5_local_udp_proxy_server
	{
	public:
		using negotiate_context_t = typename T::negotiate_context_t;
		using address_type_t = typename T::address_type_t;
		using per_io_context_t = typename T::per_io_context_t;

		using query_remote_peer_t = std::tuple<address_type_t, uint16_t, std::unique_ptr<negotiate_context_t>>(
			address_type_t, uint16_t);

	private:
		constexpr static size_t connections_array_size = 64;

		std::mutex lock_;

		std::thread proxy_server_;
		std::thread check_clients_thread_;

		std::map<uint16_t, std::unique_ptr<T>> proxy_sockets_;

		std::atomic_bool end_server_{true}; // set to true on proxy termination
		SOCKET server_socket_{INVALID_SOCKET};

		packet_pool packet_pool_{};

		std::array<char, T::send_receive_buffer_size> server_receive_buffer_{};
		WSABUF server_recv_buf_{static_cast<ULONG>(server_receive_buffer_.size()), server_receive_buffer_.data()};
		per_io_context_t server_io_context_{proxy_io_operation::relay_io_read, nullptr, true};
		SOCKADDR_STORAGE recv_from_sa_{};
		INT recv_from_sa_size_{sizeof(SOCKADDR_STORAGE)};

		uint16_t proxy_port_;
		winsys::io_completion_port& completion_port_;
		ULONG_PTR completion_key_{0};
		std::function<query_remote_peer_t> query_remote_peer_;
		/// <summary>message logging function</summary>
		std::function<void(const char*)> log_printer_;
		/// <summary>logging level</summary>
		netlib::log::log_level log_level_;

	public:
		socks5_local_udp_proxy_server(const uint16_t proxy_port, winsys::io_completion_port& completion_port,
		                              const std::function<query_remote_peer_t> query_remote_peer_fn,
		                              std::function<void(const char*)> log_printer,
		                              const netlib::log::log_level log_level)
			: proxy_port_(proxy_port),
			  completion_port_(completion_port),
			  query_remote_peer_(query_remote_peer_fn),
			  log_printer_(std::move(log_printer)), log_level_(log_level)
		{
			if (!create_server_socket())
			{
				throw std::runtime_error("socks5_local_udp_proxy_server: failed to create server socket.");
			}
		}

		~socks5_local_udp_proxy_server()
		{
			if (server_socket_ != INVALID_SOCKET)
			{
				closesocket(server_socket_);
				server_socket_ = INVALID_SOCKET;
			}

			if (end_server_ == false)
				stop();
		}

		socks5_local_udp_proxy_server(const socks5_local_udp_proxy_server& other) = delete;

		socks5_local_udp_proxy_server(socks5_local_udp_proxy_server&& other) noexcept = delete;

		socks5_local_udp_proxy_server& operator=(const socks5_local_udp_proxy_server& other) = delete;

		socks5_local_udp_proxy_server& operator=(socks5_local_udp_proxy_server&& other) noexcept = delete;

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

			if (server_socket_ != INVALID_SOCKET)
			{
				if (auto [status, io_key] = completion_port_.associate_socket(
					server_socket_,
					[this](const DWORD num_bytes, OVERLAPPED* povlp, const BOOL status)
					{
						auto result = true;
						auto server_read = false;

						if (end_server_)
							return false;

						std::lock_guard lock(lock_);

						auto io_context = static_cast<per_io_context_t*>(povlp);

						//if ((io_context->is_local == true) && (io_context->io_operation == proxy_io_operation::relay_io_read))
						if (io_context == &server_io_context_)
						{
							// Server socket read operation complete
							server_read = true;

							if (status && num_bytes)
							{
								do
								{
									if (false == connect_to_remote_host(io_context))
									{
										result = false;
										break;
									}

									io_context->wsa_buf = packet_pool_.allocate(num_bytes);

									if (!io_context->wsa_buf)
									{
										result = false;
										break;
									}

									io_context->wsa_buf->len = num_bytes;
									memmove(io_context->wsa_buf->buf, server_receive_buffer_.data(), num_bytes);
								}
								while (false);
							}
						}

						if (status && result)
						{
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
								T::process_inject_buffer_complete(packet_pool_, io_context);
								break;

							default: break; // NOLINT(clang-diagnostic-covered-switch-default)
							}
						}

						if (server_read)
						{
							DWORD flags = 0;

							if ((::WSARecvFrom(
								server_socket_,
								&server_recv_buf_,
								1,
								nullptr,
								&flags,
								reinterpret_cast<sockaddr*>(&recv_from_sa_),
								&recv_from_sa_size_,
								&server_io_context_,
								nullptr) == SOCKET_ERROR) && (ERROR_IO_PENDING != WSAGetLastError()))
							{
								result = false;
							}
						}

						return result;
					}); status == true)
				{
					completion_key_ = io_key;
					DWORD flags = 0;

					if ((::WSARecvFrom(
						server_socket_,
						&server_recv_buf_,
						1,
						nullptr,
						&flags,
						reinterpret_cast<sockaddr*>(&recv_from_sa_),
						&recv_from_sa_size_,
						&server_io_context_,
						nullptr) == SOCKET_ERROR) && (ERROR_IO_PENDING != WSAGetLastError()))
					{
						closesocket(server_socket_);
						end_server_ = false;
						return false;
					}
				}
				else
				{
					if (server_socket_ != INVALID_SOCKET)
					{
						closesocket(server_socket_);
					}

					end_server_ = false;
					return false;
				}
			}

			check_clients_thread_ = std::thread(&socks5_local_udp_proxy_server<T>::clear_thread, this);

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

			if (proxy_server_.joinable())
			{
				proxy_server_.join();
			}

			if (check_clients_thread_.joinable())
			{
				check_clients_thread_.join();
			}

			if (!proxy_sockets_.empty())
			{
				proxy_sockets_.clear();
			}
		}

	private:
		// ********************************************************************************
		/// <summary>
		/// Queries remote host information for outgoing connection by local peer IP address 
		/// and port 
		/// </summary>
		/// <param name="accepted_peer_address">IP address</param>
		/// <param name="accepted_peer_port">UDP port</param>
		/// <returns>tuple of information required to connect to the remote peer</returns>
		// ********************************************************************************
		std::tuple<address_type_t, uint16_t, std::unique_ptr<negotiate_context_t>> get_remote_peer(
			address_type_t accepted_peer_address, unsigned short accepted_peer_port) const
		{
			if (query_remote_peer_)
			{
				return query_remote_peer_(accepted_peer_address, accepted_peer_port);
			}

			return std::make_tuple(address_type_t{}, 0, nullptr);
		}

		bool create_server_socket()
		{
			server_socket_ = WSASocket(address_type_t::af_type, SOCK_DGRAM, IPPROTO_UDP, nullptr, 0,
			                           WSA_FLAG_OVERLAPPED);

			if (server_socket_ == INVALID_SOCKET)
			{
				return false;
			}

			if constexpr (address_type_t::af_type == AF_INET)
			{
				sockaddr_in service{address_type_t::af_type, htons(proxy_port_), INADDR_ANY};
				// NOLINT(clang-diagnostic-missing-field-initializers)

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
				sockaddr_in6 service{address_type_t::af_type, htons(proxy_port_), 0, in6addr_any};

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

			return true;
		}

		SOCKET connect_to_socks5_proxy(address_type_t socks_server_address, const uint16_t socks_server_port)
		{
			auto socks_tcp_socket = WSASocket(address_type_t::af_type, SOCK_STREAM, IPPROTO_TCP, nullptr, 0,
			                                  WSA_FLAG_OVERLAPPED);

			if (socks_tcp_socket == INVALID_SOCKET)
			{
				return INVALID_SOCKET;
			}

			if constexpr (address_type_t::af_type == AF_INET)
			{
				sockaddr_in sa_local = {0}; // NOLINT(clang-diagnostic-missing-field-initializers)
				sa_local.sin_family = address_type_t::af_type;
				sa_local.sin_port = htons(0);
				sa_local.sin_addr.s_addr = htonl(INADDR_ANY);

				if (const auto status = bind(socks_tcp_socket, reinterpret_cast<sockaddr*>(&sa_local), sizeof(sockaddr))
					; status == SOCKET_ERROR)
				{
					closesocket(socks_tcp_socket);
					return INVALID_SOCKET;
				}
			}
			else
			{
				sockaddr_in6 sa_local = {0}; // NOLINT(clang-diagnostic-missing-field-initializers)
				sa_local.sin6_family = address_type_t::af_type;
				sa_local.sin6_port = htons(0);
				sa_local.sin6_addr = in6addr_any;

				if (const auto status = bind(socks_tcp_socket, reinterpret_cast<sockaddr*>(&sa_local), sizeof(sockaddr))
					; status == SOCKET_ERROR)
				{
					closesocket(socks_tcp_socket);
					return INVALID_SOCKET;
				}
			}

			// connect to server
			if constexpr (address_type_t::af_type == AF_INET)
			{
				sockaddr_in sa_service = {0}; // NOLINT(clang-diagnostic-missing-field-initializers)
				sa_service.sin_family = address_type_t::af_type;
				sa_service.sin_addr = socks_server_address;
				sa_service.sin_port = htons(socks_server_port);

				if (connect(socks_tcp_socket, reinterpret_cast<SOCKADDR*>(&sa_service), sizeof(sa_service)) ==
					SOCKET_ERROR)
				{
					closesocket(socks_tcp_socket);
					return INVALID_SOCKET;
				}
			}
			else
			{
				sockaddr_in6 sa_service = {0}; // NOLINT(clang-diagnostic-missing-field-initializers)
				sa_service.sin6_family = address_type_t::af_type;
				sa_service.sin6_addr = socks_server_address;
				sa_service.sin6_port = htons(socks_server_port);

				if (connect(socks_tcp_socket, reinterpret_cast<SOCKADDR*>(&sa_service), sizeof(sa_service)) ==
					SOCKET_ERROR)
				{
					closesocket(socks_tcp_socket);
					return INVALID_SOCKET;
				}
			}

			return socks_tcp_socket;
		}

		[[nodiscard]] std::optional<uint16_t> associate_to_socks5_proxy(const SOCKET socks_tcp_socket,
		                                                                std::unique_ptr<negotiate_context_t>&
		                                                                negotiate_ctx) const noexcept
		{
			using namespace std::string_literals;

			socks5_ident_req<2> ident_req{};
			socks5_ident_resp ident_resp{};
			socks5_req<address_type_t> associate_req;
			socks5_resp<address_type_t> associate_resp;

			ident_req.methods[0] = 0x0; // RFC 1928: X'00' NO AUTHENTICATION REQUIRED
			ident_req.methods[1] = 0x2; // RFC 1928: X'02' USERNAME/PASSWORD

			auto result = send(socks_tcp_socket, reinterpret_cast<const char*>(&ident_req), sizeof(ident_req), 0);
			if (result == SOCKET_ERROR)
			{
				print_log(netlib::log::log_level::info,
				          "[SOCKS5]: associate_to_socks5_proxy: Failed to send socks5_ident_req: "s + std::to_string(
					          WSAGetLastError()));
				return {};
			}

			result = recv(socks_tcp_socket, reinterpret_cast<char*>(&ident_resp), sizeof(ident_resp), 0);
			if (result == SOCKET_ERROR)
			{
				print_log(netlib::log::log_level::info,
				          "[SOCKS5]: associate_to_socks5_proxy: Failed to receive socks5_ident_resp: "s +
				          std::to_string(WSAGetLastError()));
				return {};
			}

			if ((ident_resp.version != 5) ||
				(ident_resp.method == 0xFF))
			{
				print_log(netlib::log::log_level::info,
				          "[SOCKS5]: associate_to_socks5_proxy: SOCKS5 authentication has failed: "s);
				return {};
			}

			if (ident_resp.method == 0x2)
			{
				if (!negotiate_ctx->socks5_username.has_value())
				{
					print_log(netlib::log::log_level::info,
					          "[SOCKS5]: associate_to_socks5_proxy: RFC 1928: X'02' USERNAME/PASSWORD is chosen but USERNAME is not provided: "s);
					return {};
				}

				if (negotiate_ctx->socks5_username.value().length() > socks5_username_max_length || negotiate_ctx->
					socks5_username.value().length() < 1)
				{
					print_log(netlib::log::log_level::info,
					          "[SOCKS5]: associate_to_socks5_proxy: RFC 1928: X'02' USERNAME/PASSWORD is chosen but USERNAME exceeds maximum possible length: "s);
					return {};
				}

				if (!negotiate_ctx->socks5_password.has_value())
				{
					print_log(netlib::log::log_level::info,
					          "[SOCKS5]: associate_to_socks5_proxy: RFC 1928: X'02' USERNAME/PASSWORD is chosen but PASSWORD is not provided: "s);
					return {};
				}

				if (negotiate_ctx->socks5_password.value().length() > socks5_username_max_length || negotiate_ctx->
					socks5_password.value().length() < 1)
				{
					print_log(netlib::log::log_level::info,
					          "[SOCKS5]: associate_to_socks5_proxy: RFC 1928: X'02' USERNAME/PASSWORD is chosen but USERNAME exceeds maximum possible length: "s);
					return {};
				}

				const socks5_username_auth auth_req(negotiate_ctx->socks5_username.value(),
				                                    negotiate_ctx->socks5_password.value());

				result = send(socks_tcp_socket, reinterpret_cast<const char*>(&auth_req),
				              3 + static_cast<int>(negotiate_ctx->socks5_username.value().length()) + static_cast<int>(
					              negotiate_ctx->socks5_password.value().length()), 0);
				if (result == SOCKET_ERROR)
				{
					print_log(netlib::log::log_level::info,
					          "[SOCKS5]: associate_to_socks5_proxy: Failed to send socks5_username_auth: "s +
					          std::to_string(WSAGetLastError()));
					return {};
				}

				result = recv(socks_tcp_socket, reinterpret_cast<char*>(&ident_resp), sizeof(ident_resp), 0);
				if (result == SOCKET_ERROR)
				{
					print_log(netlib::log::log_level::info,
					          "[SOCKS5]: associate_to_socks5_proxy: Failed to receive socks5_ident_resp: "s +
					          std::to_string(WSAGetLastError()));
					return {};
				}

				if (ident_resp.method != 0x0)
				{
					print_log(netlib::log::log_level::info,
					          "[SOCKS5]: associate_to_socks5_proxy: USERNAME/PASSWORD authentication has failed!"s);
					return {};
				}

				print_log(netlib::log::log_level::info,
				          "[SOCKS5]: associate_to_socks5_proxy: USERNAME/PASSWORD authentication SUCCESS"s);
			}

			associate_req.version = 5;
			associate_req.cmd = 3;
			associate_req.reserved = 0;
			if constexpr (address_type_t::af_type == AF_INET)
			{
				associate_req.address_type = 1;
			}
			else
			{
				associate_req.address_type = 4;
			}
			associate_req.dest_address = address_type_t{};
			associate_req.dest_port = 0;
			result = send(socks_tcp_socket, reinterpret_cast<const char*>(&associate_req), sizeof(associate_req), 0);
			if (result == SOCKET_ERROR)
			{
				print_log(netlib::log::log_level::info,
				          "[SOCKS5]: associate_to_socks5_proxy: Failed to send SOCKS5 ASSOCIATE request: "s +
				          std::to_string(WSAGetLastError()));
				return {};
			}

			result = recv(socks_tcp_socket, reinterpret_cast<char*>(&associate_resp), sizeof(associate_resp), 0);
			if (result == SOCKET_ERROR)
			{
				print_log(netlib::log::log_level::info,
				          "[SOCKS5]: associate_to_socks5_proxy: Failed to receive SOCKS5 ASSOCIATE response: "s +
				          std::to_string(WSAGetLastError()));
				return {};
			}

			if ((associate_resp.version != 5) ||
				(associate_resp.reply != 0))
			{
				print_log(netlib::log::log_level::info,
				          "[SOCKS5]: associate_to_socks5_proxy: SOCKS5 ASSOCIATE has failed: "s);
				return {};
			}

			print_log(netlib::log::log_level::info,
			          "[SOCKS5]: associate_to_socks5_proxy: SOCKS5 ASSOCIATE SUCCESS port: "s + std::to_string(
				          ntohs(associate_resp.bind_port)));

			return ntohs(associate_resp.bind_port);
		}

		bool connect_to_remote_host(per_io_context_t* io_context)
		{
			uint16_t local_peer_port = 0;
			address_type_t local_peer_address{};

			if constexpr (address_type_t::af_type == AF_INET)
			{
				local_peer_port = ntohs(reinterpret_cast<sockaddr_in*>(&recv_from_sa_)->sin_port);
				local_peer_address = address_type_t(reinterpret_cast<sockaddr_in*>(&recv_from_sa_)->sin_addr);
			}
			else if constexpr (address_type_t::af_type == AF_INET6)
			{
				local_peer_port = ntohs(reinterpret_cast<sockaddr_in6*>(&recv_from_sa_)->sin6_port);
				local_peer_address = address_type_t(reinterpret_cast<sockaddr_in6*>(&recv_from_sa_)->sin6_addr);
			}
			else
			{
				static_assert(false_v<T>, "Unsupported address family used as a template parameter!");
			}

			// Lookup an existing proxy socket
			if (auto it = proxy_sockets_.find(local_peer_port); it != proxy_sockets_.end())
			{
				io_context->proxy_socket_ptr = it->second.get();
				return true;
			}

			auto [remote_address, remote_port, negotiate_ctx] =
				get_remote_peer(local_peer_address, local_peer_port);

			if (log_level_ > netlib::log::log_level::debug)
				log_printer(
					std::string("connect_to_remote_host: Connect to SOCKS5 proxy and send ASSOCIATE command: ") +
					std::string{remote_address} + " : " +
					std::to_string(remote_port));

			auto socks5_tcp_socket = connect_to_socks5_proxy(remote_address, remote_port);
			if (socks5_tcp_socket == INVALID_SOCKET)
			{
				if (log_level_ > netlib::log::log_level::info)
					log_printer(
						std::string("connect_to_remote_host: Failed to connect to SOCKS5 proxy: ") + std::string{
							remote_address
						} + " : " +
						std::to_string(remote_port));
				return false;
			}

			auto udp_port = associate_to_socks5_proxy(socks5_tcp_socket, negotiate_ctx);
			if (!udp_port.has_value())
			{
				if (log_level_ > netlib::log::log_level::info)
					log_printer(
						std::string("connect_to_remote_host: ASSOCIATE command has failed: ") + std::string{
							remote_address
						} + " : " +
						std::to_string(remote_port));

				closesocket(socks5_tcp_socket);
				return false;
			}

			if (log_level_ > netlib::log::log_level::debug)
				log_printer(
					std::string("connect_to_remote_host:  UDP connect: ") + std::string{remote_address} + " : " +
					std::to_string(udp_port.value()));

			auto remote_socket = WSASocket(address_type_t::af_type, SOCK_DGRAM, IPPROTO_UDP, nullptr, 0,
			                               WSA_FLAG_OVERLAPPED);

			if (remote_socket == INVALID_SOCKET)
			{
				return false;
			}

			if constexpr (address_type_t::af_type == AF_INET)
			{
				sockaddr_in sa_local = {0}; // NOLINT(clang-diagnostic-missing-field-initializers)
				sa_local.sin_family = address_type_t::af_type;
				sa_local.sin_port = htons(0);
				sa_local.sin_addr.s_addr = htonl(INADDR_ANY);

				if (const auto status = bind(remote_socket, reinterpret_cast<sockaddr*>(&sa_local), sizeof(sockaddr));
					status == SOCKET_ERROR)
				{
					closesocket(remote_socket);
					closesocket(socks5_tcp_socket);
					return false;
				}
			}
			else
			{
				sockaddr_in6 sa_local = {0}; // NOLINT(clang-diagnostic-missing-field-initializers)
				sa_local.sin6_family = address_type_t::af_type;
				sa_local.sin6_port = htons(0);
				sa_local.sin6_addr = in6addr_any;

				if (const auto status = bind(remote_socket, reinterpret_cast<sockaddr*>(&sa_local), sizeof(sockaddr));
					status == SOCKET_ERROR)
				{
					closesocket(remote_socket);
					closesocket(socks5_tcp_socket);
					return false;
				}
			}

			// connect to server
			if constexpr (address_type_t::af_type == AF_INET)
			{
				sockaddr_in sa_service = {0}; // NOLINT(clang-diagnostic-missing-field-initializers)
				sa_service.sin_family = address_type_t::af_type;
				sa_service.sin_addr = remote_address;
				sa_service.sin_port = htons(udp_port.value());

				if (connect(remote_socket, reinterpret_cast<SOCKADDR*>(&sa_service), sizeof(sa_service)) ==
					SOCKET_ERROR)
				{
					closesocket(remote_socket);
					closesocket(socks5_tcp_socket);
					return false;
				}
			}
			else
			{
				sockaddr_in6 sa_service = {0}; // NOLINT(clang-diagnostic-missing-field-initializers)
				sa_service.sin6_family = address_type_t::af_type;
				sa_service.sin6_addr = remote_address;
				sa_service.sin6_port = htons(remote_port);

				if (connect(remote_socket, reinterpret_cast<SOCKADDR*>(&sa_service), sizeof(sa_service)) ==
					SOCKET_ERROR)
				{
					closesocket(remote_socket);
					closesocket(socks5_tcp_socket);
					return false;
				}
			}

			auto [it, result] = proxy_sockets_.emplace(local_peer_port,
			                                           std::make_unique<T>(
				                                           socks5_tcp_socket, packet_pool_, server_socket_,
				                                           recv_from_sa_, remote_socket, remote_address,
				                                           udp_port.value(), std::move(negotiate_ctx),
				                                           log_printer_, log_level_));

			if (result)
			{
				io_context->proxy_socket_ptr = it->second.get();
				io_context->proxy_socket_ptr->associate_to_completion_port(completion_key_, completion_port_);
				io_context->proxy_socket_ptr->start();
			}
			else
			{
				closesocket(remote_socket);
				closesocket(socks5_tcp_socket);
				return false;
			}

			return result;
		}

		void clear_thread()
		{
			while (end_server_ == false)
			{
				{
					std::lock_guard<std::mutex> lock(lock_);

					for (auto it = proxy_sockets_.begin(); it != proxy_sockets_.end();)
					{
						if (it->second->is_ready_for_removal())
						{
							proxy_sockets_.erase(it++);
						}
						else
						{
							++it;
						}
					}
				}

				using namespace std::chrono_literals;
				std::this_thread::sleep_for(1000ms);
			}
		}

		void log_printer(const std::string& message) const
		{
			if (log_printer_)
			{
				log_printer_((std::string("socks5_local_udp_proxy_server: ") + message).c_str());
			}
		}

		void print_log(const netlib::log::log_level level, const std::string& message) const noexcept
		{
			if ((level < log_level_) && log_printer_)
			{
				log_printer_(message.c_str());
			}
		}
	};
}
