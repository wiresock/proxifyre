#pragma once

struct mutex_impl;

namespace proxy
{
	class socks_local_router;
}

class socksify_unmanaged
{
	explicit socksify_unmanaged(log_level_mx log_level);

public:
	~socksify_unmanaged();

	socksify_unmanaged(const socksify_unmanaged& other) = delete;
	socksify_unmanaged(socksify_unmanaged&& other) = delete;
	socksify_unmanaged& operator=(const socksify_unmanaged& other) = delete;
	socksify_unmanaged& operator=(socksify_unmanaged&& other) = delete;

	static socksify_unmanaged* get_instance(log_level_mx log_level = log_level_mx::all);
	[[nodiscard]] bool init();
	[[nodiscard]] bool start() const;
	[[nodiscard]] bool stop() const;
	[[nodiscard]] LONG_PTR add_socks5_proxy(
		const std::string& endpoint,
		supported_protocols_mx protocol,
		bool start = false,
		const std::string& login = "",
		const std::string& password = ""
	) const;
	[[nodiscard]] bool associate_process_name_to_proxy(
		const std::wstring& process_name,
		LONG_PTR proxy_id) const;
	void set_log_limit(uint32_t log_limit);
	[[nodiscard]] uint32_t get_log_limit();
	void set_log_event(HANDLE log_event);
	log_storage_mx_t read_log();

private:
	static void log_printer(const char* log);
	static void log_event(event_mx log);
	void print_log(log_level_mx level, const std::string& message) const;

	log_level_mx log_level_{log_level_mx::none};
	std::string address_;
	std::unique_ptr<proxy::socks_local_router> proxy_;
	std::unique_ptr<mutex_impl> lock_;
};
