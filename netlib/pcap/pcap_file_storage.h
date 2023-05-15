#pragma once

#include "pcap.h"

namespace pcap
{
	// --------------------------------------------------------------------------------
	/// <summary>
	/// PCAP format packet file logger
	/// </summary>
	// --------------------------------------------------------------------------------
	class pcap_file_storage
	{
	public:
		/// <summary>
		/// Constructs object instance and opens the file for the output
		/// </summary>
		/// <param name="file_name">PCAP file name</param>
		explicit pcap_file_storage(const std::string& file_name)
		{
			open(file_name);
		}

		/// <summary>
		/// Default constructor
		/// </summary>
		pcap_file_storage() = default;

		/// <summary>
		/// Deleted copy constructor
		/// </summary>
		pcap_file_storage(const pcap_file_storage& other) = delete;

		/// <summary>
		/// Default move constructor
		/// </summary>
		/// <param name="other">Object instance to move from</param>
		pcap_file_storage(pcap_file_storage&& other) noexcept = default;

		/// <summary>
		/// Deleted copy assignment
		/// </summary>
		pcap_file_storage& operator=(const pcap_file_storage& other) = delete;

		/// <summary>
		/// Default move assignment
		/// </summary>
		/// <param name="other">Object instance to move from</param>
		/// <returns></returns>
		pcap_file_storage& operator=(pcap_file_storage&& other) noexcept = default;

		/// <summary>
		/// Destructor: closes the output file stream
		/// </summary>
		~pcap_file_storage()
		{
			try
			{
				if (file_stream_)
					file_stream_.close();
			}
			catch (...)
			{
			}
		}

		/// <summary>
		/// Typecast to bool returns true is file was successfully opened
		/// </summary>
		// ReSharper disable once CppNonExplicitConversionOperator
		operator bool() const { return file_stream_ ? true : false; }

		/// <summary>
		/// Opens specified PCAP file and writes out the PCAP file header
		/// </summary>
		/// <param name="file_name">PCAP file to open</param>
		void open(const std::string& file_name)
		{
			if (file_stream_)
				file_stream_.close();

			file_stream_.open(file_name, std::ofstream::binary | std::ofstream::out | std::ofstream::trunc);

			if (file_stream_)
			{
				const pcap_file_header header{2, 4, 0, 0,MAX_ETHER_FRAME, LINKTYPE_ETHERNET};
				file_stream_ << header;
			}
		}

		/// <summary>
		/// Writes network packet stored in INTERMEDIATE_BUFFER into the PCAP file
		/// </summary>
		/// <param name="buffer">Network packet to write into the PCAP file</param>
		/// <returns></returns>
		pcap_file_storage& operator<<(const INTERMEDIATE_BUFFER& buffer)
		{
			static std::mutex lock; // NOLINT(clang-diagnostic-exit-time-destructors)
			static const auto start_time = std::chrono::high_resolution_clock::now();
			static const auto seconds_since_epoch =
				gsl::narrow_cast<uint32_t>(std::chrono::duration_cast<std::chrono::seconds>(
					std::chrono::system_clock::now().time_since_epoch()
				).count());

			std::lock_guard<std::mutex> write_lock(lock);

			const auto milliseconds =
				std::chrono::duration_cast<std::chrono::milliseconds>(
					std::chrono::high_resolution_clock::now() - start_time
				);

			const auto seconds = gsl::narrow_cast<uint32_t>(milliseconds.count() / 1000) + seconds_since_epoch;
			const auto microseconds_remain = gsl::narrow_cast<uint32_t>((milliseconds.count() % 1000) * 1000);

			const auto* const ethernet_header = reinterpret_cast<const char*>(buffer.m_IBuffer);

			file_stream_ << pcap_record_header(seconds, microseconds_remain,
			                                   buffer.m_Length, buffer.m_Length, ethernet_header);

			file_stream_.flush();

			return *this;
		}

	private:
		/// <summary>
		/// PCAP file associated file stream object instance
		/// </summary>
		std::ofstream file_stream_;
	};
}
