#pragma once
#include "pcap.h"

/// <summary>
/// The pcap_stream_logger class is responsible for logging network packets to a pcap file format.
/// </summary>
namespace pcap
{
    class pcap_stream_logger
    {
    public:
        /// <summary>
        /// Initializes a new instance of the pcap_stream_logger class.
        /// </summary>
        /// <param name="output_stream">The output stream to write the pcap data to.</param>
        explicit pcap_stream_logger(std::ostream& output_stream) : output_stream_(output_stream)
        {
            write_header();
        }

        pcap_stream_logger(const pcap_stream_logger& other) = delete;
        pcap_stream_logger& operator=(const pcap_stream_logger& other) = delete;
        pcap_stream_logger(pcap_stream_logger&& other) noexcept = delete;
        pcap_stream_logger& operator=(pcap_stream_logger&& other) noexcept = delete;

        ~pcap_stream_logger() = default;

        /// <summary>
        /// Logs the provided buffer to the pcap output stream.
        /// </summary>
        /// <param name="buffer">The buffer containing the packet data to log.</param>
        /// <returns>A reference to the current pcap_stream_logger instance.</returns>
        pcap_stream_logger& operator<<(const INTERMEDIATE_BUFFER& buffer)
        {
            {
                const auto [seconds, microseconds_remain] = get_timestamp();
                const auto* const ethernet_header = reinterpret_cast<const char*>(buffer.m_IBuffer);
                std::lock_guard lock(stream_mutex_);
                output_stream_ << pcap_record_header(seconds, microseconds_remain,
                    buffer.m_Length, buffer.m_Length, ethernet_header);

                output_stream_.flush();
            }

            return *this;
        }

    private:
        std::ostream& output_stream_;
        std::mutex stream_mutex_; // Mutex to protect the output stream

        /// <summary>
        /// Writes the pcap file header to the output stream.
        /// </summary>
        void write_header()
        {
            std::lock_guard lock(stream_mutex_);
            const pcap_file_header header{ 2, 4, 0, 0, MAX_ETHER_FRAME, LINKTYPE_ETHERNET };
            output_stream_ << header;
        }

        struct timestamp_t
        {
            uint32_t seconds;
            uint32_t microseconds_remain;
        };

        /// <summary>
        /// Gets the current timestamp in seconds and microseconds.
        /// </summary>
        /// <returns>A timestamp_t struct containing the current timestamp.</returns>
        [[nodiscard]] static timestamp_t get_timestamp()
        {
            static const auto start_time = std::chrono::high_resolution_clock::now();
            static const auto seconds_since_epoch =
                gsl::narrow_cast<uint32_t>(std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch()
                ).count());

            const auto milliseconds =
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::high_resolution_clock::now() - start_time
                );

            const auto seconds = gsl::narrow_cast<uint32_t>(milliseconds.count() / 1000) + seconds_since_epoch;
            const auto microseconds_remain = gsl::narrow_cast<uint32_t>((milliseconds.count() % 1000) * 1000);

            return { seconds, microseconds_remain };
        }
    };
}
