#pragma once

namespace tools::strings
{
    /**
     * @brief Converts a std::string to a std::wstring.
     *
     * This function converts a UTF-8 encoded std::string to a std::wstring using the Windows API.
     *
     * @param str The std::string to convert.
     * @return A std::wstring which is the wide character representation of the input string.
     */
    inline std::wstring to_wstring(const std::string& str)
    {
        const int required_size = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, nullptr, 0);
        if (required_size == 0)
        {
            // Handle error
            return L"";
        }

        std::wstring wide_string(required_size - 1, '\0');
        if (const int result = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, wide_string.data(), required_size);
            result == 0)
        {
            // Handle error
            return L"";
        }

        return wide_string;
    }

    /**
     * @brief Converts a std::wstring to a std::string.
     *
     * This function converts a std::wstring to a UTF-8 encoded std::string using the Windows API.
     *
     * @param wide_string The std::wstring to convert.
     * @return A std::string which is the UTF-8 representation of the input wide string.
     */
    inline std::string to_string(const std::wstring& wide_string)
    {
        const int required_size = WideCharToMultiByte(CP_UTF8, 0, wide_string.c_str(), -1, nullptr, 0, nullptr, nullptr);
        if (required_size == 0)
        {
            // Handle error
            return "";
        }

        std::string str(required_size - 1, '\0');
        if (const int result = WideCharToMultiByte(CP_UTF8, 0, wide_string.c_str(), -1, str.data(), required_size,
            nullptr, nullptr); result == 0)
        {
            // Handle error
            return "";
        }

        return str;
    }

    /**
     * @brief Splits a string by the specified separator.
     *
     * This function takes an input string and a separator character and splits the string
     * into a vector of strings at each occurrence of the separator.
     *
     * @param input The string to split.
     * @param sep The character to use as a separator.
     * @return A std::vector<std::string> of the split string segments.
     */
    inline std::vector<std::string> split_string(const std::string& input, const char sep)
    {
        std::stringstream ss(input);
        std::string segment;
        std::vector<std::string> strings;

        while (std::getline(ss, segment, sep))
        {
            strings.push_back(segment);
        }

        return strings;
    }

    /**
     * @brief Splits a wide string by the specified wide separator.
     *
     * This function takes an input wide string and a wide separator character and splits the string
     * into a vector of wide strings at each occurrence of the separator.
     *
     * @param input The wide string to split.
     * @param sep The wide character to use as a separator.
     * @return A std::vector<std::wstring> of the split wide string segments.
     */
    inline std::vector<std::wstring> split_string(const std::wstring& input, const wchar_t sep)
    {
        std::wstringstream wss(input);
        std::wstring segment;
        std::vector<std::wstring> strings;

        while (std::getline(wss, segment, sep))
        {
            strings.push_back(segment);
        }

        return strings;
    }

    /**
     * @brief Converts a string to lowercase.
     *
     * This function takes a std::string and converts all alphabetical characters to lowercase.
     *
     * @param input The std::string to be converted to lowercase.
     * @return A std::string in which all alphabetical characters are lowercase.
     */
    inline std::string to_lower(const std::string& input) {
        std::string output;
        std::ranges::transform(input, std::back_inserter(output),
            [](const unsigned char c) { return std::tolower(c, std::locale::classic()); });
        return output;
    }

    /**
     * @brief Converts a wide string to lowercase.
     *
     * This function takes a std::wstring and converts all alphabetical characters to lowercase.
     *
     * @param input The std::wstring to be converted to lowercase.
     * @return A std::wstring in which all alphabetical characters are lowercase.
     */
    inline std::wstring to_lower(const std::wstring& input) {
        std::wstring output;
        std::ranges::transform(input, std::back_inserter(output),
            [](const wchar_t c) { return std::tolower(c, std::locale::classic()); });
        return output;
    }
}
