#include "virus_total_client.h"
#include <cctype>
#include <sstream>
#include <utility>

#if defined(PACMAN_HAVE_CURL)
#include <curl/curl.h>
#endif

namespace PacMan {

namespace {

#if defined(PACMAN_HAVE_CURL)
// Curl write callback to append received data to a std::string
size_t writeCallback(char* ptr, size_t size, size_t nmemb, void* userdata) {
    std::string* response = static_cast<std::string*>(userdata);
    response->append(ptr, size * nmemb);
    return size * nmemb;
}
#endif

// Sanitize and URL-encode the domain name before making the API request
std::string urlEncodeDomain(const std::string& domain) {
    std::ostringstream encoded;
    for (unsigned char ch : domain) {
        if (std::isalnum(ch) || ch == '.' || ch == '-' || ch == '_') {
            encoded << static_cast<char>(ch);
        }
    }
    return encoded.str();
}

// Very basic JSON parsing to look for the "malicious" key in the response
// For a production app, a real JSON parser (like nlohmann/json) should be used.
bool responseLooksMalicious(const std::string& response) {
    const std::string key = "\"malicious\":";
    const std::size_t pos = response.find(key);
    if (pos == std::string::npos) {
        return false;
    }

    std::size_t value_pos = pos + key.size();
    while (value_pos < response.size() && std::isspace(static_cast<unsigned char>(response[value_pos]))) {
        ++value_pos;
    }

    // If the value after "malicious": is not '0', consider it malicious
    return value_pos < response.size() && response[value_pos] != '0';
}

} // namespace

VirusTotalClient::VirusTotalClient(std::string api_key) : api_key_(std::move(api_key)) {}

bool VirusTotalClient::isMalicious(const std::string& domain) const {
    return checkDomain(domain).malicious;
}

VirusTotalResult VirusTotalClient::checkDomain(const std::string& domain) const {
    VirusTotalResult result;
    if (api_key_.empty() || domain.empty()) {
        result.message = "VirusTotal skipped: no API key or domain";
        return result;
    }

    // Check the local cache first
    {
        std::lock_guard<std::mutex> lock(cache_mutex_);
        const std::unordered_map<std::string, VirusTotalResult>::const_iterator found = cache_.find(domain);
        if (found != cache_.end()) {
            return found->second;
        }
    }

#if defined(PACMAN_HAVE_CURL)
    const std::string safe_domain = urlEncodeDomain(domain);
    if (safe_domain.empty()) {
        result.message = "VirusTotal skipped: invalid domain";
        return result;
    }

    CURL* curl = curl_easy_init();
    if (curl == nullptr) {
        result.message = "VirusTotal skipped: curl initialization failed";
        return result;
    }

    std::string response;
    const std::string url = "https://www.virustotal.com/api/v3/domains/" + safe_domain;
    struct curl_slist* headers = nullptr;
    const std::string api_header = "x-apikey: " + api_key_;
    headers = curl_slist_append(headers, api_header.c_str());

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 3L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "PacMan/1.0");

    const CURLcode code = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (code != CURLE_OK) {
        result.message = std::string("VirusTotal request failed: ") + curl_easy_strerror(code);
        return result;
    }

    if (http_code < 200 || http_code >= 300) {
        result.message = "VirusTotal returned HTTP " + std::to_string(http_code);
        return result;
    }

    result.checked = true;
    result.malicious = responseLooksMalicious(response);
    result.message = result.malicious ? "VirusTotal marked domain malicious"
                                      : "VirusTotal did not mark domain malicious";
                                      
    // Cache the result to avoid redundant network calls
    {
        std::lock_guard<std::mutex> lock(cache_mutex_);
        cache_[domain] = result;
    }
    return result;
#else
    result.message = "VirusTotal skipped: libcurl not available at build time";
    return result;
#endif
}

} // namespace PacMan
