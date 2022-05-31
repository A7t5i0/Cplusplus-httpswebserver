#include <string>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <stdbool.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <signal.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <errno.h>
#include <iostream>
#include <vector>
#include <fstream>
#include <unordered_map>
#include <cstdint>
#include <filesystem>
#include <sstream>
#include <cstring>
#include <string>
#include <iomanip>

#define PORT 5000

#define BUF_SIZE 8000000
#define REQ_SIZE 2048
#define FILENAME_SIZE 1024
#define MAX_LINE 2048

SSL_CTX *create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("unable to create ssl context");
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void configure_context(SSL_CTX *ctx) {
    if (SSL_CTX_use_certificate_file(ctx, "certificate.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "privateKey.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

std::string content_header(std::string url, size_t urlLength) {
    std::string content_type = "Content-Type: text/html; charset=UTF-8\n";

    if(url.length()>1)
    {   std::unordered_map<std::string, std::string> umap;
        umap[".gif"] = "Content-Type: image/gif; charset=UTF-8\r\n";
        umap[".txt"] = "Content-Type: text/plain; charset=UTF-8\r\n";
        umap[".jpg"] = "Content-Type: image/jpg; charset=UTF-8\r\n";
        umap[".jpeg"] = "Content-Type: image/jpeg; charset=UTF-8\r\n";
        umap[".js"] = "Content-Type: application/javascript; charset=UTF-8\r\n";
        umap[".png"] = "Content-Type: image/png; charset=UTF-8\r\n";
        umap[".ico"] = "Content-Type: image/ico; charset=UTF-8\r\n";
        umap[".zip"] = "Content-Type: application/octet-stream; charset=UTF-8\r\n";
        umap[".php"] = "Content-Type: text/html; charset=UTF-8\r\n";
        umap[".tar"] = "Content-Type: image/tar; charset=UTF-8\r\n";
        umap[".rar"] = "Content-Type: application/octet-stream; charset=UTF-8\r\n";
        umap[".pdf"] = "Content-Type: application/pdf; charset=UTF-8\r\n";
        umap[".mp4"] = "Content-Type: video/mp4; charset=UTF-8\r\n";
        umap[".mov"] = "Content-Type: video/quicktime; charset=UTF-8\r\n";
        umap[".c"] = "forbidden";
        umap["sudo"] = "forbidden";
        umap[".exe"] = "forbidden";
        umap["cat"] = "forbidden";
        umap["'"] = "forbidden";

        std::string content_Type;
        int pos = url.find(".");
        std::string str = url.substr(pos);
        std::cout << umap[str];
        content_Type = umap[str];
        printf("CONTENT TYPE WRITTEN TO BROWSER IS:\n%s\n", content_Type.c_str());
        if (content_Type.empty()){
            return content_type;
        } else {
            return content_Type;
        }
    }else{
        return content_type;
    }
}

size_t return_filesize(char* filename){
    FILE *f = fopen(filename, "rb");
    fseek(f, 0L, SEEK_END);
    size_t filesize = ftell(f);
    fclose(f);
    return filesize;
}

void write_file_function(std::string filename, SSL *ssl){
    if(access(filename.c_str(), F_OK) != -1) {
        std::cout << "file is found\n";
        std::ofstream os;
        os.open(filename, std::ios::binary);
        ssize_t bytes_read;
        // while(bytes_read = read(fd))

    }
}

void write_file(const char* filename, SSL *ssl) {
    if (access(filename, F_OK) != -1) {
        printf("\nfile is found\n");
        char buf[8000000];
        int fd = open(filename, O_RDONLY);
        ssize_t bytes_read;
        while(bytes_read = read(fd, buf, sysconf(_SC_PAGESIZE))) {
            SSL_write(ssl, buf, bytes_read);
        }
        printf("file written\n");
        free(ssl);
        close(fd);
        int pid = getpid();
        kill(pid, SIGTERM);
    } else {
        printf("\nfile NOT found\n");
        int pid = getpid();
        kill(pid, SIGTERM);
    }
}

void upload_file(const char* filename, SSL *ssl) {
    if (access(filename, F_OK) != -1) {
        printf("\nfile is found\n");
        char buf[256];
        int fd = open(filename, O_RDONLY);
        ssize_t bytes_read;
        while(bytes_read = SSL_read(ssl, buf, sizeof(buf))) {
            write(fd, buf, bytes_read);
        }
        printf("file written\n");
        free(ssl);
        close(fd);
        int pid = getpid();
        kill(pid, SIGTERM);
    } else {
        printf("\nfile NOT found\n");
        int pid = getpid();
        kill(pid, SIGTERM);
    }
}

void upload_file(SSL *ssl, int child) {
    ssize_t bytes_read = 0;
    ssize_t bytes_written = 0;
    char buf[256];
    
    ssize_t first_read = SSL_read(ssl, buf, sizeof buf);
    // buf[first_read-1] = '\0';
    char *test = strstr(buf, "\n\n");
    if (test == NULL) {
        perror("weird request bro\n");
    }
    char *test2 = strstr(buf, "\r\n\r\n");
    if (test2 == NULL) {
        perror("weird request bro\n");
    }
    printf("test1:\n%s\ntest2:\n%s\n", test, test2);
    char *postheader = strstr(buf, "Content-Disposition: ");
    char *ph2 = (char*)malloc(100);
    memcpy(ph2, postheader, 100);

    char *ph3 = strstr(ph2, "filename=");
    ph3 += 10;
    char *removechar = strchr(ph3, '"');
    *removechar = '\0';

    printf("strlen(filename):\n%ld\n", strlen(ph3));
    std::string contentType = content_header(ph3, strlen(ph3));
    printf("ph3 content type:\n%s\n", contentType.c_str());

    if (access(ph3, F_OK) != -1) {
        printf("name in use\n");
    } else {
        if (contentType != "Content-Type: forbidden; charset=UTF-8\n") {
            ssize_t offset = test2 - buf;
            offset += 4;
            char *dataptr = buf + offset;
            
            ssize_t not_first_read = first_read - offset;
            
            printf("data:\n%s\n", dataptr);
            FILE* tmp = fopen(ph3, "wb");
            fwrite(dataptr, not_first_read, 1, tmp);
            while((bytes_read = SSL_read(ssl, dataptr, sizeof buf))){      
                printf("bytesread: %ld\n", bytes_read);
                bytes_written = fwrite(dataptr, bytes_read, 1, tmp);
                if (bytes_read == bytes_written) {
                    printf("read==write\n");
                } else if (bytes_read > bytes_written) {
                    printf("read>write\n");
                }
                if (bytes_read < first_read) {
                    break;
                }
            }
            fclose(tmp);
        }
    }
    printf("\nupload successful\n");
    SSL_free(ssl);
    free(ph2);

    int pid = getpid();
    kill(pid, SIGTERM);
}

std::vector<char> fillBuffer(SSL* ssl){
    std::string builtString;
    std::vector<char> buffer;
    buffer.resize(1024);
    size_t first_read = 0;
    first_read = SSL_read(ssl, buffer.data(), 256);
    size_t bytes_read = 0;
    size_t total_bytes = 0;
    total_bytes += first_read;
    size_t bufsize = 0;
    for(;;){
        bytes_read = SSL_read(ssl, buffer.data() + total_bytes, 256);
        printf("%ld\n", bytes_read);
        total_bytes += bytes_read;
        bufsize = total_bytes * 2;
        buffer.resize(bufsize);
        if(bytes_read < first_read){
            break;
        }
    }
    printf("done loading vector\n");
    for (int i = 0; i < buffer.size(); i++){
        std::cout << buffer[i];
    }
    buffer.resize(total_bytes);
    return buffer;
}

std::string readLine(std::vector<char> buffer){
    std::string line;
    for (int i = 0; i < buffer.size(); i++){
        line += buffer[i];
        if(buffer[i] == '\n'){
            break;
        }
    }
    std::cout << "line:\n" << line;
    return line;
}

std::string getContentLengthLine(std::vector<char> buffer){
    std::string line;
    for (int i = 0; i < buffer.size(); i++){
        line += buffer[i];
        if(line.find("Content-Length") != std::string::npos){
            if(buffer[i] == '\n'){
                break;
            }
        }
    }
    std::cout << "line:\n" << line;
    return line;
}

std::string getFilenameLine(std::vector<char> buffer){
    std::string line;
    for (int i = 0; i < buffer.size(); i++){
        line += buffer[i];
        if(line.find("filename") != std::string::npos){
            if(buffer[i] == '\n'){
                break;
            }
        }
    }
    std::cout << "line:\n" << line;
    return line;
}

std::string findInBuffer(std::vector<char> buffer, std::string searchFor){
    std::string line;
    for (int i = 0; i < buffer.size(); i++){
        line += buffer[i];
        if(line.find(searchFor) != std::string::npos){
            if(buffer[i] == '\n'){
                break;
            }
        }
    }
    line = line.substr(line.find(searchFor));
    std::cout << "line:\n" << line;
    return line;
}

int findStartOfFile(std::vector<char> buffer){
    std::string line;
    std::string searchFor = "Content-Type";
    int i = 0;
    for (i; i < buffer.size(); i++){
        line += buffer[i];
        if(line.find(searchFor) != std::string::npos){
            line = line.substr(5);
            if(line.find(searchFor) != std::string::npos){
                if(buffer[i] == '\n'){
                    break;
                }
            }
        }
    }
    // int lineLength = line.length();
    // i += lineLength;
    // searchFor = "Content-Type";
    // for (i; i < buffer.size(); i++){
    //     line += buffer[i];
    //     printf("testing the line: \n%s\n", line.c_str());
    //     if(line.find(searchFor) != std::string::npos){
    //         if(buffer[i] == '\n'){
    //             line += buffer[i + 1];
    //             line += buffer[i + 2];
    //             line += buffer[i + 3];
    //             line += buffer[i + 4];
    //             break;
    //         }
    //     }
    // }
    // lineLength = line.length();
    // i += lineLength;
    // i += 5;
    // searchFor = "Content-Type";
    // for (i; i < buffer.size(); i++){
    //     line += buffer[i];
    //     printf("testing the line: \n%s\n", line.c_str());
    //     if(line.find(searchFor) != std::string::npos){
    //         if(buffer[i] == '\n'){
    //             break;
    //         }
    //     }
    // }
    // i -= 10;
    // lineLength = line.length();
    // i += lineLength;
    // for (i; i < buffer.size(); i++){
    //     line += buffer[i];
    //     printf("testing the line: \n%s\n", line.c_str());
    //     if(line.find(searchFor) != std::string::npos){
    //         if(buffer[i] == '\n'){
    //             break;
    //         }
    //     }
    // }
    
    line = line.substr(line.find(searchFor));
    std::cout << "line:\n" << line;
    return i;
}

void uploadFileToServer(std::vector<char> buffer, SSL* ssl, std::string filename){
    std::ofstream f (filename, std::ios::binary | std::ios::out);
    // ifstream f;
    // f.open(filename, ios::binary | ios::out);
    // f.read
    // FILE* f = fopen(filename.c_str(), "wb");
    for (int i = 3; i<buffer.size(); i++){
        f << buffer[i];
    }
}

int contains(std::string line, std::string lookfor){
    int x = 0;
    int y = 1;
    int c = 0;
    size_t lineLen = line.length();
    size_t lookforLen = lookfor.length();
    
    for(int i = 0; i = lookforLen; i++){
        for(int j = 0; j = lineLen; j++){
            if(lookfor[i] == line[j]){
                c++;
                if(c==lookforLen){
                    return 1;
                }
            }
        }
    }
    return 0;    
}

int main(){
    if (getuid() == 0){
        printf("dont run as root\n");
        exit(0);
    }
    if(geteuid() == 0){
        printf("dont run as root\n");
        exit(0);
    }

    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGPIPE);
    sigprocmask(SIG_BLOCK, &set, NULL);

    int server_fd = socket(AF_INET6, SOCK_STREAM, 0);
    if(server_fd == 0){
        perror("failed to create socket\n");
        exit(EXIT_FAILURE);
    }
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in6 addr6 = {
        .sin6_family = AF_INET6,
        .sin6_port = htons(PORT),
        .sin6_flowinfo = 0,
        .sin6_addr = IN6ADDR_ANY_INIT,
        .sin6_scope_id = 0
    };
    socklen_t addr_len = sizeof(struct sockaddr_in6);

    if(bind(server_fd, (struct sockaddr *)&addr6, sizeof(addr6))){
        perror("failed to bind\n");
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd, 10) < 0){
        perror("failed to listen\n");
        exit(EXIT_FAILURE);
    }

    int new_socket;
    SSL_CTX *ctx;
    ctx = create_context();
    configure_context(ctx);

    while(1){
        if((new_socket = accept(server_fd, (struct sockaddr *)&addr6, (socklen_t*)&addr_len))<0){
            perror("failed to accept connection\n");
            exit(EXIT_FAILURE);
        }

        int child = fork();
        if(child){
            continue;
        }

        SSL *ssl;
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, new_socket);
        if(SSL_accept(ssl) <= 0){
            ERR_print_errors_fp(stderr);
        }

        char req[1];
        std::string line;
        std::string method;
        std::vector<char> buffer = fillBuffer(ssl);
        line = readLine(buffer);
        if(line.find("GET") != std::string::npos){
            method = "GET";
        }else if(line.find("POST") != std::string::npos){
            method = "POST";
        }
        
        if(method == "GET"){
            int offset = line.find("/");
            std::string url = line.substr(offset);
            std::cout << url;
            std::string headers;
            headers += "HTTP/1.1 200 OK\r\nDate: ";
            headers += __DATE__;
            headers += " GMT\r\nServer: GNU/linux\r\nLast-Modified: Tue, 8 Mar 2022 15:53:59 GMT\r\n";
            if (line.find("/ ") != std::string::npos){
                printf("homepage\n");
                std::string filename = "index.html";
                headers += "Content-Type: text/html; charset=UTF-8\r\n";
                std::uintmax_t filesize = std::filesystem::file_size("index.html");
                std::stringstream stream;
                stream << "Content-Length: " << filesize << "\r\n" << "Connection: close\r\n\r\n";
                std::string strstream = stream.str();
                headers += strstream;
                std::cout << headers;
                SSL_write(ssl, headers.data(), headers.length());
                write_file(filename.c_str(), ssl);
            } else {
                printf("ELSE\n");
                offset = url.find(" ");
                std::string filename = url.substr(1, offset - 1);
                printf("%s\n", filename.c_str());
                // std::cout << filename;
                size_t urlLength = url.length();
                std::string content_type = content_header(filename, filename.length());
                std::string filename2 = filename + ".html";
                std::string page404 = "404.html";
                if(access(filename.c_str(), F_OK) != -1 && content_type != "forbidden"){
                    std::cout << filename;
                    headers += content_type;
                    std::uintmax_t filesize = std::filesystem::file_size(filename);
                    std::stringstream stream;
                    stream << "Content-Length: " << filesize << "\r\n" << "Connection: close\r\n\r\n";
                    std::string strstream = stream.str();
                    headers += strstream;
                    printf("%s\n", headers.c_str());
                    SSL_write(ssl, headers.data(), headers.length());
                    write_file(filename.c_str(), ssl);
                } else if(access(filename2.c_str(), F_OK) != -1 && content_type != "forbidden"){
                    printf("%s\n", filename2.c_str());
                    std::cout << filename2;
                    headers += content_type;
                    std::uintmax_t filesize = std::filesystem::file_size(filename2);
                    std::stringstream stream;
                    stream << "Content-Length: " << filesize << "\r\n" << "Connection: close\r\n\r\n";
                    std::string strstream = stream.str();
                    headers += strstream;
                    printf("%s\n", headers.c_str());
                    SSL_write(ssl, headers.data(), headers.length());
                    write_file(filename2.c_str(), ssl);
                } else{
                    printf("%s\n", page404.c_str());
                    std::cout << page404;
                    headers += content_type;
                    std::uintmax_t filesize = std::filesystem::file_size(page404);
                    std::stringstream stream;
                    stream << "Content-Length: " << filesize << "\r\n" << "Connection: close\r\n\r\n";
                    std::string strstream = stream.str();
                    headers += strstream;
                    printf("%s\n", headers.c_str());
                    SSL_write(ssl, headers.data(), headers.length());
                    write_file(page404.c_str(), ssl);
                }
            }
        } else if(method == "POST"){
            printf("this is a post request\n");
            std::string contentLength = findInBuffer(buffer, "Content-Length");
            int offset = contentLength.find(" ");
            contentLength = contentLength.substr(offset + 1);
            int contentLengthInt = stoi(contentLength);
            std::string filename = findInBuffer(buffer, "filename");
            printf("filename IS:\n%s\n", filename.c_str());
            offset = filename.find("=");
            filename = filename.substr(offset + 2);
            offset = filename.find('"');
            filename = filename.substr(0, offset);
            printf("filename is:\n%s\n", filename.c_str());
            std::string contentType = findInBuffer(buffer, "Content-Type");
            printf("contentype IS:\n%s\n", contentType.c_str());

            std::string boundary = findInBuffer(buffer, "boundary=");
            boundary = boundary.substr(9);
            int boundaryLength = boundary.length();
            int startOfFile = findStartOfFile(buffer);
            for(int i = 0;i<startOfFile;i++){
                buffer.erase(buffer.begin());
            }
            for(int i = 0;i<boundaryLength;i++){
                buffer.pop_back();
            }
            uploadFileToServer(buffer, ssl, filename);
            // printf("%s", contentLength.c_str());
            // upload_file(ssl, child);
        } else{
            printf("request method not yet implemented");
        }
    }
}