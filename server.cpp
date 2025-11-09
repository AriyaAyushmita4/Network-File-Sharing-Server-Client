#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <fstream>
#include <vector>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <dirent.h>
#include <sys/socket.h>
#include <sys/types.h>

using namespace std;

#define BUFFER_SIZE 4096

// AES helpers
bool aes_encrypt(const unsigned char *input, int len,
                 const unsigned char *key, unsigned char *iv,
                 vector<unsigned char> &output) {
    AES_KEY enc_key;
    AES_set_encrypt_key(key, 128, &enc_key);
    output.resize(len);
    AES_cfb128_encrypt(input, output.data(), len, &enc_key, iv, &len, AES_ENCRYPT);
    return true;
}

bool aes_decrypt(const unsigned char *input, int len,
                 const unsigned char *key, unsigned char *iv,
                 vector<unsigned char> &output) {
    AES_KEY dec_key;
    AES_set_decrypt_key(key, 128, &dec_key);
    output.resize(len);
    AES_cfb128_encrypt(input, output.data(), len, &dec_key, iv, &len, AES_DECRYPT);
    return true;
}

bool send_all(int sock, const void *buf, size_t len) {
    const char *ptr = (const char *)buf;
    while (len > 0) {
        ssize_t sent = send(sock, ptr, len, 0);
        if (sent <= 0) return false;
        ptr += sent;
        len -= sent;
    }
    return true;
}

bool recv_all(int sock, void *buf, size_t len) {
    char *ptr = (char *)buf;
    while (len > 0) {
        ssize_t recvd = recv(sock, ptr, len, 0);
        if (recvd <= 0) return false;
        ptr += recvd;
        len -= recvd;
    }
    return true;
}

bool send_encrypted_message(int sock, const unsigned char *key, unsigned char *iv, const string &msg) {
    vector<unsigned char> cipher;
    aes_encrypt((const unsigned char *)msg.data(), msg.size(), key, iv, cipher);
    uint32_t len = htonl(cipher.size());
    if (!send_all(sock, &len, sizeof(len))) return false;
    return send_all(sock, cipher.data(), cipher.size());
}

bool recv_encrypted_message(int sock, const unsigned char *key, unsigned char *iv, string &out) {
    uint32_t len_net;
    if (!recv_all(sock, &len_net, sizeof(len_net))) return false;
    uint32_t len = ntohl(len_net);
    vector<unsigned char> cipher(len);
    if (!recv_all(sock, cipher.data(), len)) return false;
    vector<unsigned char> plain;
    aes_decrypt(cipher.data(), len, key, iv, plain);
    out.assign((const char *)plain.data(), plain.size());
    return true;
}

void handle_client(int client_sock, const unsigned char *key, unsigned char *iv, string shared_folder) {
    string username, password;

    // Auth
    if (!recv_encrypted_message(client_sock, key, iv, username)) return;
    if (!recv_encrypted_message(client_sock, key, iv, password)) return;

    if (username == "alice" && password == "password123") {
        send_encrypted_message(client_sock, key, iv, "OK");
    } else {
        send_encrypted_message(client_sock, key, iv, "FAIL");
        close(client_sock);
        return;
    }

    cout << "Client " << username << " connected.\n";

    while (true) {
        string cmd;
        if (!recv_encrypted_message(client_sock, key, iv, cmd)) break;
        if (cmd == "QUIT") break;

        if (cmd == "LIST") {
            string files;
            DIR *dir = opendir(shared_folder.c_str());
            struct dirent *entry;
            while ((entry = readdir(dir)) != nullptr) {
                if (entry->d_name[0] != '.')
                    files += string(entry->d_name) + "\n";
            }
            closedir(dir);
            send_encrypted_message(client_sock, key, iv, files);
        }

        else if (cmd.rfind("DOWNLOAD ", 0) == 0) {
            string fname = cmd.substr(9);
            string path = shared_folder + "/" + fname;
            ifstream in(path, ios::binary);
            if (!in) {
                send_encrypted_message(client_sock, key, iv, "ERR");
                continue;
            }
            send_encrypted_message(client_sock, key, iv, "OK");

            in.seekg(0, ios::end);
            uint64_t sz = in.tellg();
            in.seekg(0);
            uint64_t sz_net = htobe64(sz);
            send_all(client_sock, &sz_net, sizeof(sz_net));

            vector<char> buffer(BUFFER_SIZE);
            while (in) {
                in.read(buffer.data(), buffer.size());
                streamsize r = in.gcount();
                if (r <= 0) break;
                vector<unsigned char> cipher;
                aes_encrypt((const unsigned char *)buffer.data(), r, key, iv, cipher);
                uint32_t clen = htonl(cipher.size());
                send_all(client_sock, &clen, sizeof(clen));
                send_all(client_sock, cipher.data(), cipher.size());
            }
            uint32_t zero = 0;
            send_all(client_sock, &zero, sizeof(zero));
        }

        else if (cmd.rfind("UPLOAD ", 0) == 0) {
            string fname = cmd.substr(7);
            string path = shared_folder + "/" + fname;

            // Confirm ready
            if (!send_encrypted_message(client_sock, key, iv, "OK")) break;

            uint64_t sz_net;
            if (!recv_all(client_sock, &sz_net, sizeof(sz_net))) break;
            uint64_t sz = be64toh(sz_net);

            ofstream out(path, ios::binary);
            if (!out) {
                cerr << "Can't open file for writing: " << path << endl;
                continue;
            }

            uint64_t received = 0;
            while (true) {
                uint32_t clen_net;
                if (!recv_all(client_sock, &clen_net, sizeof(clen_net))) break;
                uint32_t clen = ntohl(clen_net);
                if (clen == 0) break;

                vector<unsigned char> cipher(clen);
                if (!recv_all(client_sock, cipher.data(), clen)) break;

                vector<unsigned char> plain;
                aes_decrypt(cipher.data(), clen, key, iv, plain);

                out.write((const char *)plain.data(), plain.size());
                received += plain.size();
                if (received >= sz) break;
            }
            out.close();
            cout << "✅ Received file " << fname << " from " << username << endl;
        }
    }
    close(client_sock);
    cout << "Client disconnected.\n";
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        cerr << "Usage: ./server <port> <shared_folder>\n";
        return 1;
    }

    int port = stoi(argv[1]);
    string shared_folder = argv[2];
    mkdir(shared_folder.c_str(), 0777);

    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    bind(server_sock, (sockaddr *)&addr, sizeof(addr));
    listen(server_sock, 5);
    cout << "Server started on port " << port << endl;

    unsigned char key[16] = "1234567890abcdef";
    unsigned char iv[16] = "abcdef1234567890";

    while (true) {
        sockaddr_in client_addr{};
        socklen_t len = sizeof(client_addr);
        int client_sock = accept(server_sock, (sockaddr *)&client_addr, &len);
        if (client_sock < 0) continue;
        handle_client(client_sock, key, iv, shared_folder);
    }

    close(server_sock);
    return 0;
}
