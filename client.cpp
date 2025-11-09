#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <fstream>
#include <vector>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <sys/socket.h>
#include <sys/types.h>

using namespace std;

#define BUFFER_SIZE 4096

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

int main(int argc, char *argv[]) {
    if (argc != 3) {
        cerr << "Usage: ./client <server_ip> <port>\n";
        return 1;
    }

    string server_ip = argv[1];
    int port = stoi(argv[2]);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, server_ip.c_str(), &addr.sin_addr);

    if (connect(sock, (sockaddr *)&addr, sizeof(addr)) < 0) {
        cerr << "Connection failed\n";
        return 1;
    }

    unsigned char key[16] = "1234567890abcdef";
    unsigned char iv[16] = "abcdef1234567890";

    string username, password;
    cout << "Username: ";
    getline(cin, username);
    cout << "Password: ";
    getline(cin, password);

    send_encrypted_message(sock, key, iv, username);
    send_encrypted_message(sock, key, iv, password);

    string auth;
    if (!recv_encrypted_message(sock, key, iv, auth)) {
        cerr << "Auth failed\n";
        return 1;
    }
    if (auth != "OK") {
        cerr << "Invalid credentials\n";
        return 1;
    }

    cout << "Authenticated OK\nCommands: LIST | DOWNLOAD <filename> | UPLOAD <filename> | QUIT\n> ";

    string line;
    while (getline(cin, line)) {
        if (line == "QUIT") {
            send_encrypted_message(sock, key, iv, line);
            break;
        }

        else if (line == "LIST") {
            send_encrypted_message(sock, key, iv, line);
            string list;
            recv_encrypted_message(sock, key, iv, list);
            cout << list;
        }

        else if (line.rfind("DOWNLOAD ", 0) == 0) {
            send_encrypted_message(sock, key, iv, line);
            string ok;
            recv_encrypted_message(sock, key, iv, ok);
            if (ok != "OK") {
                cout << "File not found on server\n";
                continue;
            }
            uint64_t sz_net;
            recv_all(sock, &sz_net, sizeof(sz_net));
            uint64_t sz = be64toh(sz_net);

            string fname = line.substr(9);
            ofstream out(fname, ios::binary);
            uint64_t received = 0;

            while (true) {
                uint32_t clen_net;
                recv_all(sock, &clen_net, sizeof(clen_net));
                uint32_t clen = ntohl(clen_net);
                if (clen == 0) break;

                vector<unsigned char> cipher(clen);
                recv_all(sock, cipher.data(), clen);

                vector<unsigned char> plain;
                aes_decrypt(cipher.data(), clen, key, iv, plain);

                out.write((const char *)plain.data(), plain.size());
                received += plain.size();
                if (received >= sz) break;
            }
            out.close();
            cout << "Downloaded " << fname << " (" << received << " bytes)\n";
        }

        else if (line.rfind("UPLOAD ", 0) == 0) {
            string fname = line.substr(7);
            ifstream in(fname, ios::binary);
            if (!in) {
                cout << "Can't open " << fname << "\n";
                continue;
            }

            // send upload command
            if (!send_encrypted_message(sock, key, iv, line)) break;

            // wait for OK
            string ok;
            if (!recv_encrypted_message(sock, key, iv, ok)) {
                cerr << "Upload handshake failed\n";
                break;
            }
            if (ok != "OK") {
                cout << "Server didn't accept upload\n";
                continue;
            }

            // send file size
            in.seekg(0, ios::end);
            uint64_t sz = in.tellg();
            in.seekg(0);
            uint64_t sz_net = htobe64(sz);
            send_all(sock, &sz_net, sizeof(sz_net));

            vector<char> buffer(BUFFER_SIZE);
            while (in) {
                in.read(buffer.data(), buffer.size());
                streamsize r = in.gcount();
                if (r <= 0) break;
                vector<unsigned char> cipher;
                aes_encrypt((const unsigned char *)buffer.data(), r, key, iv, cipher);
                uint32_t clen = htonl(cipher.size());
                send_all(sock, &clen, sizeof(clen));
                send_all(sock, cipher.data(), cipher.size());
            }
            uint32_t zero = 0;
            send_all(sock, &zero, sizeof(zero));
            cout << "Uploaded " << fname << "\n";
        }

        cout << "Commands: LIST | DOWNLOAD <filename> | UPLOAD <filename> | QUIT\n> ";
    }

    close(sock);
    return 0;
}
