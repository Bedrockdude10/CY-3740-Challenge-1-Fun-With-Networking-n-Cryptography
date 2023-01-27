#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sodium.h>

#define TOKEN_SIZE 128
#define PAYLOAD_SIZE crypto_secretbox_MACBYTES + TOKEN_SIZE
#define MSG_ASK "Can I get the solution to the challenge, please?"
#define STATUS_BAD 0
#define STATUS_GOOD 1

// Message format
struct message {
    int sender_id;
    int status;
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    unsigned char payload[PAYLOAD_SIZE];
};

int main() {

    // Check that sodium correctly initialized
    assert(sodium_init() > -1);

    // Create net socket
    int net_socket;
    net_socket = socket(AF_INET, SOCK_STREAM, 0);
    assert(net_socket > -1);

    // Specify family, IP address and port
    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = inet_addr("192.168.1.77");
    server_address.sin_port = htons(4000);
    server_address.sin_zero[8] = '\0';

    // attempt connection to server address from socket
    int connection_status = connect(net_socket, (struct sockaddr *) &server_address,
                                    sizeof(server_address));
    assert(connection_status > -1);

    // create the message to send to the server
    struct message mes;
    mes.sender_id = 42;

    // crypto
    // message buffer
    unsigned char send_buffer[TOKEN_SIZE];
    strcpy(send_buffer, MSG_ASK);
    // key
    unsigned char key[crypto_secretbox_KEYBYTES];
    FILE *fp = fopen("/home/hackers/hacker42/key", "rb");
    assert(fp != NULL);
    fread(key, crypto_secretbox_KEYBYTES, 1, fp);
    fclose(fp);

    // flag if message is correctly decrypted and authenticated (-1 means fail, 0 means success)
    int decrypto_status = -1;
    // buffer for the token retrieved from the return message
    unsigned char token_val[TOKEN_SIZE];
    while (decrypto_status == -1) {

        // nonce creation
        randombytes_buf(mes.nonce, sizeof(mes.nonce));
        assert(mes.nonce != NULL);

        // payload encryption
        int crypto_status = crypto_secretbox_easy(mes.payload, send_buffer, TOKEN_SIZE, mes.nonce, key);
        assert(crypto_status > -1);

        // send message to the server
        int send_status = send(net_socket, &mes, sizeof(mes), 0);
        assert(send_status > -1);

        // receive data from the server
        unsigned char receive_buffer[sizeof(mes)];
        int valread = read(net_socket, receive_buffer, sizeof(mes));
        assert(valread == sizeof(mes));

        // cast received bytes to message struct
        struct message *received_msg = (struct message *) receive_buffer;
        // check message status
        if (received_msg->status == STATUS_BAD) {
            printf("Bad status. Server returned message: %s\n", received_msg->payload);
        } else {
            decrypto_status = crypto_secretbox_open_easy(token_val, received_msg->payload, PAYLOAD_SIZE,
                                                         received_msg->nonce, key);
        }
    }

    // hashing the token
    unsigned char hash[crypto_generichash_BYTES];
    int hash_status = crypto_generichash(hash, crypto_generichash_BYTES, token_val, sizeof(token_val), NULL, 0);
    assert(hash_status > -1);

    // base64 encoding the token
    char b64[sodium_base64_ENCODED_LEN(crypto_generichash_BYTES, sodium_base64_VARIANT_ORIGINAL)];
    sodium_bin2base64(b64, sizeof(b64), hash, crypto_generichash_BYTES, sodium_base64_VARIANT_ORIGINAL);
    printf(b64, "\n");

    return 0;
}
