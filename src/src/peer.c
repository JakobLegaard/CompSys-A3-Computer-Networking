#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>

#ifdef __APPLE__
#include "./endian.h"
#else
#include <endian.h>
#endif

#include "./peer.h"

#define REQUEST_HEADER_SIZE (IP_LEN + sizeof(uint32_t) + SHA256_HASH_SIZE + sizeof(uint32_t) + sizeof(uint32_t))
#define REPLY_HEADER_SIZE   (sizeof(uint32_t) * 4 + SHA256_HASH_SIZE * 2)
#define PEER_ENTRY_SIZE     (IP_LEN + sizeof(uint32_t) + SHA256_HASH_SIZE + SALT_LEN)
#define MAX_MESSAGE_SIZE    8196

NetworkAddress_t *my_address;
NetworkAddress_t **network = NULL;
uint32_t peer_count = 0;

static void free_network()
{
    if (network == NULL) {
        peer_count = 0;
        return;
    }

    for (uint32_t i = 0; i < peer_count; i++) {
        if (network[i] != NULL) {
            free(network[i]);
        }
    }
    free(network);
    network = NULL;
    peer_count = 0;
}

static void parse_reply_header(const unsigned char *buf, ReplyHeader_t *header)
{
    uint32_t tmp;
    size_t offset = 0;

    memcpy(&tmp, buf + offset, sizeof(uint32_t));
    header->length = ntohl(tmp);
    offset += sizeof(uint32_t);

    memcpy(&tmp, buf + offset, sizeof(uint32_t));
    header->status = ntohl(tmp);
    offset += sizeof(uint32_t);

    memcpy(&tmp, buf + offset, sizeof(uint32_t));
    header->this_block = ntohl(tmp);
    offset += sizeof(uint32_t);

    memcpy(&tmp, buf + offset, sizeof(uint32_t));
    header->block_count = ntohl(tmp);
    offset += sizeof(uint32_t);

    memcpy(header->block_hash, buf + offset, SHA256_HASH_SIZE);
    offset += SHA256_HASH_SIZE;

    memcpy(header->total_hash, buf + offset, SHA256_HASH_SIZE);
}

static void add_self_to_network_if_missing(void)
{
    for (uint32_t i = 0; i < peer_count; i++) {
        if (strncmp(network[i]->ip, my_address->ip, IP_LEN) == 0 &&
            network[i]->port == my_address->port) {
            return;
        }
    }

    NetworkAddress_t *self = (NetworkAddress_t*)malloc(sizeof(NetworkAddress_t));
    if (!self) {
        fprintf(stderr, "Failed to allocate self network entry\n");
        return;
    }

    memset(self, 0, sizeof(NetworkAddress_t));
    memcpy(self->ip, my_address->ip, IP_LEN);
    self->port = my_address->port;
    memcpy(self->salt, my_address->salt, SALT_LEN);
    memcpy(self->signature, my_address->signature, SHA256_HASH_SIZE);

    NetworkAddress_t **new_list =
        (NetworkAddress_t**)realloc(network, sizeof(NetworkAddress_t*) * (peer_count + 1));
    if (!new_list) {
        fprintf(stderr, "Failed to grow network list\n");
        free(self);
        return;
    }

    network = new_list;
    network[peer_count] = self;
    peer_count++;
}

static void update_network_from_body(const char *body, uint32_t body_len)
{
    if (body_len == 0) {
        free_network();
        return;
    }

    if (body_len % PEER_ENTRY_SIZE != 0) {
        fprintf(stderr, "Network body length %u not a multiple of %u\n",
                (unsigned)body_len, (unsigned)PEER_ENTRY_SIZE);
        return;
    }

    uint32_t count = body_len / PEER_ENTRY_SIZE;

    free_network();

    network = (NetworkAddress_t**)malloc(sizeof(NetworkAddress_t*) * count);
    if (network == NULL) {
        fprintf(stderr, "Failed to allocate network list\n");
        return;
    }

    const unsigned char *ptr = (const unsigned char *)body;
    for (uint32_t i = 0; i < count; i++) {
        NetworkAddress_t *addr = (NetworkAddress_t*)malloc(sizeof(NetworkAddress_t));
        if (!addr) {
            fprintf(stderr, "Failed to allocate NetworkAddress_t\n");
            break;
        }

        memset(addr, 0, sizeof(NetworkAddress_t));

        memcpy(addr->ip, ptr, IP_LEN);
        addr->ip[IP_LEN - 1] = '\0';
        ptr += IP_LEN;

        uint32_t port_net;
        memcpy(&port_net, ptr, sizeof(uint32_t));
        addr->port = ntohl(port_net);
        ptr += sizeof(uint32_t);

        memcpy(addr->signature, ptr, SHA256_HASH_SIZE);
        ptr += SHA256_HASH_SIZE;

        memcpy(addr->salt, ptr, SALT_LEN);
        ptr += SALT_LEN;

        network[i] = addr;
    }

    peer_count = count;

    printf("Updated network list (%u peers):\n", peer_count);
    for (uint32_t i = 0; i < peer_count; i++) {
        printf("  Peer %u: IP=%s, Port=%u\n", i, network[i]->ip, network[i]->port);
    }
}

static void send_reply(int connfd, uint32_t status, const char *body, uint32_t body_len)
{
    if (REPLY_HEADER_SIZE + body_len > MAX_MESSAGE_SIZE) {
        fprintf(stderr, "Reply too large for single message\n");
        return;
    }

    ReplyHeader_t hdr;
    hdr.length = body_len;
    hdr.status = status;
    hdr.this_block = 0;
    hdr.block_count = 1;

    if (body_len > 0) {
        get_data_sha((unsigned char*)body, hdr.block_hash, body_len, SHA256_HASH_SIZE);
        memcpy(hdr.total_hash, hdr.block_hash, SHA256_HASH_SIZE);
    } else {
        const char *empty = "";
        get_data_sha((unsigned char*)empty, hdr.block_hash, 0, SHA256_HASH_SIZE);
        memcpy(hdr.total_hash, hdr.block_hash, SHA256_HASH_SIZE);
    }

    unsigned char *buf = (unsigned char*)malloc(REPLY_HEADER_SIZE + body_len);
    if (!buf) {
        fprintf(stderr, "Failed to allocate reply buffer\n");
        return;
    }

    size_t offset = 0;
    uint32_t tmp;

    tmp = htonl(hdr.length);
    memcpy(buf + offset, &tmp, sizeof(uint32_t));
    offset += sizeof(uint32_t);

    tmp = htonl(hdr.status);
    memcpy(buf + offset, &tmp, sizeof(uint32_t));
    offset += sizeof(uint32_t);

    tmp = htonl(hdr.this_block);
    memcpy(buf + offset, &tmp, sizeof(uint32_t));
    offset += sizeof(uint32_t);

    tmp = htonl(hdr.block_count);
    memcpy(buf + offset, &tmp, sizeof(uint32_t));
    offset += sizeof(uint32_t);

    memcpy(buf + offset, hdr.block_hash, SHA256_HASH_SIZE);
    offset += SHA256_HASH_SIZE;

    memcpy(buf + offset, hdr.total_hash, SHA256_HASH_SIZE);
    offset += SHA256_HASH_SIZE;

    if (body_len > 0) {
        memcpy(buf + offset, body, body_len);
        offset += body_len;
    }

    compsys_helper_writen(connfd, buf, offset);
    free(buf);
}

static void send_inform_to_others(NetworkAddress_t *new_peer)
{
    if (peer_count == 0) {
        return;
    }

    char body[PEER_ENTRY_SIZE];
    unsigned char *ptr = (unsigned char*)body;

    memcpy(ptr, new_peer->ip, IP_LEN);
    ptr += IP_LEN;

    uint32_t port_net = htonl(new_peer->port);
    memcpy(ptr, &port_net, sizeof(uint32_t));
    ptr += sizeof(uint32_t);

    memcpy(ptr, new_peer->signature, SHA256_HASH_SIZE);
    ptr += SHA256_HASH_SIZE;

    memcpy(ptr, new_peer->salt, SALT_LEN);
    ptr += SALT_LEN;

    for (uint32_t i = 0; i < peer_count; i++) {
        NetworkAddress_t *p = network[i];

        if (strncmp(p->ip, new_peer->ip, IP_LEN) == 0 && p->port == new_peer->port) {
            continue;
        }

        char port_str[PORT_STR_LEN];
        snprintf(port_str, sizeof(port_str), "%u", p->port);

        int fd = compsys_helper_open_clientfd(p->ip, port_str);
        if (fd < 0) {
            continue;
        }

        unsigned char req[REQUEST_HEADER_SIZE];
        memset(req, 0, sizeof(req));
        size_t offset = 0;

        memcpy(req + offset, my_address->ip, IP_LEN);
        offset += IP_LEN;

        uint32_t my_port_net = htonl(my_address->port);
        memcpy(req + offset, &my_port_net, sizeof(uint32_t));
        offset += sizeof(uint32_t);

        memcpy(req + offset, my_address->signature, SHA256_HASH_SIZE);
        offset += SHA256_HASH_SIZE;

        uint32_t cmd_net = htonl(COMMAND_INFORM);
        memcpy(req + offset, &cmd_net, sizeof(uint32_t));
        offset += sizeof(uint32_t);

        uint32_t len_net = htonl(PEER_ENTRY_SIZE);
        memcpy(req + offset, &len_net, sizeof(uint32_t));
        offset += sizeof(uint32_t);

        if (offset != REQUEST_HEADER_SIZE) {
            close(fd);
            continue;
        }

        compsys_helper_writen(fd, req, REQUEST_HEADER_SIZE);
        compsys_helper_writen(fd, body, PEER_ENTRY_SIZE);

        close(fd);
    }
}

static NetworkAddress_t* pick_random_peer(void)
{
    if (peer_count == 0) {
        return NULL;
    }

    int attempts = 0;
    while (attempts < (int)peer_count * 2) {
        uint32_t idx = (uint32_t)(rand() % peer_count);
        NetworkAddress_t *p = network[idx];
        if (p &&
            (strncmp(p->ip, my_address->ip, IP_LEN) != 0 || p->port != my_address->port)) {
            return p;
        }
        attempts++;
    }

    for (uint32_t i = 0; i < peer_count; i++) {
        NetworkAddress_t *p = network[i];
        if (p &&
            (strncmp(p->ip, my_address->ip, IP_LEN) != 0 || p->port != my_address->port)) {
            return p;
        }
    }

    return NULL;
}

static void retrieve_file_from_network(const char *filename)
{
    if (filename == NULL || filename[0] == '\0') {
        return;
    }

    NetworkAddress_t *target = pick_random_peer();
    if (!target) {
        printf("No peers available to retrieve from.\n");
        return;
    }

    char port_str[PORT_STR_LEN];
    snprintf(port_str, sizeof(port_str), "%u", target->port);

    int clientfd = compsys_helper_open_clientfd(target->ip, port_str);
    if (clientfd < 0) {
        fprintf(stderr, "Failed to open connection to peer %s:%s for retrieve\n",
                target->ip, port_str);
        return;
    }

    size_t fname_len = strlen(filename);
    if (REQUEST_HEADER_SIZE + fname_len > MAX_MESSAGE_SIZE) {
        fprintf(stderr, "Requested filename too long\n");
        close(clientfd);
        return;
    }

    unsigned char request[REQUEST_HEADER_SIZE];
    memset(request, 0, sizeof(request));
    size_t offset = 0;

    memcpy(request + offset, my_address->ip, IP_LEN);
    offset += IP_LEN;

    uint32_t port_net = htonl(my_address->port);
    memcpy(request + offset, &port_net, sizeof(uint32_t));
    offset += sizeof(uint32_t);

    memcpy(request + offset, my_address->signature, SHA256_HASH_SIZE);
    offset += SHA256_HASH_SIZE;

    uint32_t command_net = htonl(COMMAND_RETREIVE);
    memcpy(request + offset, &command_net, sizeof(uint32_t));
    offset += sizeof(uint32_t);

    uint32_t length_net = htonl((uint32_t)fname_len);
    memcpy(request + offset, &length_net, sizeof(uint32_t));
    offset += sizeof(uint32_t);

    if (offset != REQUEST_HEADER_SIZE) {
        fprintf(stderr, "Internal error assembling retrieve request header\n");
        close(clientfd);
        return;
    }

    if (compsys_helper_writen(clientfd, request, REQUEST_HEADER_SIZE) < 0) {
        fprintf(stderr, "Failed to send retrieve request header\n");
        close(clientfd);
        return;
    }

    if (fname_len > 0) {
        if (compsys_helper_writen(clientfd, filename, fname_len) < 0) {
            fprintf(stderr, "Failed to send retrieve request body\n");
            close(clientfd);
            return;
        }
    }

    unsigned char reply_buf[REPLY_HEADER_SIZE];
    ssize_t n = compsys_helper_readn(clientfd, reply_buf, REPLY_HEADER_SIZE);
    if (n != REPLY_HEADER_SIZE) {
        fprintf(stderr, "Failed to read first reply header for retrieve (got %zd bytes)\n", n);
        close(clientfd);
        return;
    }

    ReplyHeader_t reply_header;
    parse_reply_header(reply_buf, &reply_header);

    if (reply_header.status != 1) {
        printf("Retrieve failed with status %u\n", reply_header.status);
        close(clientfd);
        return;
    }

    uint32_t total_blocks = reply_header.block_count;
    uint32_t received_blocks = 0;
    uint32_t total_len = 0;

    char *file_data = NULL;

    while (1) {
        uint32_t body_len = reply_header.length;
        char *block = NULL;

        if (body_len > 0) {
            block = (char*)malloc(body_len);
            if (!block) {
                fprintf(stderr, "Failed to allocate memory for block\n");
                free(file_data);
                close(clientfd);
                return;
            }

            ssize_t r = compsys_helper_readn(clientfd, block, body_len);
            if (r != (ssize_t)body_len) {
                fprintf(stderr, "Failed to read block body (expected %u, got %zd)\n",
                        body_len, r);
                free(block);
                free(file_data);
                close(clientfd);
                return;
            }

            unsigned char computed_block_hash[SHA256_HASH_SIZE];
            get_data_sha((unsigned char*)block, computed_block_hash, body_len,
                         SHA256_HASH_SIZE);
            if (memcmp(computed_block_hash, reply_header.block_hash, SHA256_HASH_SIZE) != 0) {
                fprintf(stderr, "Block hash mismatch on block %u\n", reply_header.this_block);
                free(block);
                free(file_data);
                close(clientfd);
                return;
            }

            char *new_buf = (char*)realloc(file_data, total_len + body_len);
            if (!new_buf) {
                fprintf(stderr, "Failed to grow file buffer\n");
                free(block);
                free(file_data);
                close(clientfd);
                return;
            }
            file_data = new_buf;
            memcpy(file_data + total_len, block, body_len);
            total_len += body_len;

            free(block);
        }

        received_blocks++;

        if (received_blocks >= total_blocks) {
            break;
        }

        n = compsys_helper_readn(clientfd, reply_buf, REPLY_HEADER_SIZE);
        if (n != REPLY_HEADER_SIZE) {
            fprintf(stderr, "Failed to read subsequent reply header (got %zd bytes)\n", n);
            free(file_data);
            close(clientfd);
            return;
        }

        parse_reply_header(reply_buf, &reply_header);

        if (reply_header.status != 1) {
            fprintf(stderr, "Non-success status %u on subsequent block\n", reply_header.status);
            free(file_data);
            close(clientfd);
            return;
        }

        if (reply_header.block_count != total_blocks) {
            fprintf(stderr, "Inconsistent block_count in subsequent block\n");
            free(file_data);
            close(clientfd);
            return;
        }
    }

    printf("Retrieve reply. Status: 1, length: %u\n", total_len);

    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        fprintf(stderr, "Failed to open local file '%s' for writing\n", filename);
    } else {
        size_t written = fwrite(file_data, 1, total_len, fp);
        fclose(fp);
        printf("Wrote %zu bytes to file '%s'\n", written, filename);
    }

    free(file_data);
    close(clientfd);
}

static void* handle_connection(void *arg)
{
    int connfd = *(int*)arg;
    free(arg);

    unsigned char req_buf[REQUEST_HEADER_SIZE];
    ssize_t n = compsys_helper_readn(connfd, req_buf, REQUEST_HEADER_SIZE);
    if (n != REQUEST_HEADER_SIZE) {
        fprintf(stderr, "Received malformed or short request (%zd bytes)\n", n);
        send_reply(connfd, 7, NULL, 0);
        close(connfd);
        return NULL;
    }

    RequestHeader_t req;
    size_t offset = 0;

    memset(&req, 0, sizeof(RequestHeader_t));

    memcpy(req.ip, req_buf + offset, IP_LEN);
    req.ip[IP_LEN - 1] = '\0';
    offset += IP_LEN;

    uint32_t tmp32;

    memcpy(&tmp32, req_buf + offset, sizeof(uint32_t));
    req.port = ntohl(tmp32);
    offset += sizeof(uint32_t);

    memcpy(req.signature, req_buf + offset, SHA256_HASH_SIZE);
    offset += SHA256_HASH_SIZE;

    memcpy(&tmp32, req_buf + offset, sizeof(uint32_t));
    req.command = ntohl(tmp32);
    offset += sizeof(uint32_t);

    memcpy(&tmp32, req_buf + offset, sizeof(uint32_t));
    req.length = ntohl(tmp32);
    offset += sizeof(uint32_t);

    char *body = NULL;
    if (req.length > 0) {
        if (REQUEST_HEADER_SIZE + req.length > MAX_MESSAGE_SIZE) {
            fprintf(stderr, "Request body too large\n");
            send_reply(connfd, 7, NULL, 0);
            close(connfd);
            return NULL;
        }

        body = (char*)malloc(req.length);
        if (!body) {
            fprintf(stderr, "Failed to allocate request body\n");
            send_reply(connfd, 6, NULL, 0);
            close(connfd);
            return NULL;
        }

        ssize_t r = compsys_helper_readn(connfd, body, req.length);
        if (r != (ssize_t)req.length) {
            fprintf(stderr, "Failed to read full request body\n");
            free(body);
            send_reply(connfd, 7, NULL, 0);
            close(connfd);
            return NULL;
        }
    }

    if (req.command == COMMAND_REGISTER) {
        add_self_to_network_if_missing();

        int exists = 0;
        NetworkAddress_t *peer = NULL;

        for (uint32_t i = 0; i < peer_count; i++) {
            if (strncmp(network[i]->ip, req.ip, IP_LEN) == 0 &&
                network[i]->port == req.port) {
                exists = 1;
                peer = network[i];
                break;
            }
        }

        if (!exists) {
            peer = (NetworkAddress_t*)malloc(sizeof(NetworkAddress_t));
            if (!peer) {
                fprintf(stderr, "Failed to allocate new peer entry\n");
                send_reply(connfd, 6, NULL, 0);
                if (body) free(body);
                close(connfd);
                return NULL;
            }

            memset(peer, 0, sizeof(NetworkAddress_t));
            memcpy(peer->ip, req.ip, IP_LEN);
            peer->port = req.port;

            char salt[SALT_LEN];
            generate_random_salt(salt);
            memcpy(peer->salt, salt, SALT_LEN);

            char sig_input[SHA256_HASH_SIZE + SALT_LEN];
            memcpy(sig_input, req.signature, SHA256_HASH_SIZE);
            memcpy(sig_input + SHA256_HASH_SIZE, salt, SALT_LEN);
            get_data_sha((unsigned char*)sig_input, peer->signature,
                         SHA256_HASH_SIZE + SALT_LEN, SHA256_HASH_SIZE);

            NetworkAddress_t **new_list =
                (NetworkAddress_t**)realloc(network, sizeof(NetworkAddress_t*) * (peer_count + 1));
            if (!new_list) {
                fprintf(stderr, "Failed to grow network list\n");
                free(peer);
                send_reply(connfd, 6, NULL, 0);
                if (body) free(body);
                close(connfd);
                return NULL;
            }

            network = new_list;
            network[peer_count] = peer;
            peer_count++;

            send_inform_to_others(peer);
        }

        uint32_t count = peer_count;
        uint32_t body_len = count * PEER_ENTRY_SIZE;
        char *resp_body = (char*)malloc(body_len);
        if (!resp_body) {
            fprintf(stderr, "Failed to allocate response body\n");
            send_reply(connfd, 6, NULL, 0);
            if (body) free(body);
            close(connfd);
            return NULL;
        }

        unsigned char *ptr = (unsigned char*)resp_body;
        for (uint32_t i = 0; i < count; i++) {
            NetworkAddress_t *p = network[i];

            memcpy(ptr, p->ip, IP_LEN);
            ptr += IP_LEN;

            uint32_t port_net = htonl(p->port);
            memcpy(ptr, &port_net, sizeof(uint32_t));
            ptr += sizeof(uint32_t);

            memcpy(ptr, p->signature, SHA256_HASH_SIZE);
            ptr += SHA256_HASH_SIZE;

            memcpy(ptr, p->salt, SALT_LEN);
            ptr += SALT_LEN;
        }

        uint32_t status = exists ? 2 : 1;
        send_reply(connfd, status, resp_body, body_len);
        free(resp_body);
    } else if (req.command == COMMAND_INFORM) {
        if (req.length != PEER_ENTRY_SIZE || body == NULL) {
            if (body) free(body);
            close(connfd);
            return NULL;
        }

        const unsigned char *ptr = (const unsigned char*)body;
        NetworkAddress_t *peer = (NetworkAddress_t*)malloc(sizeof(NetworkAddress_t));
        if (!peer) {
            if (body) free(body);
            close(connfd);
            return NULL;
        }

        memset(peer, 0, sizeof(NetworkAddress_t));

        memcpy(peer->ip, ptr, IP_LEN);
        peer->ip[IP_LEN - 1] = '\0';
        ptr += IP_LEN;

        uint32_t port_net;
        memcpy(&port_net, ptr, sizeof(uint32_t));
        peer->port = ntohl(port_net);
        ptr += sizeof(uint32_t);

        memcpy(peer->signature, ptr, SHA256_HASH_SIZE);
        ptr += SHA256_HASH_SIZE;

        memcpy(peer->salt, ptr, SALT_LEN);
        ptr += SALT_LEN;

        int exists = 0;
        for (uint32_t i = 0; i < peer_count; i++) {
            if (strncmp(network[i]->ip, peer->ip, IP_LEN) == 0 &&
                network[i]->port == peer->port) {
                exists = 1;
                break;
            }
        }

        if (!exists) {
            NetworkAddress_t **new_list =
                (NetworkAddress_t**)realloc(network, sizeof(NetworkAddress_t*) * (peer_count + 1));
            if (!new_list) {
                free(peer);
                if (body) free(body);
                close(connfd);
                return NULL;
            }

            network = new_list;
            network[peer_count] = peer;
            peer_count++;

            printf("INFORM: added peer IP=%s, Port=%u\n", peer->ip, peer->port);
        } else {
            free(peer);
        }
    } else if (req.command == COMMAND_RETREIVE) {
        int known = 0;
        for (uint32_t i = 0; i < peer_count; i++) {
            if (strncmp(network[i]->ip, req.ip, IP_LEN) == 0 &&
                network[i]->port == req.port) {
                known = 1;
                break;
            }
        }

        if (!known) {
            send_reply(connfd, 3, NULL, 0);
        } else if (body == NULL || req.length == 0) {
            send_reply(connfd, 7, NULL, 0);
        } else {
            char *filename = (char*)malloc(req.length + 1);
            if (!filename) {
                send_reply(connfd, 6, NULL, 0);
            } else {
                memcpy(filename, body, req.length);
                filename[req.length] = '\0';

                FILE *fp = fopen(filename, "rb");
                if (!fp) {
                    send_reply(connfd, 5, NULL, 0);
                } else {
                    if (fseek(fp, 0, SEEK_END) != 0) {
                        fclose(fp);
                        send_reply(connfd, 6, NULL, 0);
                    } else {
                        long fsize_long = ftell(fp);
                        if (fsize_long < 0) {
                            fclose(fp);
                            send_reply(connfd, 6, NULL, 0);
                        } else {
                            uint32_t fsize = (uint32_t)fsize_long;
                            rewind(fp);

                            char *filebuf = (char*)malloc(fsize);
                            if (!filebuf) {
                                fclose(fp);
                                send_reply(connfd, 6, NULL, 0);
                            } else {
                                size_t read_bytes = fread(filebuf, 1, fsize, fp);
                                fclose(fp);

                                if (read_bytes != fsize) {
                                    free(filebuf);
                                    send_reply(connfd, 6, NULL, 0);
                                } else {
                                    uint32_t max_body = MAX_MESSAGE_SIZE - REPLY_HEADER_SIZE;
                                    uint32_t block_count = (fsize == 0) ? 1 :
                                        (fsize + max_body - 1) / max_body;

                                    unsigned char total_hash[SHA256_HASH_SIZE];
                                    if (fsize > 0) {
                                        get_data_sha((unsigned char*)filebuf, total_hash,
                                                     fsize, SHA256_HASH_SIZE);
                                    } else {
                                        const char *empty = "";
                                        get_data_sha((unsigned char*)empty, total_hash,
                                                     0, SHA256_HASH_SIZE);
                                    }

                                    for (uint32_t b = 0; b < block_count; b++) {
                                        uint32_t offset_b = b * max_body;
                                        uint32_t this_len;
                                        if (b == block_count - 1) {
                                            if (fsize > offset_b) {
                                                this_len = fsize - offset_b;
                                            } else {
                                                this_len = 0;
                                            }
                                        } else {
                                            this_len = max_body;
                                        }

                                        ReplyHeader_t rh;
                                        rh.length = this_len;
                                        rh.status = 1;
                                        rh.this_block = b;
                                        rh.block_count = block_count;

                                        unsigned char block_hash[SHA256_HASH_SIZE];
                                        if (this_len > 0) {
                                            get_data_sha((unsigned char*)(filebuf + offset_b),
                                                         block_hash, this_len,
                                                         SHA256_HASH_SIZE);
                                        } else {
                                            const char *empty = "";
                                            get_data_sha((unsigned char*)empty, block_hash,
                                                         0, SHA256_HASH_SIZE);
                                        }

                                        memcpy(rh.block_hash, block_hash, SHA256_HASH_SIZE);
                                        memcpy(rh.total_hash, total_hash, SHA256_HASH_SIZE);

                                        unsigned char header_buf[REPLY_HEADER_SIZE];
                                        size_t h_off = 0;
                                        uint32_t t;

                                        t = htonl(rh.length);
                                        memcpy(header_buf + h_off, &t, sizeof(uint32_t));
                                        h_off += sizeof(uint32_t);

                                        t = htonl(rh.status);
                                        memcpy(header_buf + h_off, &t, sizeof(uint32_t));
                                        h_off += sizeof(uint32_t);

                                        t = htonl(rh.this_block);
                                        memcpy(header_buf + h_off, &t, sizeof(uint32_t));
                                        h_off += sizeof(uint32_t);

                                        t = htonl(rh.block_count);
                                        memcpy(header_buf + h_off, &t, sizeof(uint32_t));
                                        h_off += sizeof(uint32_t);

                                        memcpy(header_buf + h_off, rh.block_hash, SHA256_HASH_SIZE);
                                        h_off += SHA256_HASH_SIZE;

                                        memcpy(header_buf + h_off, rh.total_hash, SHA256_HASH_SIZE);
                                        h_off += SHA256_HASH_SIZE;

                                        compsys_helper_writen(connfd, header_buf, h_off);

                                        if (this_len > 0) {
                                            compsys_helper_writen(connfd,
                                                                  filebuf + offset_b,
                                                                  this_len);
                                        }
                                    }

                                    free(filebuf);
                                }
                            }
                        }
                    }
                }

                free(filename);
            }
        }
    } else {
        send_reply(connfd, 7, NULL, 0);
    }

    if (body) {
        free(body);
    }

    close(connfd);
    return NULL;
}

void* client_thread()
{
    char peer_ip[IP_LEN];
    fprintf(stdout, "Enter peer IP to connect to: ");
    scanf("%16s", peer_ip);

    for (int i = strlen(peer_ip); i < IP_LEN; i++) {
        peer_ip[i] = '\0';
    }

    char peer_port[PORT_STR_LEN];
    fprintf(stdout, "Enter peer port to connect to: ");
    scanf("%16s", peer_port);

    for (int i = strlen(peer_port); i < PORT_STR_LEN; i++) {
        peer_port[i] = '\0';
    }

    NetworkAddress_t peer_address;
    memset(&peer_address, 0, sizeof(NetworkAddress_t));
    memcpy(peer_address.ip, peer_ip, IP_LEN);
    peer_address.port = atoi(peer_port);

    int clientfd = compsys_helper_open_clientfd(peer_address.ip, peer_port);
    if (clientfd < 0) {
        fprintf(stderr, "Failed to open connection to peer %s:%s\n", peer_ip, peer_port);
        return NULL;
    }

    unsigned char request[REQUEST_HEADER_SIZE];
    memset(request, 0, sizeof(request));
    size_t offset = 0;

    memcpy(request + offset, my_address->ip, IP_LEN);
    offset += IP_LEN;

    uint32_t port_net = htonl(my_address->port);
    memcpy(request + offset, &port_net, sizeof(uint32_t));
    offset += sizeof(uint32_t);

    memcpy(request + offset, my_address->signature, SHA256_HASH_SIZE);
    offset += SHA256_HASH_SIZE;

    uint32_t command_net = htonl(COMMAND_REGISTER);
    memcpy(request + offset, &command_net, sizeof(uint32_t));
    offset += sizeof(uint32_t);

    uint32_t length_net = htonl(0);
    memcpy(request + offset, &length_net, sizeof(uint32_t));
    offset += sizeof(uint32_t);

    if (offset != REQUEST_HEADER_SIZE) {
        fprintf(stderr, "Internal error assembling request header\n");
        close(clientfd);
        return NULL;
    }

    if (compsys_helper_writen(clientfd, request, REQUEST_HEADER_SIZE) < 0) {
        fprintf(stderr, "Failed to send register request\n");
        close(clientfd);
        return NULL;
    }

    unsigned char reply_buf[REPLY_HEADER_SIZE];
    ssize_t n = compsys_helper_readn(clientfd, reply_buf, REPLY_HEADER_SIZE);
    if (n != REPLY_HEADER_SIZE) {
        fprintf(stderr, "Failed to read full reply header (got %zd bytes)\n", n);
        close(clientfd);
        return NULL;
    }

    ReplyHeader_t reply_header;
    parse_reply_header(reply_buf, &reply_header);

    uint32_t body_len = reply_header.length;
    char *body = NULL;

    if (body_len > 0) {
        body = (char *)malloc(body_len);
        if (!body) {
            fprintf(stderr, "Failed to allocate memory for reply body\n");
            close(clientfd);
            return NULL;
        }

        ssize_t r = compsys_helper_readn(clientfd, body, body_len);
        if (r != (ssize_t)body_len) {
            fprintf(stderr, "Failed to read full reply body (expected %u, got %zd)\n",
                    body_len, r);
            free(body);
            close(clientfd);
            return NULL;
        }
    }

    printf("Got reply. Status: %u, length: %u\n",
           reply_header.status, reply_header.length);

    if ((reply_header.status == 1 || reply_header.status == 2) && body_len > 0) {
        update_network_from_body(body, body_len);
    }

    if (body) {
        free(body);
    }

    close(clientfd);

    while (1) {
        char filename[256];
        printf("Enter filename to retrieve (or 'quit' to exit): ");
        if (scanf("%255s", filename) != 1) {
            break;
        }
        if (strcmp(filename, "quit") == 0) {
            break;
        }
        retrieve_file_from_network(filename);
    }

    return NULL;
}


void* server_thread()
{
    add_self_to_network_if_missing();

    char port_str[PORT_STR_LEN];
    snprintf(port_str, sizeof(port_str), "%u", my_address->port);

    int listenfd = compsys_helper_open_listenfd(port_str);
    if (listenfd < 0) {
        fprintf(stderr, "Failed to open listening socket on port %s\n", port_str);
        return NULL;
    }

    printf("Server listening on %s:%s\n", my_address->ip, port_str);

    while (1) {
        struct sockaddr_storage clientaddr;
        socklen_t clientlen = sizeof(clientaddr);
        int *connfdp = (int*)malloc(sizeof(int));
        if (!connfdp) {
            fprintf(stderr, "Failed to allocate connfd pointer\n");
            continue;
        }

        *connfdp = accept(listenfd, (struct sockaddr *)&clientaddr, &clientlen);
        if (*connfdp < 0) {
            free(connfdp);
            continue;
        }

        pthread_t tid;
        if (pthread_create(&tid, NULL, handle_connection, connfdp) != 0) {
            fprintf(stderr, "Failed to create connection handler thread\n");
            close(*connfdp);
            free(connfdp);
            continue;
        }
        pthread_detach(tid);
    }

    return NULL;
}

int main(int argc, char **argv)
{
    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s <IP> <PORT>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    my_address = (NetworkAddress_t*)malloc(sizeof(NetworkAddress_t));
    if (!my_address) {
        fprintf(stderr, "Failed to allocate memory for my_address\n");
        exit(EXIT_FAILURE);
    }

    memset(my_address->ip, '\0', IP_LEN);
    memcpy(my_address->ip, argv[1], strlen(argv[1]));
    my_address->port = atoi(argv[2]);

    if (!is_valid_ip(my_address->ip)) {
        fprintf(stderr, ">> Invalid peer IP: %s\n", my_address->ip);
        exit(EXIT_FAILURE);
    }

    if (!is_valid_port(my_address->port)) {
        fprintf(stderr, ">> Invalid peer port: %d\n", my_address->port);
        exit(EXIT_FAILURE);
    }

    srand((unsigned int)time(NULL));

    char password[PASSWORD_LEN];
    fprintf(stdout, "Create a password to proceed: ");
    scanf("%16s", password);

    for (int i = strlen(password); i < PASSWORD_LEN; i++) {
        password[i] = '\0';
    }

    char salt[SALT_LEN + 1] = "0123456789ABCDEF";
    memcpy(my_address->salt, salt, SALT_LEN);

    char salted[PASSWORD_LEN + SALT_LEN + 1];
    memset(salted, 0, sizeof(salted));
    snprintf(salted, sizeof(salted), "%s%s", password, salt);
    get_data_sha((unsigned char*)salted, my_address->signature,
                 (uint32_t)strlen(salted), SHA256_HASH_SIZE);

    pthread_t client_thread_id;
    pthread_t server_thread_id;
    pthread_create(&client_thread_id, NULL, client_thread, NULL);
    pthread_create(&server_thread_id, NULL, server_thread, NULL);

    pthread_join(client_thread_id, NULL);
    pthread_join(server_thread_id, NULL);

    free_network();
    if (my_address) {
        free(my_address);
    }

    exit(EXIT_SUCCESS);
}
