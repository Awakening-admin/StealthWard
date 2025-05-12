#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <libgen.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <netdb.h>
#include <jansson.h>
#include <signal.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <syslog.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/wait.h>

#define MAX_PACKETS 1000
#define PCAP_DIR "/var/edr_agent/pcap_files"
#define ALERT_DIR "/var/edr_agent/alerts"
#define SSH_BRUTE_THRESH 10
#define DELAYED_SSH_THRESH 30
#define FTP_BRUTE_THRESH 15
#define PORT_SCAN_THRESH 20
#define AGGRESSIVE_SCAN_THRESH 30
#define AGGRESSIVE_SCAN_WINDOW 30
#define DNS_QUERY_THRESH 100
#define SYN_FLOOD_THRESH 500
#define ICMP_FLOOD_THRESH 1000
#define UDP_FLOOD_THRESH 1000
#define SNAPLEN 65535
#define ADMIN_IP "192.168.18.32"
#define ADMIN_USERNAME "liza"

typedef struct {
    int ssh_attempts;
    int ssh_total_attempts;
    time_t first_ssh_time;
    int ftp_attempts;
    int scanned_ports[65536];
    int port_scan_count;
    time_t first_port_scan_time;
    int dns_queries;
    int syn_packets;
    int icmp_count;
    int udp_flood_count;
    time_t last_reset;
} AttackCounters;

typedef struct {
    json_t *alerts;
    char alert_filename[256];
    const char *pcap_filename;
} AlertContext;

void log_message(const char *format, ...);
void console_log(const char *format, ...);
const char* detect_interface();
const char* get_current_timestamp();
char* get_endpoint_ip();

volatile sig_atomic_t stop_flag = 0;
pcap_dumper_t *current_pcap = NULL;
char current_pcap_filename[256] = {0};

void handle_signal(int sig) {
    (void)sig;
    stop_flag = 1;
    if (current_pcap) {
        pcap_dump_close(current_pcap);
        current_pcap = NULL;
    }
}

void console_log(const char *format, ...) {
    va_list args;
    va_start(args, format);

    char log_buffer[512];
    vsnprintf(log_buffer, sizeof(log_buffer), format, args);

    printf("[%s] %s\n", get_current_timestamp(), log_buffer);

    va_end(args);
}

void log_message(const char *format, ...) {
    va_list args;
    va_start(args, format);

    openlog("edr_agent", LOG_PID|LOG_CONS, LOG_USER);
    vsyslog(LOG_INFO, format, args);
    closelog();

    va_end(args);
}

char* get_endpoint_ip() {
    FILE *fp;
    char buffer[128];
    char *ip = NULL;

    fp = popen("command -v hostname >/dev/null && hostname -I 2>/dev/null | awk '{print $1}' || echo ''", "r");
    if (fp) {
        if (fgets(buffer, sizeof(buffer), fp) != NULL) {
            buffer[strcspn(buffer, "\n")] = 0;
            if (strlen(buffer) > 0) {
                ip = strdup(buffer);
            }
        }
        pclose(fp);
    }

    if (ip && strlen(ip) > 0) return ip;

    fp = popen("command -v hostname >/dev/null && hostname -i 2>/dev/null || echo ''", "r");
    if (fp) {
        if (fgets(buffer, sizeof(buffer), fp) != NULL) {
            buffer[strcspn(buffer, "\n")] = 0;
            if (strlen(buffer) > 0) {
                free(ip);
                ip = strdup(buffer);
            }
        }
        pclose(fp);
    }

    if (ip && strlen(ip) > 0) return ip;

    fp = popen("ip -4 addr show | grep 'inet ' | grep -v '127.0.0.1' | awk '{print $2}' | cut -d'/' -f1 | head -n 1", "r");
    if (fp) {
        if (fgets(buffer, sizeof(buffer), fp) != NULL) {
            buffer[strcspn(buffer, "\n")] = 0;
            if (strlen(buffer) > 0) {
                free(ip);
                ip = strdup(buffer);
            }
        }
        pclose(fp);
    }

    return ip ? ip : strdup("unknown");
}

const char* detect_interface() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *interfaces, *temp;

    if (pcap_findalldevs(&interfaces, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return NULL;
    }

    for (temp = interfaces; temp; temp = temp->next) {
        if (temp->flags & PCAP_IF_LOOPBACK) continue;
        if (strstr(temp->name, "virbr") || strstr(temp->name, "docker")) continue;

        const char* interface_name = strdup(temp->name);
        pcap_freealldevs(interfaces);
        return interface_name;
    }

    pcap_freealldevs(interfaces);
    return NULL;
}

int get_mac_address(const char *interface, char *mac_address) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        fprintf(stderr, "Socket creation failed: %s\n", strerror(errno));
        return -1;
    }

    struct ifreq ifr;
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);

    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == -1) {
        fprintf(stderr, "Failed to get MAC address for %s: %s\n", interface, strerror(errno));
        close(sockfd);
        return -1;
    }

    snprintf(mac_address, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             (unsigned char)ifr.ifr_hwaddr.sa_data[0],
             (unsigned char)ifr.ifr_hwaddr.sa_data[1],
             (unsigned char)ifr.ifr_hwaddr.sa_data[2],
             (unsigned char)ifr.ifr_hwaddr.sa_data[3],
             (unsigned char)ifr.ifr_hwaddr.sa_data[4],
             (unsigned char)ifr.ifr_hwaddr.sa_data[5]);

    close(sockfd);
    return 0;
}

int get_ip_address(const char *interface, char *ip_address) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        fprintf(stderr, "Socket creation failed: %s\n", strerror(errno));
        return -1;
    }

    struct ifreq ifr;
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFADDR, &ifr) == -1) {
        fprintf(stderr, "Failed to get IP address for %s: %s\n", interface, strerror(errno));
        close(sockfd);
        return -1;
    }

    struct sockaddr_in *ip_addr = (struct sockaddr_in *)&ifr.ifr_addr;
    strncpy(ip_address, inet_ntoa(ip_addr->sin_addr), INET_ADDRSTRLEN);

    close(sockfd);
    return 0;
}

void create_directories() {
    struct stat st = {0};

    if (stat("/var/edr_agent", &st) == -1) {
        mkdir("/var/edr_agent", 0775);
    }

    if (stat(PCAP_DIR, &st) == -1) {
        mkdir(PCAP_DIR, 0775);
    }

    if (stat(ALERT_DIR, &st) == -1) {
        mkdir(ALERT_DIR, 0775);
    }
}

void generate_filename(const char *interface, char *filename, size_t size, const char *ext) {
    char mac_address[18] = "00:00:00:00:00:00";
    char ip_address[INET_ADDRSTRLEN] = "0.0.0.0";

    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock >= 0) {
        strncpy(ifr.ifr_name, interface, IFNAMSIZ);
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) != -1) {
            get_mac_address(interface, mac_address);
            get_ip_address(interface, ip_address);
        }
        close(sock);
    }

    time_t t;
    struct tm *tmp;
    char timestr[32];

    time(&t);
    tmp = localtime(&t);
    strftime(timestr, sizeof(timestr), "%Y%m%d_%H%M%S", tmp);

    if (strcmp(ext, "pcap") == 0) {
        snprintf(filename, size, "%s/capture_%s_%s_%s.pcap", PCAP_DIR, mac_address, ip_address, timestr);
    } else {
        snprintf(filename, size, "%s/alerts_%s_%s_%s.json", ALERT_DIR, mac_address, ip_address, timestr);
    }
}

const char* get_current_timestamp() {
    static char timestamp[64];
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm);
    return timestamp;
}

void add_alert(AlertContext *context, const char *attack_type, const char *src_ip, int src_port,
              const char *dst_ip, int dst_port) {
    json_t *alert = json_object();
    json_object_set_new(alert, "timestamp", json_string(get_current_timestamp()));
    json_object_set_new(alert, "attack_type", json_string(attack_type));
    json_object_set_new(alert, "source_ip", json_string(src_ip));
    json_object_set_new(alert, "source_port", json_integer(src_port));
    json_object_set_new(alert, "destination_ip", json_string(dst_ip));
    json_object_set_new(alert, "destination_port", json_integer(dst_port));
    json_object_set_new(alert, "pcap_reference", json_string(context->pcap_filename));
    json_object_set_new(alert, "severity", json_string("high"));

    json_array_append_new(context->alerts, alert);
}

void finalize_alerts(AlertContext *context) {
    char *endpoint_ip = get_endpoint_ip();
    
    // Write JSON alerts to file
    if (json_array_size(context->alerts) > 0) {
        json_dump_file(context->alerts, context->alert_filename, 
                      JSON_INDENT(2) | JSON_PRESERVE_ORDER);
    }

    char mkdir_command[512];
    snprintf(mkdir_command, sizeof(mkdir_command),
        "ssh %s@%s \"mkdir -p %s/%s && mkdir -p %s/%s\"",
        ADMIN_USERNAME, ADMIN_IP, 
        "/home/liza/edr_server/pcap_files", endpoint_ip,
        "/home/liza/edr_server/alerts", endpoint_ip);

    system(mkdir_command);

    // Transfer alerts file if alerts exist
    if (json_array_size(context->alerts) > 0) {
        char scp_alert[512];
        snprintf(scp_alert, sizeof(scp_alert),
            "scp -q %s %s@%s:%s/%s/",
            context->alert_filename, ADMIN_USERNAME, ADMIN_IP,
            "/home/liza/edr_server/alerts", endpoint_ip);
        
        if (system(scp_alert) == 0) {
            remove(context->alert_filename); // Clean up local file
        }
    }

    // Transfer PCAP file
    char scp_pcap[512];
    snprintf(scp_pcap, sizeof(scp_pcap),
        "scp -q %s %s@%s:%s/%s/",
        current_pcap_filename, ADMIN_USERNAME, ADMIN_IP,
        "/home/liza/edr_server/pcap_files", endpoint_ip);
    
    if (system(scp_pcap) == 0) {
        remove(current_pcap_filename); // Clean up local file
    }

    free(endpoint_ip);
    json_decref(context->alerts);
}

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    AttackCounters *counters = (AttackCounters *)user_data;
    AlertContext *alert_ctx = (AlertContext *)(user_data + sizeof(AttackCounters));

    pcap_dump((u_char *)current_pcap, pkthdr, packet);

    if (pkthdr->caplen < sizeof(struct ether_header) + sizeof(struct ip)) {
        return;
    }

    struct ether_header *eth_header = (struct ether_header *)packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        return;
    }

    struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
    if (ip_header->ip_v != 4) {
        return;
    }

    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

    int src_port = 0;
    int dst_port = 0;
    time_t now = time(NULL);

    if (ip_header->ip_p == IPPROTO_TCP &&
        pkthdr->caplen >= sizeof(struct ether_header) + (ip_header->ip_hl << 2) + sizeof(struct tcphdr)) {
        struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + (ip_header->ip_hl << 2));
        src_port = ntohs(tcp_header->th_sport);
        dst_port = ntohs(tcp_header->th_dport);

        if (dst_port == 22) {
            // Rapid SSH brute force detection
            counters->ssh_attempts++;
            if (counters->ssh_attempts >= SSH_BRUTE_THRESH) {
                add_alert(alert_ctx, "SSH Brute Force", src_ip, src_port, dst_ip, dst_port);
                counters->ssh_attempts = 0;
            }

            // Delayed SSH brute force detection
            if (counters->ssh_total_attempts == 0) {
                counters->first_ssh_time = now;
            }
            counters->ssh_total_attempts++;

            if (counters->ssh_total_attempts >= DELAYED_SSH_THRESH) {
                if (difftime(now, counters->first_ssh_time) <= 600) { // 10 minutes
                    add_alert(alert_ctx, "Delayed SSH Brute Force", src_ip, src_port, dst_ip, dst_port);
                    counters->ssh_total_attempts = 0;
                    counters->first_ssh_time = 0;
                } else {
                    counters->ssh_total_attempts = 1;
                    counters->first_ssh_time = now;
                }
            }
        }

        if (dst_port == 21) {
            counters->ftp_attempts++;
            if (counters->ftp_attempts >= FTP_BRUTE_THRESH) {
                add_alert(alert_ctx, "FTP Brute Force", src_ip, src_port, dst_ip, dst_port);
                counters->ftp_attempts = 0;
            }
        }

        if (!counters->scanned_ports[dst_port]) {
            counters->scanned_ports[dst_port] = 1;
            counters->port_scan_count++;

            // Aggressive port scan detection
            if (counters->port_scan_count == 1) {
                counters->first_port_scan_time = now;
            } else {
                if (difftime(now, counters->first_port_scan_time) <= AGGRESSIVE_SCAN_WINDOW) {
                    if (counters->port_scan_count >= AGGRESSIVE_SCAN_THRESH) {
                        add_alert(alert_ctx, "Aggressive Port Scanning", src_ip, src_port, dst_ip, dst_port);
                        memset(counters->scanned_ports, 0, sizeof(counters->scanned_ports));
                        counters->port_scan_count = 0;
                        counters->first_port_scan_time = 0;
                    }
                } else {
                    memset(counters->scanned_ports, 0, sizeof(counters->scanned_ports));
                    counters->port_scan_count = 0;
                    counters->first_port_scan_time = 0;
                }
            }

            if (counters->port_scan_count >= PORT_SCAN_THRESH) {
                add_alert(alert_ctx, "Port Scanning", src_ip, src_port, dst_ip, dst_port);
                memset(counters->scanned_ports, 0, sizeof(counters->scanned_ports));
                counters->port_scan_count = 0;
                counters->first_port_scan_time = 0;
            }
        }

        if (tcp_header->th_flags & TH_SYN && !(tcp_header->th_flags & TH_ACK)) {
            counters->syn_packets++;
            if (counters->syn_packets >= SYN_FLOOD_THRESH) {
                add_alert(alert_ctx, "SYN Flood Attack", src_ip, src_port, dst_ip, dst_port);
                counters->syn_packets = 0;
            }
        }
    } else if (ip_header->ip_p == IPPROTO_UDP &&
             pkthdr->caplen >= sizeof(struct ether_header) + (ip_header->ip_hl << 2) + sizeof(struct udphdr)) {
        struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + (ip_header->ip_hl << 2));
        src_port = ntohs(udp_header->uh_sport);
        dst_port = ntohs(udp_header->uh_dport);

        if (dst_port == 53) {
            counters->dns_queries++;
            if (counters->dns_queries >= DNS_QUERY_THRESH) {
                add_alert(alert_ctx, "DNS Amplification Attempt", src_ip, src_port, dst_ip, dst_port);
                counters->dns_queries = 0;
            }
        } else {
            counters->udp_flood_count++;
            if (counters->udp_flood_count >= UDP_FLOOD_THRESH) {
                add_alert(alert_ctx, "UDP Flood Attack", src_ip, src_port, dst_ip, dst_port);
                counters->udp_flood_count = 0;
            }
        }
    } else if (ip_header->ip_p == IPPROTO_ICMP) {
        counters->icmp_count++;
        if (counters->icmp_count >= ICMP_FLOOD_THRESH) {
            add_alert(alert_ctx, "ICMP Flood Attack", src_ip, 0, dst_ip, 0);
            counters->icmp_count = 0;
        }
    }

    if (difftime(now, counters->last_reset) > 60) {
        memset(counters, 0, sizeof(AttackCounters));
        counters->last_reset = now;
    }
}

void capture_traffic(const char *interface) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        fprintf(stderr, "Socket creation failed: %s\n", strerror(errno));
        return;
    }

    strncpy(ifr.ifr_name, interface, IFNAMSIZ);
    if (ioctl(sock, SIOCGIFFLAGS, &ifr) == -1) {
        fprintf(stderr, "Interface %s does not exist or is not available: %s\n",
               interface, strerror(errno));
        close(sock);
        return;
    }
    close(sock);

    generate_filename(interface, current_pcap_filename, sizeof(current_pcap_filename), "pcap");

    handle = pcap_open_live(interface,
                           SNAPLEN,
                           1,
                           1000,
                           errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
        return;
    }

    const char *filter_exp =
        "(tcp port 22 or tcp port 21 or tcp port 23 or tcp port 80 or "
        "tcp port 443 or tcp port 8080 or tcp port 445 or tcp port 3389 or "
        "tcp port 3306 or tcp port 5900 or udp port 53 or udp port 123 or "
        "udp port 161 or icmp or tcp port 135 or tcp port 139 or "
        "tcp port 1521 or tcp port 3306) or (ip and not net 127.0.0.0/8)";

    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Could not parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pcap_close(handle);
        return;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Could not install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pcap_close(handle);
        return;
    }

    current_pcap = pcap_dump_open(handle, current_pcap_filename);
    if (current_pcap == NULL) {
        fprintf(stderr, "Error opening output file: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return;
    }

    printf("Capturing on %s... Saving to %s\n", interface, current_pcap_filename);

    struct {
        AttackCounters counters;
        AlertContext alert_ctx;
    } capture_data;
    
    memset(&capture_data.counters, 0, sizeof(AttackCounters));
    capture_data.counters.last_reset = time(NULL);
    capture_data.alert_ctx.alerts = json_array();
    generate_filename(interface, capture_data.alert_ctx.alert_filename,
                    sizeof(capture_data.alert_ctx.alert_filename), "json");
    capture_data.alert_ctx.pcap_filename = current_pcap_filename;

    pcap_loop(handle, MAX_PACKETS, packet_handler, (u_char *)&capture_data);
    finalize_alerts(&capture_data.alert_ctx);
        
    // Clean up PCAP handler
    pcap_dump_close(current_pcap);
    pcap_close(handle);
    current_pcap = NULL;

}

int main() {
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    create_directories();

    const char *interface = detect_interface();
    if (interface == NULL) {
        log_message("No suitable network interface found");
        console_log("Error: No suitable network interface found");
        return EXIT_FAILURE;
    }

    log_message("Using interface: %s", interface);
    console_log("Starting capture on interface: %s", interface);

    time_t last_status_check = time(NULL);
    while (!stop_flag) {
        capture_traffic(interface);

        time_t now = time(NULL);
        if (difftime(now, last_status_check) > 30) {
            console_log("Agent status: Running (interface: %s)", interface);
            last_status_check = now;
        }

        sleep(1);
    }

    log_message("Agent shutting down gracefully");
    console_log("Agent shutting down gracefully");
    return EXIT_SUCCESS;
}
