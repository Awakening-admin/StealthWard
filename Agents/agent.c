#include <stdio.h>           // Standard I/O functions (printf, fopen, etc.)
#include <stdlib.h>          // Memory allocation, process control, conversions (malloc, exit, atoi)
#include <string.h>          // String handling (strcpy, strcmp, strlen, etc.)
#include <pcap.h>            // Packet capture library (libpcap) for sniffing network traffic
#include <unistd.h>          // POSIX OS API (fork, sleep, access, close, etc.)
#include <time.h>            // Time and date functions (time, strftime, etc.)
#include <sys/stat.h>        // File status and permission info (stat, mkdir, chmod, etc.)
#include <sys/types.h>       // Primitive system data types (pid_t, uid_t, size_t, etc.)
#include <arpa/inet.h>       // Functions for IP address conversion (inet_ntoa, inet_pton, etc.)
#include <libgen.h>          // File path manipulation (basename, dirname)
#include <net/if.h>          // Network interface structures (ifreq, interface flags)
#include <sys/ioctl.h>       // I/O control operations (used to manipulate device parameters)
#include <fcntl.h>           // File control options (open, fcntl, file locking)
#include <netdb.h>           // Network database operations (gethostbyname, getaddrinfo, etc.)
#include <jansson.h>         // JSON parsing and encoding (used for alerts, configs, logs)
#include <signal.h>          // Signal handling (signal, raise, kill, SIGINT, etc.)
#include <netinet/ip.h>      // IP protocol definitions and IP header struct
#include <netinet/tcp.h>     // TCP protocol definitions and TCP header struct
#include <netinet/udp.h>     // UDP protocol definitions and UDP header struct
#include <netinet/if_ether.h>// Ethernet frame definitions (Ethernet header, ETH_P_IP, etc.)
#include <syslog.h>          // System logging interface (syslog, openlog, closelog)
#include <stdarg.h>          // Variable argument handling macros (va_list, va_start, va_end)
#include <errno.h>           // Error number definitions and error handling (errno, strerror)
#include <sys/wait.h>        // Wait for process status changes (wait, waitpid)

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
#define ADMIN_IP "192.168.100.24"
#define ADMIN_USERNAME "robot"

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
    int alert_count;
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
    context->alert_count++;
    
    // Immediately write to file
    json_dump_file(context->alerts, context->alert_filename, JSON_INDENT(2));
    console_log("Alert added: %s", attack_type);
}

void finalize_alerts(AlertContext *context) {
    char *endpoint_ip = get_endpoint_ip();
    char command[512];
    
    // Create remote directories
    snprintf(command, sizeof(command),
        "ssh %s@%s 'mkdir -p /home/robot/edr_server/pcap_files/%s /home/robot/edr_server/alerts/%s'",
        ADMIN_USERNAME, ADMIN_IP, endpoint_ip, endpoint_ip);
    system(command);

    // Always transfer PCAP file
    snprintf(command, sizeof(command),
        "scp -q %s %s@%s:/home/robot/edr_server/pcap_files/%s/",
        current_pcap_filename, ADMIN_USERNAME, ADMIN_IP, endpoint_ip);
    system(command);

    // Transfer Alerts only if there are any
    if (context->alert_count > 0) {
        snprintf(command, sizeof(command),
            "scp -q %s %s@%s:/home/robot/edr_server/alerts/%s/",
            context->alert_filename, ADMIN_USERNAME, ADMIN_IP, endpoint_ip);
        system(command);
        // Remove alert file after transfer
        remove(context->alert_filename);
    }

    // Remove PCAP file after transfer
    remove(current_pcap_filename);

    free(endpoint_ip);
    json_decref(context->alerts);
    context->alert_count = 0;
}

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    AttackCounters *counters = (AttackCounters *)user_data;
    AlertContext *alert_ctx = (AlertContext *)(user_data + sizeof(AttackCounters));

    // Write packet to pcap
    pcap_dump((u_char *)current_pcap, pkthdr, packet);

    // Basic packet validation
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

    // Extract IP addresses
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

    int src_port = 0, dst_port = 0;
    time_t now = time(NULL);

    // TCP processing
    if (ip_header->ip_p == IPPROTO_TCP && 
        pkthdr->caplen >= sizeof(struct ether_header) + (ip_header->ip_hl << 2) + sizeof(struct tcphdr)) {
        
        struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + (ip_header->ip_hl << 2));
        src_port = ntohs(tcp_header->th_sport);
        dst_port = ntohs(tcp_header->th_dport);

        // SSH brute force detection
        if (dst_port == 22) {
            counters->ssh_attempts++;
            if (counters->ssh_attempts >= SSH_BRUTE_THRESH) {
                add_alert(alert_ctx, "SSH Brute Force", src_ip, src_port, dst_ip, dst_port);
                counters->ssh_attempts = 0;  // Reset counter after alert
            }

            // Delayed SSH detection
            if (counters->ssh_total_attempts++ == 0) {
                counters->first_ssh_time = now;
            }
            if (counters->ssh_total_attempts >= DELAYED_SSH_THRESH && 
                difftime(now, counters->first_ssh_time) <= 600) {
                add_alert(alert_ctx, "Delayed SSH Brute Force", src_ip, src_port, dst_ip, dst_port);
                counters->ssh_total_attempts = 0;
            }
        }

        // FTP brute force detection
        if (dst_port == 21) {
            if (++counters->ftp_attempts >= FTP_BRUTE_THRESH) {
                add_alert(alert_ctx, "FTP Brute Force", src_ip, src_port, dst_ip, dst_port);
                counters->ftp_attempts = 0;
            }
        }

        // Port scan detection
        if (!counters->scanned_ports[dst_port]) {
            counters->scanned_ports[dst_port] = 1;
            counters->port_scan_count++;

            // Aggressive scan detection
            if (counters->port_scan_count == 1) {
                counters->first_port_scan_time = now;
            }
            else if (difftime(now, counters->first_port_scan_time) <= AGGRESSIVE_SCAN_WINDOW) {
                if (counters->port_scan_count >= AGGRESSIVE_SCAN_THRESH) {
                    add_alert(alert_ctx, "Aggressive Port Scanning", src_ip, src_port, dst_ip, dst_port);
                    memset(counters->scanned_ports, 0, sizeof(counters->scanned_ports));
                    counters->port_scan_count = 0;
                }
            }
            else {  // Reset if window expired
                memset(counters->scanned_ports, 0, sizeof(counters->scanned_ports));
                counters->port_scan_count = 0;
            }

            // General port scan detection
            if (counters->port_scan_count >= PORT_SCAN_THRESH) {
                add_alert(alert_ctx, "Port Scanning", src_ip, src_port, dst_ip, dst_port);
                memset(counters->scanned_ports, 0, sizeof(counters->scanned_ports));
                counters->port_scan_count = 0;
            }
        }

        // SYN flood detection
        if ((tcp_header->th_flags & TH_SYN) && !(tcp_header->th_flags & TH_ACK)) {
            if (++counters->syn_packets >= SYN_FLOOD_THRESH) {
                add_alert(alert_ctx, "SYN Flood Attack", src_ip, src_port, dst_ip, dst_port);
                counters->syn_packets = 0;
            }
        }
    }
    // UDP processing
    else if (ip_header->ip_p == IPPROTO_UDP &&
             pkthdr->caplen >= sizeof(struct ether_header) + (ip_header->ip_hl << 2) + sizeof(struct udphdr)) {
        
        struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + (ip_header->ip_hl << 2));
        src_port = ntohs(udp_header->uh_sport);
        dst_port = ntohs(udp_header->uh_dport);

        if (dst_port == 53) {  // DNS
            if (++counters->dns_queries >= DNS_QUERY_THRESH) {
                add_alert(alert_ctx, "DNS Amplification Attempt", src_ip, src_port, dst_ip, dst_port);
                counters->dns_queries = 0;
            }
        } else {  // Other UDP
            if (++counters->udp_flood_count >= UDP_FLOOD_THRESH) {
                add_alert(alert_ctx, "UDP Flood Attack", src_ip, src_port, dst_ip, dst_port);
                counters->udp_flood_count = 0;
            }
        }
    }
    // ICMP processing
    else if (ip_header->ip_p == IPPROTO_ICMP) {
        if (++counters->icmp_count >= ICMP_FLOOD_THRESH) {
            add_alert(alert_ctx, "ICMP Flood Attack", src_ip, 0, dst_ip, 0);
            counters->icmp_count = 0;
        }
    }

    // Reset counters every minute
    if (difftime(now, counters->last_reset) > 60) {
        memset(counters, 0, sizeof(AttackCounters));
        counters->last_reset = now;
    }
}

void capture_traffic(const char *interface) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // Generate fresh filenames for this capture session
    generate_filename(interface, current_pcap_filename, sizeof(current_pcap_filename), "pcap");
    
    char alert_filename[256];
    generate_filename(interface, alert_filename, sizeof(alert_filename), "json");

    // Open network interface
    handle = pcap_open_live(interface, SNAPLEN, 1, 1000, errbuf);
    if (!handle) {
        console_log("Error opening interface %s: %s", interface, errbuf);
        return;
    }

    // Set up filter
    struct bpf_program fp;
    const char *filter = "(tcp or udp or icmp) and not net 127.0.0.0/8";
    if (pcap_compile(handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        console_log("Couldn't parse filter: %s", pcap_geterr(handle));
        pcap_close(handle);
        return;
    }
    
    if (pcap_setfilter(handle, &fp) == -1) {
        console_log("Couldn't install filter: %s", pcap_geterr(handle));
        pcap_close(handle);
        return;
    }

    // Open pcap dump file
    current_pcap = pcap_dump_open(handle, current_pcap_filename);
    if (!current_pcap) {
        console_log("Error creating pcap file: %s", pcap_geterr(handle));
        pcap_close(handle);
        return;
    }

    // Initialize context structures
    AttackCounters counters = {0};
    counters.last_reset = time(NULL);

    AlertContext alert_ctx = {
        .alerts = json_array(),
        .alert_count = 0
    };
    strncpy(alert_ctx.alert_filename, alert_filename, sizeof(alert_ctx.alert_filename));
    alert_ctx.pcap_filename = current_pcap_filename;

    // Combined structure for handler data
    struct {
        AttackCounters counters;
        AlertContext alert_ctx;
    } handler_data = {
        .counters = counters,
        .alert_ctx = alert_ctx
    };

    // Start capture with 1000 packet limit
    console_log("Starting new capture session: %s", current_pcap_filename);
    pcap_loop(handle, MAX_PACKETS, packet_handler, (u_char *)&handler_data);
    
        // Properly close the PCAP dump file before finalizing alerts
    pcap_dump_close(current_pcap);
    current_pcap = NULL;
    
        // Process results after capture completes
    console_log("Capture completed. %d alerts detected", handler_data.alert_ctx.alert_count);
    finalize_alerts(&handler_data.alert_ctx);
    
    pcap_close(handle);
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
