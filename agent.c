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
#include <unistd.h>
#include <netdb.h>

// Function to detect network interface
const char* detect_interface() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *interfaces, *temp;
    
    if (pcap_findalldevs(&interfaces, errbuf) == -1) {
        perror("Error finding devices");
        exit(1);
    }

    // Look for the first non-loopback interface
    for (temp = interfaces; temp; temp = temp->next) {
        if (temp->flags & PCAP_IF_LOOPBACK) continue;
        const char* interface_name = strdup(temp->name);
        pcap_freealldevs(interfaces);
        return interface_name;
    }

    pcap_freealldevs(interfaces);
    return NULL;
}

// Function to get the MAC address of the network interface
void get_mac_address(const char *interface, char *mac_address) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr;

    strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == -1) {
        perror("Failed to get MAC address");
        exit(EXIT_FAILURE);
    }

    snprintf(mac_address, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             (unsigned char)ifr.ifr_hwaddr.sa_data[0],
             (unsigned char)ifr.ifr_hwaddr.sa_data[1],
             (unsigned char)ifr.ifr_hwaddr.sa_data[2],
             (unsigned char)ifr.ifr_hwaddr.sa_data[3],
             (unsigned char)ifr.ifr_hwaddr.sa_data[4],
             (unsigned char)ifr.ifr_hwaddr.sa_data[5]);

    close(sockfd);
}

// Function to get the local endpoint's IP address (the machine's own IP)
const char* get_local_ip() {
    char buffer[256];
    struct sockaddr_in sa;
    socklen_t len = sizeof(struct sockaddr_in);
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    if (sockfd == -1) {
        perror("Error creating socket");
        exit(EXIT_FAILURE);
    }

    if (getsockname(sockfd, (struct sockaddr *)&sa, &len) == -1) {
        perror("Error getting local IP address");
        exit(EXIT_FAILURE);
    }

    close(sockfd);

    return inet_ntoa(sa.sin_addr);
}

void capture_traffic(const char *interface, const char *admin_ip, const char *endpoint_ip) {
    char mac_address[18];
    get_mac_address(interface, mac_address);  // Get MAC address for uniqueness

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct pcap_pkthdr header;
    const u_char *packet;
    char filename[256];
    time_t t;
    struct tm *tmp;
    char timestr[32];

    // Generate unique filename using MAC address, IP address, and timestamp
    time(&t);
    tmp = localtime(&t);
    strftime(timestr, sizeof(timestr), "%Y%m%d_%H%M%S", tmp);
    snprintf(filename, sizeof(filename), "/var/edr_agent/capture_%s_%s_%s.pcap", mac_address, endpoint_ip, timestr);

    // Open the interface for capture
    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
        exit(EXIT_FAILURE);
    }

    printf("Capturing on %s\n", interface);

    // Set the extended capture filter for common ports and protocols
    const char *filter_exp = "tcp port 22 or tcp port 23 or tcp port 25 or tcp port 53 or tcp port 80 or tcp port 110 or tcp port 143 or tcp port 443 or tcp port 445 or tcp port 3389 or tcp port 3306 or tcp port 5432 or tcp port 5900 or tcp port 8080 or tcp port 1433 or udp port 161 or udp port 123 or udp port 69 or udp port 514 or udp port 161 or icmp";
    
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Could not parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Could not install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    // Save packets to pcap file
    pcap_dumper_t *pcap_file = pcap_dump_open(handle, filename);
    if (pcap_file == NULL) {
        fprintf(stderr, "Error opening output file: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        exit(EXIT_FAILURE);
    }

    // Capture packets for 60 seconds
    for (int i = 0; i < 60; i++) {
        packet = pcap_next(handle, &header);
        if (packet != NULL) {
            pcap_dump((u_char *)pcap_file, &header, packet);
        }
        sleep(1);
    }

    pcap_dump_close(pcap_file);
    pcap_close(handle);

    printf("Capture completed. File saved as %s\n", filename);

    // Transfer the file to the admin server
    char scp_command[512];
    snprintf(scp_command, sizeof(scp_command), "scp %s robot@%s:/home/robot/edr_server/pcap_files/", filename, admin_ip);
    system(scp_command);

    printf("File transferred to admin server.\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <ADMIN_IP>\n", argv[0]);
        return 1;
    }

    const char *admin_ip = argv[1];  // Accepting only admin IP
    const char *interface = detect_interface();

    if (interface == NULL) {
        fprintf(stderr, "No suitable network interface found.\n");
        return 1;
    }

    // Get the local endpoint's IP address automatically
    const char *endpoint_ip = get_local_ip();

    // Run capture-transfer loop
    while (1) {
        capture_traffic(interface, admin_ip, endpoint_ip);
    }

    return 0;
}
