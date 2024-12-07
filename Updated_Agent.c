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

// Function to detect network interface
const char* detect_interface() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *interfaces, *temp;

    if (pcap_findalldevs(&interfaces, errbuf) == -1) {
        perror("Error finding devices");
        exit(EXIT_FAILURE);
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

    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
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

// Function to get the IP address of the network interface
void get_ip_address(const char *interface, char *ip_address) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr;

    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFADDR, &ifr) == -1) {
        perror("Failed to get IP address");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in *ip_addr = (struct sockaddr_in *)&ifr.ifr_addr;
    strncpy(ip_address, inet_ntoa(ip_addr->sin_addr), INET_ADDRSTRLEN);

    close(sockfd);
}

// Function to capture network traffic
void capture_traffic(const char *interface, const char *admin_ip) {
    char mac_address[18];
    char ip_address[INET_ADDRSTRLEN];
    get_mac_address(interface, mac_address);
    get_ip_address(interface, ip_address);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct pcap_pkthdr header;
    const u_char *packet;
    char filename[256];
    time_t t;
    struct tm *tmp;
    char timestr[32];

    // Generate a unique filename using MAC address, IP address, and timestamp
    time(&t);
    tmp = localtime(&t);
    strftime(timestr, sizeof(timestr), "%Y%m%d_%H%M%S", tmp);
    snprintf(filename, sizeof(filename), "/var/edr_agent/pcap_files/capture_%s_%s_%s.pcap", mac_address, ip_address, timestr);

    // Open the interface for capture
    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
        exit(EXIT_FAILURE);
    }

    printf("Capturing on %s...\n", interface);

    // Apply a filter for common organizational ports and protocols
    const char *filter_exp = 
        "tcp port 22 or tcp port 80 or tcp port 443 or tcp port 8080 or "
        "udp port 53 or udp port 123 or udp port 161 or icmp";
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Could not parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Could not install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    // Save packets to a pcap file
    pcap_dumper_t *pcap_file = pcap_dump_open(handle, filename);
    if (pcap_file == NULL) {
        fprintf(stderr, "Error opening output file: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        exit(EXIT_FAILURE);
    }

    // Capture packets for a defined duration
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
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <ADMIN_IP>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *admin_ip = argv[1];
    const char *interface = detect_interface();

    if (interface == NULL) {
        fprintf(stderr, "No suitable network interface found.\n");
        return EXIT_FAILURE;
    }

    printf("Using interface: %s\n", interface);

    while (1) {
        capture_traffic(interface, admin_ip);
    }

    return EXIT_SUCCESS;
}
