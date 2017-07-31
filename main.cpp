#include <QCoreApplication>
#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <fstream>
#define MAXLINE 256

using namespace std;


int main(int argc, char *argv[])
{
    pcap_t *handle;			/* Session handle */
    char *dev;			/* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    struct bpf_program fp;		/* The compiled filter */
    char filter_exp[] = "port 80";	/* The filter expression */
    bpf_u_int32 mask;		/* Our netmask */
    bpf_u_int32 net;		/* Our IP */
    struct pcap_pkthdr *header;	/* The header that pcap gives us */

    int res;
    const u_char *pkt;
    u_char send_pkt[100];
    struct tm *ltime;
    char timestr[16];
    time_t local_tv_sec;
    char buf[INET_ADDRSTRLEN];

    /* My info */
    char senderIP[16];
    char senderMAC[18];


    /* Find Mac Address and IP */

    FILE *fp2;

    fp2 = popen( "ifconfig | grep -A3 \"192.\" | sed -n 1p | awk '{print $2}'", "r");
    if ( NULL == fp2)
    {
        perror( "popen() 실패");
        return -1;
    }

    while( fgets( senderIP, 17, fp2) );
    pclose( fp2);

    fp2 = popen( "ifconfig | grep -A3 \"192.\" | sed -n 3p | awk '{print $2}'", "r");
    if ( NULL == fp2)
    {
        perror( "popen() 실패");
        return -1;
    }

    while( fgets( senderMAC, 19, fp2) );
    pclose( fp2);

    printf("my ip : %s", senderIP);
    printf("my mac : %s", senderMAC);







    /* Define the device */
    dev = pcap_lookupdev(errbuf);;
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }
    /* Find the properties for the device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }
    printf("Device is %s\n", argv[1]);
    /* Open the session in promiscuous mode */
    handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", argv[1], errbuf);
        return(2);
    }
    /* Compile and apply the filter */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    while((res = pcap_next_ex( handle, &header, &pkt)) >= 0){

        if(res == 0)
            /* Timeout elapsed */
            continue;

        /* convert the timestamp to readable format */
        local_tv_sec = header->ts.tv_sec;
        ltime=localtime(&local_tv_sec);
        strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);
        printf("================================================\n");
        printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);

        /* Check ARP */
        if(ntohs(eth->ether_type) != ETHERTYPE_ARP)  continue;


    }

    return 0;
}
