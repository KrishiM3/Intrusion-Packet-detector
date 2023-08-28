#include "analysis.h"

#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <time.h>

//these includes below are used to easily obtain the ip address from an unsigned int to ipv4 format for blacklist section
#include <netinet/in.h> /*contains the IN struct which just contains the internet address*/
#include <arpa/inet.h> /*contains the inet_ntoa() function which converts Internet number in IN to ASCII representation.  The return value is a pointer to an internal array containing the string.  */

//obtain our global variables defined in sniff.c
extern int syncounter;
extern int size;
extern int arpcounter;
extern int google;
extern int facebook;

extern uint32_t *ip_array; 
extern pthread_mutex_t lock;

clock_t start;
clock_t difference;

void analyse(struct pcap_pkthdr *header,const unsigned char *packet,int verbose){
  //obtians the ethernet header of a packet
  struct ether_header *eth_header = (struct ether_header *) packet;
  //we check if it is an arp request by checking the ethertype
  if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP){
    //if so increment our counter 
    pthread_mutex_lock(&lock);
    arpcounter++;
    pthread_mutex_unlock(&lock);
  }else{
    //else we check if its a syn packet and/or contains a blacklisted url in its http header

    //obtain the ip header and tcp header 
    struct iphdr *ipheader = (struct iphdr*) (packet + sizeof(struct ether_header));
    struct tcphdr *tcpheader = (struct tcphdr*) (packet + sizeof(struct ether_header) + sizeof(struct iphdr));
    
    //local boolean variable signifing if the ip address is unique or not 
    int valid = 1;
    //check if the syn flag is 1 and all other are 0, if this is the case then it is a syn packet
    pthread_mutex_lock(&lock);
    if (tcpheader->fin == 0 && tcpheader->syn == 1 && tcpheader->rst == 0 && tcpheader->psh == 0 && tcpheader->ack == 0 && tcpheader->urg == 0){

      //FOR TESTING
      // if (syncounter == 0){
      //   start=clock();
      // }

      syncounter++;

      //FOR TESTING
      // if (syncounter == 245000){
      //   difference = clock() - start;
      //   printf("Time Elapsed %ld\n", (difference/CLOCKS_PER_SEC));
      // }

      //check if it is a unique ip
      for (int i = 0; i < size; i++){
        if (ip_array[i] == ipheader->saddr){
          valid = 0;
          break;
        }
      }
      //if it is unique we increment the size of the array and add it
      if (valid == 1){
        ip_array[size - 1] = ipheader->saddr;
        size++;
        ip_array = realloc(ip_array, size * sizeof(uint32_t));
      }
    }
    pthread_mutex_unlock(&lock);

    //check if the http header contains our blacklisted url

    //first we check if the packet has destination port 80, the http form
    if (ntohs(tcpheader->th_dport) == 80){
      //then obtain the http header
      char* payload = (char*) (packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr));
      char *found_google = strstr(payload, "www.google.co.uk");
      char *found_facebook = strstr(payload, "www.facebook.com");
      //if google.co.uk string is found then we must increment our google counter
      if (found_google != NULL){ 
        pthread_mutex_lock(&lock);
        google++;
        pthread_mutex_unlock(&lock);
        //formatting to see the dest and source ip address in terminal
        struct in_addr in;
        in.s_addr = ipheader->saddr;
        char* source = inet_ntoa(in);
        printf("\n=================================\n");
        printf("Blacklisted URL violation detected\n");
        printf("source IP Address: %s\n", source);
        in.s_addr = ipheader->daddr;
        char* dest = inet_ntoa(in);
        printf("Destination IP Address: %s\n", dest);
        printf("===================================\n");
      }
      //same process for facebook.com
      if(found_facebook != NULL){
        pthread_mutex_lock(&lock);
        facebook++;
        pthread_mutex_unlock(&lock);
        struct in_addr in;
        in.s_addr = ipheader->saddr;
        char* source = inet_ntoa(in);
        printf("\n=================================\n");
        printf("Blacklisted URL violation detected\n");
        printf("Source IP Address: %s\n", source);
        in.s_addr = ipheader->daddr;
        char* dest = inet_ntoa(in);
        printf("Destination IP Address: %s\n", dest);
        printf("===================================\n");
      }
    }

  }

}
