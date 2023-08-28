#include "sniff.h"

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <signal.h>
#include <pthread.h>


#include "dispatch.h"
#include "myqueue.h"

//this is the size of the thread pool we make
#define THREAD_POOL_SIZE 16

//initalise our variables
pthread_t thread_pool[THREAD_POOL_SIZE]; //the array of threads
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER; //our mutex lock
pthread_cond_t condition = PTHREAD_COND_INITIALIZER; //our condition variable 
pcap_t *pcap_handle; // the connection handler
int v = 0; //global variable representing verbose
int syncounter = 0; //counter to count all syn packets
int size = 1; //counter for the array of unique ips
int arpcounter = 0; //counter to count all arp requests
int google = 0; //counter to count all google http traffic (blacklisted)
int facebook = 0; //counter to count all facebook http traffic (blacklisted)
struct queue *q; //initalise our queue to hold all the packets yet to be processed 
int continueLoop = 1; //to signify when our threads should be working 
uint32_t *ip_array; //unique ip array 

//signal handler when ctrl+c is pressed
void signal_handler(int sig)
{
    //we break the pcap loop and close it to exit the pcap_loop and as we no longer use it 
    pcap_breakloop(pcap_handle);
    pcap_close(pcap_handle);
}

//handler function where the packets are passed to in pcap_loop 
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    
  if (packet == NULL) {
    // pcap_next can return null if no packet is seen within a timeout
    if (v) {
      printf("No packet received. %s\n", pcap_geterr(pcap_handle));
    }
  } else {
    //mutex lock because we use threads now, queue is a shared block of memory amongst threads so we must mutex lock
    pthread_mutex_lock(&lock);
    enqueue(q,(struct pcap_pkthdr *)header,packet);
    pthread_cond_broadcast(&condition); // send a signal to the threads when a packet is enqueued to minimise cpu cycles wasted
    pthread_mutex_unlock(&lock);
    // If verbose is set to 1, dump raw packet to terminal
    if (v) {
      dump(packet, (*header).len);
    }
  }
}

// Application main sniffing loop
void sniff(char *interface, int verbose) {
  v = verbose; //set global verbose variable as the verbose passed into sniff
  char errbuf[PCAP_ERRBUF_SIZE];

  // Open the specified network interface for packet capture. pcap_open_live() returns the handle to be used for the packet
  // capturing session. check the man page of pcap_open_live()
  pcap_handle = pcap_open_live(interface, 4096, 1, 1000, errbuf);
  if (pcap_handle == NULL) {
    fprintf(stderr, "Unable to open interface %s\n", errbuf);
    exit(EXIT_FAILURE);
  } else {
    printf("SUCCESS! Opened %s for capture\n", interface);
  }


  //create the array and queue 
  ip_array = malloc(size*sizeof(uint32_t));
  q = create_queue();

  //create the threads
  for (int i=0; i<THREAD_POOL_SIZE; i++){
    pthread_create(&thread_pool[i],NULL,dispatch,NULL);
  }

  //establish our signal handler
  signal(SIGINT, signal_handler);
  pcap_loop(pcap_handle,-69,got_packet,NULL);
  continueLoop = 0; //when pcap_loop is broken we must tell our threads to stop working
  pthread_cond_broadcast(&condition); //finally send a final signal to get stuck threads in pthread_cond_wait out and terminate them 
  //ensure the threads have all joined and none are orphans before finally printing our results 
  for(int i =0; i< THREAD_POOL_SIZE; i++){
    pthread_join(thread_pool[i],NULL);
  }
  
  //print results 
  printf("\n");
  printf("%d SYN packets detected\n", syncounter);
  printf("%d Unique IPs!\n",(size - 1));
  printf("%d Arp Responses (cache poisoning)\n", arpcounter);
  printf("%d URL Blacklist violations (%d google and %d facebook)\n", google + facebook, google, facebook);
  
}

// Utility/Debugging method for dumping raw packet data
void dump(const unsigned char *data, int length) {
  unsigned int i;
  static unsigned long pcount = 0;
  // Decode Packet Header
  struct ether_header *eth_header = (struct ether_header *) data;
  printf("\n\n === PACKET %ld HEADER ===", pcount);
  printf("\nSource MAC: ");
  for (i = 0; i < 6; ++i) {
    printf("%02x", eth_header->ether_shost[i]);
    if (i < 5) {
      printf(":");
    }
  }
  printf("\nDestination MAC: ");
  for (i = 0; i < 6; ++i) {
    printf("%02x", eth_header->ether_dhost[i]);
    if (i < 5) {
      printf(":");
    }
  }
  printf("\nType: %hu\n", eth_header->ether_type);
  printf(" === PACKET %ld DATA == \n", pcount);
  // Decode Packet Data (Skipping over the header)
  int data_bytes = length - ETH_HLEN;
  const unsigned char *payload = data + ETH_HLEN;
  const static int output_sz = 20; // Output this many bytes at a time
  while (data_bytes > 0) {
    int output_bytes = data_bytes < output_sz ? data_bytes : output_sz;
    // Print data in raw hexadecimal form
    for (i = 0; i < output_sz; ++i) {
      if (i < output_bytes) {
        printf("%02x ", payload[i]);
      } else {
        printf ("   "); // Maintain padding for partial lines
      }
    }
    printf ("| ");
    // Print data in ascii form
    for (i = 0; i < output_bytes; ++i) {
      char byte = payload[i];
      if (byte > 31 && byte < 127) {
        // Byte is in printable ascii range
        printf("%c", byte);
      } else {
        printf(".");
      }
    }
    printf("\n");
    payload += output_bytes;
    data_bytes -= output_bytes;
  }
  pcount++;
}
