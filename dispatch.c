#include "dispatch.h"
#include <pthread.h>
#include <pcap.h>

#include "analysis.h"
#include "myqueue.h"

//obtain our variables from sniff.c
extern struct queue *q;
extern pthread_mutex_t lock;
extern pthread_cond_t condition;
extern int v;
extern int continueLoop;

//dispatch is our thread handler function, allocating threads the work they need
void * dispatch(void *arg) {
  //in a loop continuously checking if any more work is left to be done until ctrl+c is called
  while (continueLoop){
    struct node* temp;
    //acquires lock and if the queue is empty waits until something is enqueued
    pthread_mutex_lock(&lock);
    while(isempty(q) && continueLoop){  
			pthread_cond_wait(&condition, &lock);
		}
    //conditional needed for threads stuck in the wait and need to be terminated
    if(continueLoop == 0){
      
      pthread_mutex_unlock(&lock);
      return NULL;
    }
    //obtain the packet to be analysed
    temp = dequeue(q);
    pthread_mutex_unlock(&lock);
    struct pcap_pkthdr *hed = temp->header;
    const unsigned char *pak = temp->packet;
    //pass into analyse
    analyse(hed, pak,v);
  }
  return NULL;
  // TODO: Your part 2 code here
  // This method should handle dispatching of work to threads. At present
  // it is a simple passthrough as this skeleton is single-threaded.
}
