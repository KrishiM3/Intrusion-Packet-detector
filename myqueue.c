#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

struct node{ // data structure for each node
  struct pcap_pkthdr *header;
  const unsigned char *packet;
  struct node *next;
};

struct queue{ // data structure for queue
  struct node *head;
  struct node *tail;
};

struct queue *create_queue(void){ //creates a queue and returns its pointer
  struct queue *q=(struct queue *)malloc(sizeof(struct queue));
  q->head=NULL;
  q->tail=NULL;
  return(q);
}

int isempty(struct queue *q){ // checks if queue is empty
  return(q->head==NULL);
}

void enqueue(struct queue *q,struct pcap_pkthdr *hdr, const unsigned char *pckt){ //enqueues a node with an item
  struct node *new_node=(struct node *)malloc(sizeof(struct node));
  new_node->header=hdr;
  new_node->packet=pckt;
  new_node->next=NULL;
  if(isempty(q)){
    q->head=new_node;
    q->tail=new_node;
  }
  else{
    q->tail->next=new_node;
    q->tail=new_node;
  }
}

struct node* dequeue(struct queue *q){ //dequeues a the head node
  struct node *head_node;
  if(isempty(q)){
    printf("Error: attempt to dequeue from an empty queue");
    return NULL;
  }
  else{
    head_node=q->head;
    q->head=q->head->next;
    if(q->head==NULL)
      q->tail=NULL;
    return head_node;
    // free(head_node);
  }
}

// void printqueue(struct queue *q){
//     if(isempty(q)){
//         printf("The queue is empty\n");
//     }
//     else{
//         struct node *read_head;
//         read_head=q->head;
//         printf("The queue elements from head to tail are:\n");
//         printf("%lld",read_head->item);
//         while(read_head->next!=NULL){
//             read_head=read_head->next;
//             printf("--> %lld",read_head->item);
//         }
//         printf("\n");
//     }
// }

