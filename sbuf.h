#ifndef __SBUF_H__
#define __SBUF_H__

#include "csapp.h"

typedef struct
{
    int *buf;
    int n;
    int front;
    int rear;
    sem_t mutex;
    sem_t slots;
    sem_t items;
} sbuf_t;

#endif