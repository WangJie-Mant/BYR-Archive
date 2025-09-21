#include "sbuf.h"

void sbuf_init(sbuf_t *sp, int n)
{
    /*初始化sbuf，大小为n，并初始化信号量*/
    sp->buf = Calloc(n, sizeof(int));
    sp->n = n;
    sp->front = sp->rear = 0;
    Sem_init(&sp->mutex, 0, 1);
    Sem_init(&sp->slots, 0, n);
    Sem_init(&sp->items, 0, 0);
}

void sbuf_deinit(sbuf_t *sp)
{
    /*释放已初始化过的内存，去初始化*/
    Free(sp->buf);
}

void sbuf_insert(sbuf_t *sp, int item)
{
    /*向sp->buffer插入一个item*/
    P(&sp->slots); // 等待有空槽
    P(&sp->mutex); // 进入临界区
    sp->buf[(++sp->rear) % (sp->n)] = item;
    V(&sp->mutex); // 离开临界区
    V(&sp->items); // 增加可用项目数
}

void sbuf_remove(sbuf_t *sp)
{
    /*从sp->buffer移除并返回一个item*/
    int item;
    P(&sp->items); // 等待有可用项目
    P(&sp->mutex); // 进入临界区
    item = sp->buf[(++sp->front) % (sp->n)];
    V(&sp->mutex); // 离开临界区
    V(&sp->slots); // 增加空槽数
    return item;
}