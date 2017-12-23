#ifndef FIREBASE_H
#define FIREBASE_H

#include <linux/list.h>
#include <linux/proc_fs.h>

typedef enum Operation { ALLOW, DENY } Operation;
typedef enum Action{ ADD, DELETE, MODIFY } Action;
typedef enum Protocol { TCP = 0x06, UDP = 0x17,ICMP = 0x16, IGMP = 0x88, ALL = 0 } Protocol;
typedef enum Type{ INPUT, OUTPUT } Type;
typedef enum State { ENABLED, DESABLED } State;

typedef struct rule{
        char *if_name;
        int action;
        uint32_t saddr;uint32_t smsk;uint32_t dmsk;uint32_t daddr;uint8_t sport;uint8_t dport;
        Protocol proto;
        Type type;
        struct list_head head;
} rule_t;
typedef struct cmd{
        Operation op;
        char *if_name;
        int action;
        char* saddr;char* smsk;char* dmsk;char* daddr;
        uint8_t sport;
        uint8_t dport;
        Type type;
        Operation proto;
        int enabled;
} cmd_t;

typedef struct firebase
{
        State state;
        uint32_t num_droped;
        uint32_t num_passed;
        uint32_t num_packets;

} firebase_t;
#endif

