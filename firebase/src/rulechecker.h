#ifndef RULECHK_H
#define RULECHK_H

#include <linux/string.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/ip.h>

#include "firebase.h"

int net_ipcmp( unsigned int ip, unsigned int ip_rule, unsigned int mask );
int host_ipcmp( unsigned int saddr , unsigned int daddr );
int tcp_rule_check( rule_t* rule , struct tcphdr* tcp_header );
int udp_rule_check( rule_t* rule , struct udphdr* udp_header );
int ipv4_rule_check( rule_t* rule , struct iphdr* ip_header );
int interface_check( rule_t* rule , struct net_device* interface ,
                     struct iphdr* ip_header );

#endif