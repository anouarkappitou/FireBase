#include "rulechecker.h"

#define NULL_CHECK( obj ) if( obj == NULL ) return 0

int net_ipcmp(unsigned int ip, unsigned int ip_rule, unsigned int mask) {

    unsigned int tmp = ntohl(ip);    //network to host long

    int cmp_len = 32;

    int i = 0, j = 0;

    printk(KERN_INFO "\ncompare ip: %u <=> %u\n", tmp, ip_rule);

    if (mask != 0) {

       cmp_len = 0;

       for (i = 0; i < 32; ++i) {

      if (mask & (1 << (32-1-i)))

         cmp_len++;

      else

         break;

       }

    }

    for (i = 31, j = 0; j < cmp_len; --i, ++j) {

        if ((tmp & (1 << i)) != (ip_rule & (1 << i))) {

            printk(KERN_INFO "ip compare: %d bit doesn't match\n", (32-i));

            return 0;

        }

    }

    return 1;
}

int host_ipcmp( unsigned int saddr , unsigned int daddr )
{
        saddr = ntohl(saddr);    //network to host long

        printk( "\n[ HOST ] : comparing %u <=> %u\n" , saddr , daddr );

        int output = !( ( saddr ^ daddr ) );

        printk( "Result : %d\n" , output );

        return output;
}

int tcp_rule_check( rule_t* rule , struct tcphdr* tcp_header )
{

}

int udp_rule_check( rule_t* rule , struct udphdr* udp_header )
{

}

int interface_check( rule_t* rule , struct net_device* interface ,
                     struct iphdr* ip_header )
{

    NULL_CHECK( rule );
    NULL_CHECK( interface );
    NULL_CHECK( ip_header );

    int ret = 0;

    if( rule->if_name == NULL ) return ret;

    if( strcmp( rule->if_name , interface->name ) == 0 )
    {
        if( rule->proto == NONE ) return 1;

        if( rule->proto == ip_header->protocol ) return 1;
    }

    return 0;

}

int ipv4_rule_check( rule_t* rule , struct iphdr* ip_header )
{
        int ret = 0;
        // check destination ip match

        // this is shit refactor is better idea

        bool is_source = false, is_dest = false;


        printk( "checking ipv4 rule" );

        if( rule->daddr != 0 ){

                if( rule->dmsk == 0 )
                {
                        printk( "destination mask is null\n" );
                        if( host_ipcmp( ip_header->daddr , rule->daddr ) ) {

                                ret = 1;
                        }
                }else
                {
                        if( net_ipcmp( ip_header->daddr , rule->daddr , rule->dmsk ) )
                        {
                                ret = 1;
                        }
                }
        }

        if( rule->saddr != 0 )
        {
                if( rule->smsk == 0 )
                {
                        if( host_ipcmp( ip_header->saddr , rule->saddr ) )
                        {
                                ret = 1;
                        }
                }else
                {
                        if( net_ipcmp( ip_header->saddr , rule->saddr , rule->dmsk ) )
                        {
                                ret = 1;
                        }
                }
        }

        return ret;
}
