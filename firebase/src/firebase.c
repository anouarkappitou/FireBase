#include <linux/module.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#include <linux/slab.h>
#include <linux/seq_file.h>
#include <linux/list.h>

#include <linux/string.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/ip.h>

#define KERNEL

#include "firebase.h"
#include "cmd_parser.h"
#include "rulechecker.h"

#define PROCFS_NAME "firebase"
#define PROCFS_MOD      644
#define CMD_LEN (512)

static char *cmd;
static struct proc_dir_entry *procf;
rule_t* policies;
firebase_t app;


void
tcp_packet_filter(
        struct sk_buff *skb,
        rule_t *rule )
{

}

void udp_packer_filter(
            struct sk_buff* skb,
            rule_t* rule )
{

}

static unsigned int
hook_func_out(unsigned int hooknum,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn) (struct sk_buff *))
{
    struct udphdr *udp_header;
    struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);

    struct list_head* pos;
    rule_t *rule;

    list_for_each( pos , &policies->head )
    {

            rule = list_entry( pos , rule_t , head );

            if( rule->type == INPUT ) continue;

            printk( "[OUTPUT] : destination addr : %u\n" , rule->daddr );

            printk( "ipv4 res : %d\n" , ipv4_rule_check( rule , ip_header ) );

            if( ipv4_rule_check( rule , ip_header ) )
            {
                    return NF_DROP;
            }

    }

    return NF_ACCEPT;
}

static unsigned int
hook_func_in(unsigned int hooknum,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn) (struct sk_buff *))
{
    struct udphdr *udp_header;
    struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);

        struct list_head* pos;
        rule_t *rule;

        list_for_each( pos , &policies->head )
        {

                rule = list_entry( pos , rule_t , head );


                if( rule->type == OUTPUT ) continue;

                printk( "[ INPUT ] : rule destination addr : %u packer destination addr : %u\n" , rule->daddr , ip_header->daddr);

                printk( "ipv4 res : %d\n" , ipv4_rule_check( rule , ip_header ) );

                if( ipv4_rule_check( rule , ip_header ) )
                {
                        return NF_DROP;
                }


        }


    return NF_ACCEPT;
}

int
add_rule( rule_t * list , rule_t* new )
{
        INIT_LIST_HEAD( &new->head );
        list_add( &new->head , &list->head );
}

static ssize_t
proc_write(struct file *filp,const char *buf,size_t count,loff_t *offp)
{

        memset( cmd , 0 , CMD_LEN );

        if( count > CMD_LEN )
                return -ENOMEM;

        copy_from_user( cmd , buf, count );

        rule_t* newrule = kmalloc( sizeof( rule_t ) , GFP_KERNEL );
        cmd_t* newcmd   = kmalloc( sizeof( cmd_t ) , GFP_KERNEL );

        if( parse_cmd( cmd , newcmd ) != 0 )
        {
                kfree( newrule );
                return count;
        }

        rule_init( &app , newcmd , newrule );

        if( newcmd->op == ADD ){
                add_rule( policies , newrule );
                printk( "adding rule\n" );
        }

        //newrule->smsk = ip_to_bytes( "255.0.0.0" );
        //newrule->dmsk = ip_to_bytes( "255.255.255.0" );

        struct list_head* pos;
        rule_t *rule;

        bool found = false;

        list_for_each( pos , &policies->head )
        {
                rule = list_entry( pos , rule_t , head );

                if( rules_cmp( rule , newrule ) )
                {
                        found = true;
                }
        }


        return count;
}

static int
proc_read( struct file* m, char __user * v , size_t size , loff_t* offset )
{
        // STUB FUNC
        return 0;
}

static int
proc_open( struct inode* node , struct file* file )
{
        return single_open( file , proc_read , NULL );
}

static const struct file_operations ops = {

        .owner = THIS_MODULE,
        .open  = proc_open,
        .read  = seq_read,
        .llseek = seq_lseek,
        .release = single_release,
        .write  = proc_write
};

static struct nf_hook_ops nfho = {

    .hook       = hook_func_out,
    .hooknum    = NF_INET_LOCAL_OUT, /* NF_IP_LOCAL_IN */
    .pf         = PF_INET,
    .priority   = NF_IP_PRI_FIRST,
};

static struct nf_hook_ops nfhi = {

    .hook       = hook_func_in,
    .hooknum    = NF_INET_LOCAL_IN, /* NF_IP_LOCAL_IN */
    .pf         = PF_INET,
    .priority   = NF_IP_PRI_FIRST,
};


int
init_module( void )
{
        nf_register_hook(&nfho);
        nf_register_hook(&nfhi);

        app.state = ENABLED;
        app.num_droped = 0;
        app.num_passed = 0;

 		policies = kmalloc( sizeof( rule_t ) , GFP_KERNEL );

        INIT_LIST_HEAD( &policies->head );


        cmd = kmalloc( CMD_LEN , GFP_KERNEL );
        procf = proc_create( PROCFS_NAME , PROCFS_MOD , NULL , &ops );

        if( procf == NULL )
        {
                printk( "\nFailed to create procfile" );
                return -ENOMEM;
        }

        printk( "\nModule was installed succesfly" );

        return 0;
}


void
cleanup_module( void )
{
        nf_unregister_hook(&nfho);
        nf_unregister_hook(&nfhi);
        remove_proc_entry( PROCFS_NAME , procf );

        printk( "\nModule was unnistalled" );
}


MODULE_AUTHOR( "Kappitou anouar" );
MODULE_DESCRIPTION( "Module for packets filtering" );
MODULE_LICENSE("GPL");

