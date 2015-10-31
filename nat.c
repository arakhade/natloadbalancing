/*
 * nat.c
 *
 * A kernel module which implements a DNAT
 *
 * Compile using make. Use insmod nat.ko to insert the module
 *
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/ip.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/udp.h>

#define PUBLIC_IP_ADDRESS_NAT "\xC0\xA8\x01\x01" // 192.168.1.1
#define PUBLIC_VIDEO_PORT_NAT "\xC3\x50"         // 50000
#define NUMBER_OF_SERVERS     4
#define SERVER_IP_1           "\xC0\xA8\x01\x02" // 192.168.1.2
#define SERVER_IP_2           "\xC0\xA8\x01\x03" // 192.168.1.3
#define SERVER_IP_3           "\xC0\xA8\x01\x04" // 192.168.1.4
#define SERVER_IP_4           "\xC0\xA8\x01\x05" // 192.168.1.5

static struct nf_hook_ops netfilter_ops_in, netfilter_ops_out;
static char *if_eth0 = "eth0";
static char *if_eth1 = "eth1";
struct sk_buff *sock_buff;
struct udphdr *udp_header;

typedef struct nat_table {
	unsigned int client_ip;
	unsigned int server_ip;
	unsigned short client_port;
	unsigned short server_port;
	//timestamp to be done
	struct list_head list;
}nat_table;

struct list_head nat_head;
LIST_HEAD(nat_head);

int table_entries = 0;

nat_table * search_nat_table(unsigned int client_ipaddress, unsigned int client_port, int table_entries)
{
//	int i = 0;
//	for(;i<table_entries;i++)
//	{
//		if((nat_table_ptr[i]->client_ip == client_ipaddress) && (nat_table_ptr[i]->client_ip == client_port))
//			return nat_table_ptr[i];
//	}
	return NULL;
}

unsigned int dnat_hook(unsigned int hooknum,
                       struct sk_buff **skb,
                       const struct net_device *in,
                       const struct net_device *out,
                       int (*okfn) (struct sk_buff *))
{
	unsigned int source_ip;
	unsigned short source_port;
	nat_table *rule; // A pointer to the structure of the corresponding rule
	nat_table *temp;

	/* Accept packets from servers */
	if((strcmp(in->name, if_eth0) == 0) || 
		(strcmp(in->name, if_eth1) == 0)) 
	{ 
		return NF_ACCEPT; 
	}

    /* Drop packet if destination IP is not public IP of NAT */
	sock_buff = *skb;
	if(!sock_buff){ return NF_ACCEPT; }
	if(!(ip_hdr(sock_buff))){ return NF_ACCEPT; }
	if(( (ip_hdr(sock_buff))->daddr ) == *(unsigned int *)PUBLIC_IP_ADDRESS_NAT)
		return NF_DROP;
	
	/* Check if it's a UDP packet and its destination port number */
	if(( (ip_hdr(sock_buff))->protocol ) != 17){ return NF_ACCEPT; }

	source_ip   =  ip_hdr(sock_buff)->saddr;
	udp_header  =  (struct udphdr *)(sock_buff->data + (( (ip_hdr(sock_buff))->ihl ) * 4));
	if((udp_header->dest) != *(unsigned short *)PUBLIC_VIDEO_PORT_NAT) { return NF_DROP; }

	/* Search nat_table for client entry */
	source_port =  udp_header->source; 
	rule = search_nat_table(source_ip, source_port, table_entries); 
	if(rule != NULL)
	{
		ip_hdr(sock_buff)->daddr = rule->server_ip;
	}
	else
	{
		//insert rule to nat_table and update dest addr and dest port
		temp = kmalloc(sizeof(struct nat_table *), GFP_KERNEL);
		temp->client_ip = source_ip;
		temp->client_port = source_port;
		temp->server_ip = *(unsigned int *)SERVER_IP_1;
		ip_hdr(sock_buff)->daddr = temp->server_ip;
		list_add(&temp->list, &nat_head);
	}

	/* Accept all other packets */
	return NF_ACCEPT;
}

unsigned int snat_hook(unsigned int hooknum,
                       struct sk_buff **skb,
                       const struct net_device *in,
                       const struct net_device *out,
                       int (*okfn) (struct sk_buff *))
{
	unsigned int destination_ip;
	unsigned short destination_port;
	nat_table *rule; // A pointer to the structure of the corresponding rule

	/* Do not mangle packets other than from servers */
	if(!(strcmp(in->name, if_eth0) == 0) || 
		!(strcmp(in->name, if_eth1) == 0)) 
	{ 
		return NF_ACCEPT; 
	}

	/* Check if it's a UDP packet */
	sock_buff = *skb;
	if(!sock_buff){ return NF_ACCEPT; }
	if(!(ip_hdr(sock_buff))){ return NF_ACCEPT; }
	if(( (ip_hdr(sock_buff))->protocol ) != 17){ return NF_ACCEPT; }

	destination_ip   =  ip_hdr(sock_buff)->daddr;
	udp_header       =  (struct udphdr *)(sock_buff->data + (( (ip_hdr(sock_buff))->ihl ) * 4));
	destination_port =  udp_header->dest; 
	rule = search_nat_table(destination_ip, destination_port, table_entries); 
	if(rule != NULL)
	{
		ip_hdr(sock_buff)->saddr = *(unsigned int *)PUBLIC_IP_ADDRESS_NAT;
	}
	else
	{
		return NF_DROP; //drop packet if rule is not found in NAT table
	}
	return NF_ACCEPT;
}

int init_module()
{
	netfilter_ops_in.hook		=		(nf_hookfn *)dnat_hook;
	netfilter_ops_in.pf			=		PF_INET;
	netfilter_ops_in.hooknum	=		NF_INET_PRE_ROUTING;
	netfilter_ops_in.priority	=		NF_IP_PRI_FIRST;

	netfilter_ops_out.hook		=		(nf_hookfn *)snat_hook;
	netfilter_ops_out.pf		=		PF_INET;
	netfilter_ops_out.hooknum	=		NF_INET_POST_ROUTING;
	netfilter_ops_out.priority	=		NF_IP_PRI_FIRST;

	nf_register_hook(&netfilter_ops_in);
	nf_register_hook(&netfilter_ops_out);

	return 0;
}

void cleanup_module()
{
	nf_unregister_hook(&netfilter_ops_in);
	nf_unregister_hook(&netfilter_ops_out);
}
