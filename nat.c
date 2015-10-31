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

#define PUBLIC_IP_ADDRESS_NAT "\xC0\xA8\x01\x01" // 192.168.0.1
#define PUBLIC_VIDEO_PORT_NAT "\xC3\x50"         // 50000
#define NUMBER_OF_SERVERS     4

char *server_ip[4]={	"\xC0\xA8\x01\x15", // 192.168.1.21
						"\xC0\xA8\x01\x16", // 192.168.1.22
						"\xC0\xA8\x01\x17",	// 192.168.1.23
						"\xC0\xA8\x01\x18"};// 192.168.1.24
static int round_robin_server_number = 0;

static struct nf_hook_ops netfilter_ops_in, netfilter_ops_out;
static char *if_eth0 = "eth0";
static char *if_eth1 = "eth1";
/*static char *if_eth2 = "eth2";
static char *if_eth3 = "eth3";
static char *if_eth4 = "eth4";*/
struct sk_buff *sock_buff;
struct udphdr *udp_header;

typedef struct nat_table {
	unsigned int client_ip;
	unsigned int server_ip;
	unsigned short client_port;
	unsigned short server_port;
	//timestamp to be done
	
	struct list_head list;
	/*struct list_head{
		struct list_head *next;
		struct list_head *prev;
	}*/
	
}nat_table;


LIST_HEAD(nat_head);

int table_entries = 0;

nat_table * search_nat_table(unsigned int client_ipaddress, unsigned int client_port,struct list_head *nat_head)
{
	nat_table *table_row;
	struct list_head *ptr;
	unsigned int  cl_ip;
	unsigned short cl_port;
	list_for_each(ptr, nat_head)
	{
			table_row = list_entry(ptr, struct nat_table, list);
			cl_ip = table_row->client_ip;	
			cl_port = table_row->client_port;
			if(client_ipaddress== cl_ip && client_port == cl_port)
				return table_row;
	}
	return NULL;
}

int	insert_nat_table_roundrobin(int source_ip,int source_port,struct list_head *nat_head)
{	
	nat_table * temp;
	//return 0 if not possible else retun 1;
	temp = kmalloc(sizeof(struct nat_table *), GFP_KERNEL);
	if(temp == NULL)
		return 0;
	temp->client_ip = source_ip;
	temp->client_port = source_port;
	temp->server_ip = *(unsigned int *)server_ip[round_robin_server_number];
	ip_hdr(sock_buff)->daddr = temp->server_ip;
	list_add(&temp->list, nat_head);
	round_robin_server_number = (round_robin_server_number+1)%4;
	
	return 1;
	
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
	if(( (ip_hdr(sock_buff))->daddr ) != *(unsigned int *)PUBLIC_IP_ADDRESS_NAT)
		return NF_DROP;
	
	/* Check if it's a UDP packet and its destination port number */
	if(( (ip_hdr(sock_buff))->protocol ) != 17){ return NF_ACCEPT; }

	source_ip   =  ip_hdr(sock_buff)->saddr;
	udp_header  =  (struct udphdr *)(sock_buff->data + (( (ip_hdr(sock_buff))->ihl ) * 4));
	if((udp_header->dest) != *(unsigned short *)PUBLIC_VIDEO_PORT_NAT) { return NF_DROP; }

	/* Search nat_table for client entry */
	source_port =  udp_header->source; 
	rule = search_nat_table(source_ip, source_port,&nat_head); 
	
	if(rule != NULL)
	{
		ip_hdr(sock_buff)->daddr = rule->server_ip;
	}
	else
	{
		if(!(insert_nat_table_roundrobin(source_ip,source_port,&nat_head)))
			return NF_DROP;
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
	rule = search_nat_table(destination_ip, destination_port, &nat_head); 
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
