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

#define PUBLIC_IP_ADDRESS_NAT "\x98\xA8\x00\x15" // 152.168.0.21
#define PUBLIC_VIDEO_PORT_NAT "\x1F\x90"         // 8080
#define NUMBER_OF_SERVERS     4

static char *server_ip[4]={"\xC0\xA8\x01\x1", 	// 192.168.1.1
					"\xC0\xA8\x01\x1", 	// 192.168.2.1
					"\xC0\xA8\x01\x1",	// 192.168.3.1
					"\xC0\xA8\x01\x1"};	// 192.168.4.1

static int round_robin_server_number = 0;
static struct nf_hook_ops netfilter_ops_in, netfilter_ops_out;
static char *if_eth0 = "eth0";
static char *if_eth1 = "eth1";
static char *if_eth2 = "eth2";
static char *if_eth3 = "eth3";
static char *if_eth4 = "eth4";
static struct sk_buff *sock_buff;
static struct udphdr *udp_header;
static LIST_HEAD(nat_head);
static int table_entries = 0;


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

nat_table * search_nat_table(unsigned int client_ipaddress, unsigned int client_port)
{
	nat_table *table_row;
	struct list_head *ptr;
	unsigned int  cl_ip;
	unsigned short cl_port;
	list_for_each(ptr, &nat_head)
	{
		table_row = list_entry(ptr, struct nat_table, list);
		cl_ip = table_row->client_ip;	
		cl_port = table_row->client_port;
		if(client_ipaddress== cl_ip && client_port == cl_port)
			return table_row;
	}
	return NULL;
}

int	insert_nat_table_roundrobin(int source_ip,int source_port)
{	
	nat_table * temp;
	//return 0 if not possible else retun 1;
	temp = kmalloc(sizeof(struct nat_table *), GFP_KERNEL);
	if(temp == NULL)
		return 0;
	temp->client_ip = source_ip;
	temp->client_port = source_port;
	temp->server_ip = *(unsigned int *)server_ip[round_robin_server_number];
	if(!sock_buff)
		return 0;
	else if(!ip_hdr(sock_buff))
		return 0;
	ip_hdr(sock_buff)->daddr = temp->server_ip;
	list_add(&temp->list, &nat_head);
	round_robin_server_number = (round_robin_server_number + 1) % 4;
	return 1;
}

unsigned int dnat_hook(unsigned int hooknum,
                       struct sk_buff *skb,
                       const struct net_device *in,
                       const struct net_device *out,
                       int (*okfn) (struct sk_buff *))
{
	unsigned int source_ip;
	unsigned short source_port;
	int udp_len;
	nat_table *rule; // A pointer to the structure of the corresponding rule

	printk("1\n");
	/* Accept packets from servers */
	if(in)
	{
		printk("2\n");
		if((strcmp(in->name, if_eth1) == 0) ||
			(strcmp(in->name, if_eth2) == 0) ||
			(strcmp(in->name, if_eth3) == 0) ||
			(strcmp(in->name, if_eth4) == 0)) 
		{ 
			printk("3\n");
			return NF_ACCEPT; 
		}
	}
	sock_buff = skb;
	if(!sock_buff)
	{
		printk("4\n");
		return NF_ACCEPT; 
	}
	if(!(ip_hdr(sock_buff)))
	{
		printk("5\n");
		return NF_ACCEPT; 
	}
	if(!( (ip_hdr(sock_buff))->daddr ))
	{
		printk("6\n");
		return NF_ACCEPT;
	}
	if(( (ip_hdr(sock_buff))->daddr ) != *(unsigned int *)PUBLIC_IP_ADDRESS_NAT)
	{
		printk("7\n");
		return NF_DROP;
	}
	if(!( (ip_hdr(sock_buff))->protocol ))
	{
		return NF_ACCEPT;
	}
	/* Check if it's a UDP packet and its destination port number */
	if(( (ip_hdr(sock_buff))->protocol ) != 17)
	{
		printk("8\n");
		return NF_ACCEPT;
	}
	
	source_ip   =  ip_hdr(sock_buff)->saddr;
	udp_header  =  (struct udphdr *)(sock_buff->data + (( (ip_hdr(sock_buff))->ihl ) * 4));
	if(!udp_header)
	{
		printk("9\n");
		return NF_ACCEPT;
	}
	if((udp_header->dest) != *(unsigned short *)PUBLIC_VIDEO_PORT_NAT) 
	{
		printk("10\n");
		return NF_DROP; 
	}
	/* Search nat_table for client entry */
	source_port =  udp_header->source; 
	udp_len = (sock_buff->len - (ip_hdr(sock_buff)->ihl << 2));
	rule = search_nat_table(source_ip, source_port); 
	printk("11\n");
	if(rule != NULL)
	{
		printk("12\n");
		ip_hdr(sock_buff)->daddr = rule->server_ip;
	}
	else
	{
		printk("13\n");
		if(!(insert_nat_table_roundrobin(source_ip, source_port)))
		{
			printk("13\n");
			return NF_DROP;
		}
	}
	udp_header->check = 0;
	udp_header->check = csum_tcpudp_magic(ip_hdr(sock_buff)->saddr,
					      ip_hdr(sock_buff)->daddr,
					      udp_len,
					      IPPROTO_UDP,
					      csum_partial((unsigned char *)udp_header,
					      udp_len,
							   0));
	ip_hdr(sock_buff)->check = 0;
	ip_hdr(sock_buff)->check = ip_fast_csum(ip_hdr(sock_buff), ip_hdr(sock_buff)->ihl);
	printk("13\n");
	/* Accept all other packets */
	return NF_ACCEPT;
}

unsigned int snat_hook(unsigned int hooknum,
                       struct sk_buff *skb,
                       const struct net_device *in,
                       const struct net_device *out,
                       int (*okfn) (struct sk_buff *))
{
	unsigned int destination_ip;
	unsigned short destination_port;
	int udp_len;
	nat_table *rule; // A pointer to the structure of the corresponding rule
	printk("14\n");
	/* Do not mangle packets other than from servers */
	if(out)
	{
		printk("15\n");
		if(!(strcmp(out->name, if_eth0) == 0)) 
		{
			printk("16\n");
			return NF_ACCEPT; 
		}
	}

	/* Check if it's a UDP packet */
	sock_buff = skb;
	printk("17\n");
	if(!sock_buff)
	{
		printk("18\n");
		return NF_ACCEPT;
	}
	if(!(ip_hdr(sock_buff)))
	{
		printk("19\n");
		return NF_ACCEPT;
	}
	if(( (ip_hdr(sock_buff))->protocol ) != 17)
	{
		printk("20\n"); 
		return NF_ACCEPT; 
	}
	destination_ip   =  ip_hdr(sock_buff)->daddr;
	udp_header       =  (struct udphdr *)(sock_buff->data + (( (ip_hdr(sock_buff))->ihl ) * 4));
	if(!udp_header)
	{
		return NF_ACCEPT;
	}
	destination_port =  udp_header->dest; 
	udp_len          =  (sock_buff->len - (ip_hdr(sock_buff)->ihl << 2));
	rule = search_nat_table(destination_ip, destination_port); 
	printk("21\n");
	if(rule == NULL)
	{
		printk("22\n");
		return NF_DROP; //drop packet if rule is not found in NAT table
	}
	printk("23\n");
	ip_hdr(sock_buff)->saddr = *(unsigned int *)PUBLIC_IP_ADDRESS_NAT;
	udp_header->check = 0;
	udp_header->check = csum_tcpudp_magic(ip_hdr(sock_buff)->saddr,
					    ip_hdr(sock_buff)->daddr,
					    udp_len,
					    IPPROTO_UDP,
					    csum_partial((unsigned char *)udp_header,
						udp_len,
						0));
						
	ip_hdr(sock_buff)->check = 0;
	ip_hdr(sock_buff)->check = ip_fast_csum(ip_hdr(sock_buff), ip_hdr(sock_buff)->ihl);
	printk("24\n");
	return NF_ACCEPT;
}
int init_module()
{
	netfilter_ops_in.hook		=		(nf_hookfn *)dnat_hook;
	netfilter_ops_in.pf		=		PF_INET;
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
