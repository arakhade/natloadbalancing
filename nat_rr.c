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

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("NAT with round robin load balancing");

static const char *server_list[4]={"\xC0\xA8\x01\x1", 	// 192.168.1.1
				   "\xC0\xA8\x01\x1", 	// 192.168.2.1
				   "\xC0\xA8\x01\x1",	// 192.168.3.1
				   "\xC0\xA8\x01\x1"};	// 192.168.4.1

static struct nf_hook_ops netfilter_ops_in, netfilter_ops_out;
static const char *if_eth0 = "eth0";
static const char *if_eth1 = "eth1";
static const char *if_eth2 = "eth2";
static const char *if_eth3 = "eth3";
static const char *if_eth4 = "eth4";
static struct sk_buff *sock_buff;
static struct udphdr *udp_header;
static int round_robin_server_number = 0;
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

static nat_table nat_head;

nat_table * search_nat_table(unsigned int client_ipaddress, unsigned int client_port)
{
	nat_table *table_row;
	struct list_head *ptr;
	unsigned int  cl_ip;
	unsigned short cl_port;
	list_for_each(ptr, &nat_head.list)
	{
		table_row = list_entry(ptr, struct nat_table, list);
		cl_ip = table_row->client_ip;	
		cl_port = table_row->client_port;
		if(client_ipaddress== cl_ip && client_port == cl_port)
			return table_row;
	}
	return NULL;
}

int insert_nat_table_roundrobin(int source_ip,int source_port)
{	
	nat_table * temp;
	temp = kmalloc(sizeof(struct nat_table *), GFP_KERNEL);
	if(!temp)
	{
		printk(KERN_ERR "kmalloc failed\n");
		return 0;
	}
	temp->client_ip = source_ip;
	temp->client_port = source_port;
	temp->server_ip = *(unsigned int *)server_list[round_robin_server_number];
	if(!sock_buff)
		return 0;
	if(!ip_hdr(sock_buff))
		return 0;
	ip_hdr(sock_buff)->daddr = temp->server_ip;
	INIT_LIST_HEAD(&temp->list);
	list_add_tail(&temp->list, &nat_head.list);
	round_robin_server_number = (round_robin_server_number + 1) % NUMBER_OF_SERVERS;
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

	/* Accept packets from servers */
	if(in)
	{
		if((strcmp(in->name, if_eth1) == 0) ||
		   (strcmp(in->name, if_eth2) == 0) ||
		   (strcmp(in->name, if_eth3) == 0) ||
		   (strcmp(in->name, if_eth4) == 0)) 
		{ 
			return NF_ACCEPT; 
		}
		sock_buff = skb;
		if(!sock_buff)
		{
			printk(KERN_ERR "Socket buffer not initialized\n");
			return NF_ACCEPT; 
		}
		if(!(ip_hdr(sock_buff)))
		{
			printk(KERN_ERR "IP header not initialized\n");
			return NF_ACCEPT; 
		}
		if(!( (ip_hdr(sock_buff))->daddr ))
		{
			printk(KERN_ERR "Destination IP address not initialized\n");
			return NF_ACCEPT;
		}
		if(( (ip_hdr(sock_buff))->daddr ) != *(unsigned int *)PUBLIC_IP_ADDRESS_NAT)
		{
			printk(KERN_INFO "Dropped. Cause: Not destined to public IP of NAT");
			return NF_DROP;
		}

		/* Check if it's a UDP packet and its destination port number */
		source_ip   =  ip_hdr(sock_buff)->saddr;
		if(( (ip_hdr(sock_buff))->protocol ) == IPPROTO_UDP)
		{
			udp_header  =  (struct udphdr *)(sock_buff->data + (( (ip_hdr(sock_buff))->ihl ) * 4));
			if(!udp_header)
			{
				printk(KERN_ERR "UDP header not initialized\n");
				return NF_ACCEPT;
			}
			if((udp_header->dest) != *(unsigned short *)PUBLIC_VIDEO_PORT_NAT) 
			{
				printk(KERN_INFO "Dropped. Cause: Not destined to public port of NAT\n");
				return NF_DROP; 
			}
			/* Search nat_table for client entry */
			source_port =  udp_header->source; 
			udp_len = (sock_buff->len - (ip_hdr(sock_buff)->ihl << 2));
			rule = search_nat_table(source_ip, source_port); 
			if(rule != NULL)
			{
				ip_hdr(sock_buff)->daddr = rule->server_ip;
			}
			else
			{
				if(!(insert_nat_table_roundrobin(source_ip, source_port)))
				{
					printk(KERN_ERR "Could not insert rule to NAT table\n");
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
		}
	}
	else // if(in)
	{
		printk(KERN_ERR "Error:Input interface not initialized\n");
	}

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
	/* Do not mangle packets other than from servers */
	if(out)
	{
		if(!(strcmp(out->name, if_eth0) == 0)) 
		{
			return NF_ACCEPT; 
		}
		sock_buff = skb;
		if(!sock_buff)
		{
			printk(KERN_ERR "Socket buffer not initialized\n");
			return NF_ACCEPT;
		}
		if(!(ip_hdr(sock_buff)))
		{
			printk(KERN_ERR "IP header not initialized\n");
			return NF_ACCEPT;
		}

		/* Check if it's a UDP packet */
		if(( (ip_hdr(sock_buff))->protocol ) == IPPROTO_UDP)
		{
			destination_ip   =  ip_hdr(sock_buff)->daddr;
			udp_header       =  (struct udphdr *)(sock_buff->data + (( (ip_hdr(sock_buff))->ihl ) * 4));
			if(!udp_header)
			{
				printk(KERN_ERR "UDP header not initialized\n");
				return NF_ACCEPT;
			}
			destination_port =  udp_header->dest; 
			udp_len          =  (sock_buff->len - (ip_hdr(sock_buff)->ihl << 2));
			rule = search_nat_table(destination_ip, destination_port); 
			if(rule == NULL)
			{
				printk(KERN_ERR "Rule not found in NAT table\n");
				return NF_DROP; //drop packet if rule is not found in NAT table
			}
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
		}
	}
	else // if(out)
	{
		printk(KERN_ERR "Error:Output interface not initialized\n");
	}
		return NF_ACCEPT;
}
int init_module()
{
	//LIST_HEAD(nat_head);
	INIT_LIST_HEAD(&nat_head.list);
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
	struct list_head *p, *q;
	struct nat_table *an_entry;

	nf_unregister_hook(&netfilter_ops_in);
	nf_unregister_hook(&netfilter_ops_out);

	list_for_each_safe(p, q, &nat_head.list)
	{
		an_entry = list_entry(p, struct nat_table, list);
		list_del(p);
		kfree(an_entry);
	}
}
