/*
 * nat_leastrate.c
 *
 * A kernel module which implements a DNAT
 *
 * Compile using make. Use insmod nat_leastrate.ko to insert the module
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
#include <linux/limits.h>
#include <linux/time.h>

#define PUBLIC_IP_ADDRESS_NAT "\x98\xA8\x00\x15" // 152.168.0.21
#define PUBLIC_VIDEO_PORT_NAT "\x1F\x90"         // 8080
#define NUMBER_OF_SERVERS     4
#define MAX_TABLE_ENTRIES     10

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("NAT with least rate load balancing");

static const char *server_list[NUMBER_OF_SERVERS]={"\xC0\xA8\x01\x1", 	// 192.168.1.1
						  "\xC0\xA8\x02\x1", 	// 192.168.2.1
						  "\xC0\xA8\x03\x1",	// 192.168.3.1
						  "\xC0\xA8\x04\x1"};	// 192.168.4.1

static struct nf_hook_ops netfilter_ops_in, netfilter_ops_out;
static const char *if_eth0 = "eth0";
static const char *if_eth1 = "eth1";
static const char *if_eth2 = "eth2";
static const char *if_eth3 = "eth3";
static const char *if_eth4 = "eth4";
static const char *if_eth5 = "eth5";
static struct sk_buff *sock_buff;
static struct udphdr *udp_header;
static int server_rate[NUMBER_OF_SERVERS];
static int table_size = 0;


typedef struct nat_table {
	unsigned int client_ip;
	unsigned int server_ip;
	unsigned short client_port;
	struct timeval timestamp;
}nat_table;

static nat_table table_entry[MAX_TABLE_ENTRIES];

void init_packet_rate(void)
{
	int i;
	for(i=0; i < NUMBER_OF_SERVERS; i++)
		server_rate[i] = 0;
}

int find_server_index(unsigned int server_address)
{
	int i;
	for(i=0; i < NUMBER_OF_SERVERS; i++)
	{
		if( (*(unsigned int *)server_list[i]) == server_address)
			return i;
	}
	return -1;
}

int assign_lr_server(void)
{
	int i, index = 0;
	int min = INT_MAX;

	for(i=0; i < NUMBER_OF_SERVERS; i++)
	{
		if(server_rate[i] < min)
		{
			min = server_rate[i];
			index = i;
		}
	}
	return index;
}

void assign_timestamp(nat_table *rule)
{
	struct timeval t;
	do_gettimeofday(&t);
	rule->timestamp.tv_sec = t.tv_sec;
	rule->timestamp.tv_usec = t.tv_usec;
}

nat_table * least_used_table_entry(void)
{
	int i;
	nat_table * table_row = &table_entry[0];
	nat_table * table_id = NULL;
	struct timeval min;

	do_gettimeofday(&min);
	for(i = 0; i < MAX_TABLE_ENTRIES; i++, table_row++)
	{
		if(timeval_compare(&min, &(table_row->timestamp)) == 1)
		{
			min.tv_sec = table_row->timestamp.tv_sec;	
			min.tv_usec = table_row->timestamp.tv_usec;	
			table_id = table_row;
		}
	}
	return table_id;
}

nat_table * search_nat_table(unsigned int client_ipaddress, unsigned int client_port, int * index)
{
	int i;
	nat_table * table_pointer = &table_entry[0];

	for(i=0; i<table_size; i++, table_pointer++)
	{
		if( (table_pointer->client_ip == client_ipaddress) && (table_pointer->client_port == client_port) )
		{
			if( (*index = find_server_index(table_pointer->server_ip)) == -1)
			{
				*index = 0;
				printk(KERN_ERR "Unable to assign server index, set to 0\n");
			}
			return table_pointer;
		}
	}
	return NULL;
}

int insert_nat_table_least_rate(int source_ip, int source_port, int * index)
{
	nat_table * table_pointer = NULL;	
	if(!sock_buff)
		return 1;
	if(!ip_hdr(sock_buff))
		return 1;
	if(table_size >= MAX_TABLE_ENTRIES)
	{
		if( (table_pointer = least_used_table_entry()) == NULL )
		{
			printk(KERN_ERR "Timeout: Could not find least used table entry\n");
			return 1;
		}
	}
	else
	{
		table_pointer = &table_entry[table_size];
		table_size++;
	}
	table_pointer->client_ip = source_ip;
	table_pointer->client_port = source_port;
	*index = assign_lr_server();
	table_pointer->server_ip = *(unsigned int *)server_list[*index];
	assign_timestamp(table_pointer);
	init_packet_rate();
	ip_hdr(sock_buff)->daddr = table_pointer->server_ip;
	return 0;
}

unsigned int dnat_hook(unsigned int hooknum,
                       struct sk_buff *skb,
                       const struct net_device *in,
                       const struct net_device *out,
                       int (*okfn) (struct sk_buff *))
{
	unsigned int source_ip;
	unsigned short source_port;
	int udp_len, index=0;
	nat_table *rule; // A pointer to the structure of the corresponding rule

	/* Accept packets from servers */
	if(in)
	{
		if((strcmp(in->name, if_eth1) == 0) ||
		   (strcmp(in->name, if_eth2) == 0) ||
		   (strcmp(in->name, if_eth3) == 0) ||
		   (strcmp(in->name, if_eth4) == 0) ||
		   (strcmp(in->name, if_eth5) == 0)) 
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

		/* Check if it's a UDP packet and its destination port number */
		source_ip   =  ip_hdr(sock_buff)->saddr;
		if(( (ip_hdr(sock_buff))->protocol ) == IPPROTO_UDP)
		{
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
			rule = search_nat_table(source_ip, source_port, &index); 
			if(rule != NULL)
			{
				ip_hdr(sock_buff)->daddr = rule->server_ip;
				assign_timestamp(rule);
			}
			else
			{
				if(insert_nat_table_least_rate(source_ip, source_port, &index))
				{
					printk(KERN_ERR "Could not insert rule to NAT table\n");
					return NF_DROP;
				}
			}
			server_rate[index]++;
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
		} // if it is a UDP packet
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
	int udp_len, index=0;
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
			rule = search_nat_table(destination_ip, destination_port, &index); 
			if(rule == NULL)
			{
				printk(KERN_ERR "Rule not found in NAT table\n");
				return NF_DROP; //drop packet if rule is not found in NAT table
			}
			assign_timestamp(rule);
			server_rate[index]++;
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
	init_packet_rate();

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
