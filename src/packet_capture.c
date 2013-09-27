#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <linux/init.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Patrick Conner, Ho Yin Pun");


/* PARAMS */
static char *iface = "eth0";
static int run_time = 150;
module_param(iface, charp, 0);
module_param(run_time, int, 0 );




const float GROWTH_FACTOR = 0.75;
static int array_size, item_count;

typedef struct map
{
	unsigned int dst;
	int count; 
} map_t;

static struct nf_hook_ops nfho;  //struct holding set of hook function options

static map_t** map;
void insert_map(map_t** mp, int* size, int* itemc, unsigned int dstip, int set_count);
void dstlookup(unsigned int dstip);
int get_count(unsigned int dstip);
void free_hash();

static unsigned int packet_interceptor_hook(unsigned int hook, 
	struct sk_buff *pskb, 
	const struct net_device *indev, 
	const struct net_device *outdev, 
	int (*okfn)(struct sk_buff *))
{
	

	struct iphdr *ip_header = (struct iphdr *)skb_network_header(pskb);
	/*
	if(ip_header == NULL)
		printk(KERN_INFO "ip header is null");
	else 
  	{
		printk(KERN_INFO "ip header is not null");
		if(ip_header->saddr == NULL)
    		{
			printk(KERN_INFO "\tsaddr is not null");
		}
	}	
*/
	dstlookup(ip_header->daddr);
	printk(KERN_INFO "Received-Interface: %s   ---   SRC-IP: %d   ---   DST-IP: %d   ---   Packet-Count: \n", indev->name, ip_header->saddr, ip_header->daddr);  
   
	return NF_ACCEPT;  //accepts the packet        
}

//Called when module loaded using 'insmod'
int init_module()
{
	array_size = 13;
	item_count = 0;
	map = vmalloc(sizeof(map_t*)*array_size);
  
	nfho.hook = packet_interceptor_hook;  //function to call when conditions below met
	nfho.hooknum = 0;  //called right after packet recieved, first hook in Netfilter
	nfho.pf = PF_INET;  //IPV4 packets
	nfho.priority = NF_IP_PRI_FIRST;  //set to highest priority over all other hook functions
	nf_register_hook(&nfho);  //register hook
	printk("Running on interface %s for %ds\n", iface, run_time);
	return 0;  //return 0 for successi
}

//Called when module unloaded using 'rmmod'
void cleanup_module()
{
	nf_unregister_hook(&nfho);  //cleanup – unregister hook
	free_hash();
}


void free_hash()
{
	//delete hash table stuff
	for(int i = 0; i < array_size; i++)
	{
		vfree(map[i]);
	}
	vfree(map);
}

int get_count(unsigned int dstip)
{
	int index = dstip%array_size;
	while(map[index] && map[index]->dst != dstip)
  	{
		index++;
		if(index == array_size) index = 0;
    		if(map[index]==NULL) return -1;
    
  	}
	return map[index]->count;
}

void dstlookup(unsigned int dstip)
{
	insert_map(map, &array_size, &item_count, dstip,0);
	float gf = (float)item_count/array_size;
	if(gf >= GROWTH_FACTOR)
  	{
		array_size *= 22;
		map_t** newmap = vmalloc(sizeof(map_t*)*array_size);
		int i;
    		int temp_item_ct = 0;
    		for(i = 0; i < array_size/2; i++)
		{
        		if(map[i])
	  			insert_map(newmap, &array_size, &temp_item_ct,map[i]->dst,map[i]->count); 
    		}
    		vfree(map);
    		map = newmap;
  	}
}


void insert_map(map_t** mp, int* size, int* itemc, unsigned int dstip, int set_count)
{
	int index = dstip % *size;
  
	if(mp[index])
	{
		while(mp[index] && mp[index++]->dst != dstip)
        		if(index == *size) index = 0;

		if(mp[index]) 
			mp[index]->count++;
    		else
    		{
        		mp[index] = vmalloc(sizeof(map_t));
        		mp[index]->dst = dstip;
        		mp[index]->count = 1;
        		*itemc++;
    		}
	}		
	else
	{
		mp[index] = vmalloc(sizeof(map_t));
    		mp[index]->dst = dstip;
    		mp[index]->count = 1;
    		*itemc++;
  	}
	if(set_count !=0) mp[index]->count = set_count;
}
