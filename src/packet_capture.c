#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <linux/init.h>
#include <linux/hash.h>
#include <linux/list.h>
#include <linux/string.h>
#include <linux/time.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Patrick Conner, Ho Yin Pun");


/* PARAMS */
static char *iface = "eth0";
static int run_time = 150;
module_param(iface, charp, 0);
module_param(run_time, int, 0 );

typedef struct hte{
	unsigned int addr;
	unsigned int count;
	struct hlist_node node;
} hte_t;

struct timespec* ts;

long end_s;//end time, in seconds

hte_t* __make_hte(unsigned int addr, unsigned int count);
void insert_ip(unsigned int ip);

void print_all(void);
static struct nf_hook_ops nfho;  //struct holding set of hook function options

static struct iphdr *ip_header;
int in_time_limit(void);


#define GLOBAL_MAP_SIZE 1024
struct hlist_head** global_map;

static unsigned int packet_interceptor_hook(unsigned int hook, 
	struct sk_buff *pskb, 
	const struct net_device *indev, 
	const struct net_device *outdev, 
	int (*okfn)(struct sk_buff *))
{
	if(strcmp(iface, indev->name) == 0){
		if(/*in_time_limit()==*/1){	
	 		ip_header = (struct iphdr *)skb_network_header(pskb);
			insert_ip(ip_header->daddr);
			insert_ip(ip_header->saddr);
			//printk(KERN_INFO "------------------------------------\n");
			//printk("in iface: %s - out iface: %s \n", indev->if_port, outdev->if_port);
			/*
			if(indev->name) printk("input iface: %s ", indev->name);
			if(outdev->name) printk("output iface: %s ", outdev->name);
			printk("\n");
			*/
		}
		else{
			printk("END OF PACKET CAPTURE TIME \n");
		}
	}
	return NF_ACCEPT;  //accepts the packet        
}

//Called when module loaded using 'insmod'
int init_module()
{

	global_map = (struct hlist_head**)kmalloc(sizeof(struct hlist_head*)*GLOBAL_MAP_SIZE, GFP_KERNEL);
	for(int i = 0; i < GLOBAL_MAP_SIZE; i++)
		global_map[i] = NULL;
	//getnstimeofday(ts);
	//if(ts)
	//	end_s = ts->tv_sec + run_time;
	
	nfho.hook = packet_interceptor_hook;  //function to call when conditions below met
	nfho.hooknum = 0;  //called right after packet recieved, first hook in Netfilter
	nfho.pf = PF_INET;  //IPV4 packets
	nfho.priority = NF_IP_PRI_FIRST;  //set to highest priority over all other hook functions
	nf_register_hook(&nfho);  //register hook
	

	//test
	//insert_ip(1);
	//insert_ip(2);
	//if(ts)
	//	printk("starting packet capture at system time %ld\n", ts->tv_sec);
	return 0;  //return 0 for successi
}

//Called when module unloaded using 'rmmod'
void cleanup_module()
{
	print_all();
	nf_unregister_hook(&nfho);  //cleanup – unregister hook
	//TODO - cleanup hash table
}


int in_time_limit(){
	getnstimeofday(ts);
	if(ts->tv_sec <= end_s)		
		return 1;
	printk("Ending at system time %ld\n", ts->tv_sec);
	return 0;
}

void insert_ip(unsigned int ip){
	unsigned int iphash = hash_32(ip, 10);//10 bits in 1024
	if(global_map[iphash]){
		struct hlist_node* n;
		hte_t* h;
		hlist_for_each_entry(h, n, global_map[iphash], node){
			if(h->addr == ip){
				h->count++;
				return;
			}
		}
		hte_t* add_new = __make_hte(ip,1);
		hlist_add_after(&h->node, &add_new->node);
	}
	else{
		hte_t* new = __make_hte(ip, 1);
		global_map[iphash] = kmalloc(sizeof(struct hlist_head), GFP_KERNEL);
		INIT_HLIST_HEAD(global_map[iphash]);
		INIT_HLIST_NODE(&new->node);
		hlist_add_head(&new->node, global_map[iphash]);

	}
}


hte_t* __make_hte(unsigned int addr, unsigned int count){
	hte_t* new = (hte_t*)kmalloc(sizeof(hte_t), GFP_KERNEL);
	new->addr = addr;
	new->count = count;

	return new;
}

void print_all(){
	int i;
	hte_t* h;
	struct hlist_node* n;

	for(i = 0; i < GLOBAL_MAP_SIZE; i++){
		if(global_map[i]){
			
			hlist_for_each(n, global_map[i]){
				h = hlist_entry(n, hte_t, node);
				if(h) printk("IP: %pI4 - count: %d\n", &h->addr, h->count);
				
			}
			
			//printk("first ip - %d first count - %d\n", hlist_entry(global_map[i]->first, hte_t, node)->addr,hlist_entry(global_map[i]->first, hte_t, node)->count);
		}
	}
}
