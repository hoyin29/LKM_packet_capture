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


/*
const float GROWTH_FACTOR = 0.75;
static int array_size, item_count;

typedef struct map
{
	unsigned int dst;
	int count; 
} map_t;
*/


#define LOAD_FACTOR 0.5
#define REGROW_FACTOR 2
#define INITIAL_SIZE 10

typedef struct hash_map_entry
{
    unsigned int key;
    int value;
} hash_map_entry_t;

typedef struct hash_map
{
    int map_size;
    int entry_count;
    hash_map_entry_t** container;
} hash_map_t;

void free_hash_map(hash_map_t* hmap);
void free_hash_container(hash_map_t* hmap, int size);
void regrow(hash_map_t* hmap);
void insert(hash_map_t* hmap, hash_map_entry_t** container, unsigned int key);
int get_value(hash_map_t* hmap, unsigned int key);
void print_hash_map(hash_map_t* hmap);

static struct nf_hook_ops nfho;  //struct holding set of hook function options

/*
static map_t** map;
void insert_map(map_t** mp, int* size, int* itemc, unsigned int dstip, int set_count);
void dstlookup(unsigned int dstip);
int get_count(unsigned int dstip);
void free_hash();
*/

static hash_map_t* hmap;
static struct iphdr *ip_header;

static unsigned int packet_interceptor_hook(unsigned int hook, 
	struct sk_buff *pskb, 
	const struct net_device *indev, 
	const struct net_device *outdev, 
	int (*okfn)(struct sk_buff *))
{
	ip_header = (struct iphdr *)skb_network_header(pskb);
	insert(hmap, hmap->container, ip_header->daddr);
	
	//dstlookup(ip_header->daddr);
	printk(KERN_INFO "Receive-Interface: %s   ---   SRC-IP: %pI4   ---   DST-IP: %pI4   ---   Packet-Count: %d\n", indev->name, &ip_header->saddr, &ip_header->daddr, get_value(hmap, ip_header->daddr));  
   
	printk(KERN_INFO "Send-Interface: %s   ---   SRC-IP: %pI4   ---   DST-IP: %pI4   ---   Packet-Count: %d\n", outdev->name, &ip_header->saddr, &ip_header->daddr, get_value(hmap, ip_header->daddr));  
   

	printk(KERN_INFO "------------------------------------\n");

	return NF_ACCEPT;  //accepts the packet        
}

//Called when module loaded using 'insmod'
int init_module()
{
	/*
	array_size = 13;
	item_count = 0;
	map = vmalloc(sizeof(map_t*)*array_size);
  	*/

	hmap = kmalloc(sizeof(hash_map_t), GFP_KERNEL); 
    	hmap->map_size = INITIAL_SIZE;
    	hmap->entry_count = 0;
    	hmap->container = kmalloc(sizeof(hash_map_entry_t*) * INITIAL_SIZE, GFP_KERNEL);

	nfho.hook = packet_interceptor_hook;  //function to call when conditions below met
	nfho.hooknum = 0;  //called right after packet recieved, first hook in Netfilter
	nfho.pf = PF_INET;  //IPV4 packets
	nfho.priority = NF_IP_PRI_FIRST;  //set to highest priority over all other hook functions
	nf_register_hook(&nfho);  //register hook
	
	printk(KERN_INFO "Running on interface %s for %ds\n", iface, run_time);
	return 0;  //return 0 for successi
}

//Called when module unloaded using 'rmmod'
void cleanup_module()
{
	nf_unregister_hook(&nfho);  //cleanup – unregister hook
	//free_hash_map(hmap);
}

/*
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
*/


void free_hash_map(hash_map_t* hmap)
{
    int i;
    for(i = 0; i < hmap->map_size; ++i)
    {
	kfree(hmap->container[i]);
    }
    kfree(hmap);
}

void free_hash_container(hash_map_t* hmap, int size)
{
    int i;
    for(i = 0; i < size; ++i)
    {
	kfree(hmap->container[i]);
    }
}

void regrow(hash_map_t* hmap)
{
    float load = ((float)hmap->entry_count)/hmap->map_size;
    
    if(load > LOAD_FACTOR)
    {
	int old_size = hmap->map_size;
	hmap->map_size *= REGROW_FACTOR;
	hmap->entry_count = 0;
	hash_map_entry_t** new_container = kmalloc(sizeof(hash_map_entry_t*) * hmap->map_size, GFP_KERNEL);
	
	int i;
	for(i = 0; i < old_size; ++i)
	{
	    if(hmap->container[i])
	    {
		insert(hmap, new_container, hmap->container[i]->key);
	    }
	}
	
	free_hash_container(hmap, old_size);
	hmap->container = new_container;
    }
}

void insert(hash_map_t* hmap, hash_map_entry_t** container, unsigned int key)
{
    printk(KERN_INFO "map_size: %d     entry_count: %d     dst ip: %u\n", hmap->map_size, hmap->entry_count, key);
	
    int index = key % hmap->map_size;
    int old_index = index;
    hash_map_entry_t* hmentry = container[index];
       
    if(hmentry)
    {
	  while(hmentry && hmentry->key != key && index < hmap->map_size)
	  {
		++index;
		hmentry = container[index];
	  }
	  
	  if(hmentry)
	  {
	      if(hmentry->key == key)
	      {
		  hmentry->value++;
	      }
	      else
	      {
		  index = 0;
		  
		  while(hmentry && hmentry->key != key && index < old_index)
		  {
			++index;
			hmentry = container[index];
		  }
		
		  if(hmentry)
		  {
		      if(hmentry->key == key)
		      {
			  hmentry->value++;
		      }
		      else
		      {
			  hmentry = kmalloc(sizeof(hash_map_entry_t), GFP_KERNEL);
			  hmentry->key = key;
			  hmentry->value = 1;
			  container[index] = hmentry;
			  hmap->entry_count++;  
			  regrow(hmap);
		      }
		  }
		  else
		  {
		      hmentry = kmalloc(sizeof(hash_map_entry_t), GFP_KERNEL);
		      hmentry->key = key;
		      hmentry->value = 1;
		      container[index] = hmentry;
		      hmap->entry_count++;  
		      regrow(hmap);
		  }
	      } 
	  } 
	  else
	  {
	      hmentry = kmalloc(sizeof(hash_map_entry_t), GFP_KERNEL);
	      hmentry->key = key;
	      hmentry->value = 1;
	      container[index] = hmentry;
	      hmap->entry_count++; 
	      regrow(hmap);
	  }
    }
    else
    {
	hmentry = kmalloc(sizeof(hash_map_entry_t), GFP_KERNEL);
	hmentry->key = key;
	hmentry->value = 1;
	container[index] = hmentry;
	hmap->entry_count++; 
	regrow(hmap);
    }
}

int get_value(hash_map_t* hmap, unsigned int key)
{
    int index = key % hmap->map_size;
    int old_index = index;
    hash_map_entry_t* hmentry = hmap->container[index];
     
    if(hmentry)
    {
	  while(hmentry && hmentry->key != key && index < hmap->map_size)
	  {
		++index;
		hmentry = hmap->container[index];
	  }
	  
	  if(hmentry)
	  {
	      if(hmentry->key == key)
	      {
		  return hmentry->value;
	      }
	      else
	      {
		  index = 0;
		  
		  while(hmentry && hmentry->key != key && index < old_index)
		  {
			++index;
			hmentry = hmap->container[index];
		  }
		
		  if(hmentry)
		  {
		      if(hmentry->key == key)
		      {
			  return hmentry->value;
		      }
		  }
	      } 
	  } 
    }
    
    return -1;
}

void print_hash_map(hash_map_t* hmap)
{  
    int i;
    for(i = 0; i < hmap->map_size; ++i)
    {
	if(hmap->container[i])
	{
	    printk(KERN_INFO "key: %u          value: %d\n", hmap->container[i]->key, hmap->container[i]->value);
	}
    }
}








