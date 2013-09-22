#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netdevice.h>

static struct nf_hook_ops nfho;  //struct holding set of hook function options

//function to be called by hook
unsigned int hook_func(unsigned int hooknum, struct sk_buff **skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
  printk(KERN_INFO "packet received from interface - %s\n", in->name);  //log to var/log/messages
  printk(KERN_INFO "packet sent from interface - %s\n", out->name);  
  return NF_ACCEPT;  //accepts the packet        
}

//Called when module loaded using 'insmod'
int init_module()
{
  nfho.hook = hook_func;  //function to call when conditions below met
  nfho.hooknum = 0;  //called right after packet recieved, first hook in Netfilter
  nfho.pf = PF_INET;  //IPV4 packets
  nfho.priority = NF_IP_PRI_FIRST;  //set to highest priority over all other hook functions
  nf_register_hook(&nfho);  //register hook
  return 0;  //return 0 for success
}

//Called when module unloaded using 'rmmod'
void cleanup_module()
{
  nf_unregister_hook(&nfho);  //cleanup – unregister hook
}
