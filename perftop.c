#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/hashtable.h>


#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <asm/uaccess.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("[Gaurang Karwande]");
MODULE_DESCRIPTION("LKP Project 3");

#define TBL_SIZE 10
#define FUNCTION_NAME_LENGTH 20




//module_param(int_str, charp, S_IRUSR | S_IRGRP | S_IROTH); //module parameters currently void

//MODULE_PARM_DESC(int_str, "A comma-separated list of integers"); //no module parameters at present

static struct kretprobe my_kretprobe;
static char probed_function_name[FUNCTION_NAME_LENGTH] = "pick_next_task_fair";

static DEFINE_HASHTABLE(pid_hash_table, TBL_SIZE);

struct pid_hash_entry { 		//pid_hash_table node
	unsigned int freq;
	unsigned int pid;
	struct hlist_node node;
};


static int pid_hash_store_value(unsigned int key)
{
	struct pid_hash_entry *new_entry;
	hash_for_each_possible(pid_hash_table, new_entry, node, key)
	{
		if (new_entry != NULL) 
		{
			new_entry->freq += 1;
			return 0;
		}
	}
	if ((new_entry = kmalloc(sizeof( *new_entry), GFP_ATOMIC)) == NULL) 
	{
		printk(KERN_INFO "No memory to add new hash table entry \n");
		return -ENOMEM;
	}
	new_entry->pid = key;
	new_entry->freq = 1;
	hash_add(pid_hash_table, &new_entry->node, key);
	return 0;
}

static void pid_hash_print_table(struct seq_file *m) 
{
	struct pid_hash_entry *current_entry;
	int bkt;
	seq_printf(m, "PID \t: Frequency \n"); 
	hash_for_each(pid_hash_table, bkt, current_entry, node) 
	{
	    seq_printf(m, "%u \t: %u, \n", current_entry->pid, current_entry->freq);	
	}
	seq_printf(m, "\n");
}

/*
static void destroy_hash_table_and_free(void)
{

	struct pid_hash_entry *current_entry;
       	struct hlist_node *tmp_node;
	int bkt;
	printk(KERN_INFO "Destroying Hash Table : ");
	hash_for_each_safe( pid_hash_table, bkt, tmp_node, current_entry, node) {
		printk(KERN_CONT " %d ", current_entry->pid);
		hash_del(&current_entry->node);
		kfree(current_entry);
	}
}
*/

//use kret_probe!

int ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs){
	int err;
	unsigned int pid;
	unsigned long current_task_struct_pointer = regs->ax;
	struct task_struct* curr_task = (struct task_struct*)current_task_struct_pointer;
	if (curr_task != NULL)
	{
		pid = (unsigned int)curr_task->pid;
		err = pid_hash_store_value(pid);
		if (err)
		{
			printk(KERN_INFO "Error in ret_handler \n");
			return err;
		}
	}
	return 0;
}

/*
void post_handler(struct kprobe *p, struct pt_regs *regs, unsigned long flags){
	
}
*/

static int  proj3 (struct seq_file *m, void *v)
{
	//seq_printf(m, "Hello World \n");
	//seq_printf(m, "Counter: %d \n", counter);
	pid_hash_print_table(m);

	return 0;
}

static int  perftop_open(struct inode *inode, struct file *file)
{
	return single_open(file, proj3, NULL);
}

static const struct proc_ops perftop_ops = {
	.proc_open = perftop_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static int __init perftop_init(void)
{
	int ret;
	my_kretprobe.handler = ret_handler;
	my_kretprobe.kp.symbol_name = probed_function_name;
	ret = register_kretprobe(&my_kretprobe);
	if (ret < 0) {
		printk(KERN_INFO "register_kretprobe failed, returned %d\n", ret);
		return -1;
	}
	printk(KERN_INFO "Planted return probe at %s: %p\n", my_kretprobe.kp.symbol_name, my_kretprobe.kp.addr);

	proc_create("perftop", 0, NULL, &perftop_ops);
	return 0;
}


static void __exit perftop_exit(void)
{
	unregister_kretprobe(&my_kretprobe);
	remove_proc_entry("perftop", NULL);
	return;
}

module_init(perftop_init);
module_exit(perftop_exit);
