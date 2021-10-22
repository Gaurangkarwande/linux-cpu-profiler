#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/hashtable.h>
#include <linux/stacktrace.h>
#include <linux/jhash.h>
#include <linux/kallsyms.h>
#include <linux/spinlock.h>
#include <linux/jhash.h>
#include <linux/ktime.h>
#include <linux/rbtree.h>

#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <asm/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("[Gaurang Karwande]");
MODULE_DESCRIPTION("LKP Project 3");

#define TBL_SIZE 10
#define FUNCTION_NAME_LENGTH 20
#define MAX_TRACE_SIZE 51
#define NUM_TASKS 20

extern unsigned int stack_trace_save_user(unsigned long *store, unsigned int size);
#define stack_trace_save_user (*(typeof(&stack_trace_save_user))kallsyms_stack_trace_save_user)
void *kallsyms_stack_trace_save_user = NULL;

extern unsigned long kallsyms_lookup_name(const char *name);
#define kallsyms_lookup_name (*(typeof((&kallsyms_lookup_name)))my_kallsyms_lookup_name)
void *my_kallsyms_lookup_name = NULL;

static struct kretprobe my_kretprobe;
static struct kprobe kp_lookup = {
	.symbol_name = "kallsyms_lookup_name"};

unsigned long stack_trace_log[MAX_TRACE_SIZE];
static char probed_function_name[FUNCTION_NAME_LENGTH] = "pick_next_task_fair";

static DEFINE_HASHTABLE(trace_hash_table, TBL_SIZE);
static struct rb_root trace_rbtree = RB_ROOT;
static DEFINE_SPINLOCK(trace_hash_table_lock);

static DEFINE_HASHTABLE(entry_stamp_hash_table, TBL_SIZE);

struct trace_hash_entry
{ //trace_hash_table node
	unsigned int freq;
	unsigned int pid;
	unsigned long stack_log[MAX_TRACE_SIZE];
	unsigned int stack_log_length;
	u64 task_duration;
	struct hlist_node node;
};

struct trace_rbtree_entry
{
	unsigned int key;
	unsigned int freq;
	unsigned int pid;
	unsigned long stack_log[MAX_TRACE_SIZE];
	unsigned int stack_log_length;
	u64 task_duration;
	struct rb_node node;
};

struct entry_stamp_hash_entry
{
	u64 entry_time_stamp;
	struct hlist_node node;
};

static bool delete_prev_rbtree_entry(unsigned int key, u64 *task_duration, unsigned int *freq)
{
	struct rb_node *node;
	struct trace_rbtree_entry *current_entry;
	for (node = rb_first(&trace_rbtree); node; node = rb_next(node))
	{
		current_entry = rb_entry(node, struct trace_rbtree_entry, node);
		if (current_entry->key == key)
		{
			*task_duration = current_entry->task_duration;
			*freq = current_entry->freq;
			rb_erase(&current_entry->node, &trace_rbtree);
			kfree(current_entry);
			return true;
		}
	}
	*task_duration = 0;
	*freq = 0;
	return false;
}

static int trace_rbtree_store_value(unsigned int key, unsigned int pid, unsigned long *stack_log, unsigned int stack_lenght, u64 task_duration)
{
	int i = 0;
	u64 prev_task_duration = 0;
	unsigned prev_freq = 0;
	struct trace_rbtree_entry *new_entry, *current_entry;
	struct rb_node **link = &trace_rbtree.rb_node, *parent;
	delete_prev_rbtree_entry(key, &prev_task_duration, &prev_freq);
	if ((new_entry = kmalloc(sizeof(*new_entry), GFP_ATOMIC)) == NULL)
	{
		return -ENOMEM;
	}
	new_entry->key = key;
	new_entry->pid = pid;
	new_entry->stack_log_length = stack_lenght;
	new_entry->freq = prev_freq + 1;
	new_entry->task_duration = prev_task_duration + task_duration;
	for (i = 0; i < stack_lenght && stack_lenght <= MAX_TRACE_SIZE; i++)
	{
		new_entry->stack_log[i] = stack_log[i];
	}
	while (*link)
	{
		parent = *link;
		current_entry = rb_entry(parent, struct trace_rbtree_entry, node);
		if (current_entry->task_duration < new_entry->task_duration)
			link = &(*link)->rb_left;
		else
			link = &(*link)->rb_right;
	}
	rb_link_node(&new_entry->node, parent, link);
	rb_insert_color(&new_entry->node, &trace_rbtree);
	return 0;
}

static void trace_rbtree_print_value(struct seq_file *m, int max_count)
{
	int i = 0, j;
	struct rb_node *node;
	struct trace_rbtree_entry *current_entry;
	for (node = rb_first(&trace_rbtree); node && i <= max_count; node = rb_next(node))
	{
		seq_printf(m, "Rank : %d \n", i);
		current_entry = rb_entry(node, struct trace_rbtree_entry, node);
		seq_printf(m, "PID : %u \t Frequency : %u \t CPU Cycles: %lld \t Jenkins Hash: %u  \n", current_entry->pid, current_entry->freq, current_entry->task_duration, current_entry->key);
		seq_printf(m, "Stack Trace : \n");
		if (current_entry->stack_log_length == 0)
		{
			seq_printf(m, "No Stack Trace.\n");
		}
		for (j = 0; j < 4; j++)
		{
			seq_printf(m, "%pS\n", (void *)current_entry->stack_log[j]);
		}
		i++;
		seq_printf(m, "\n");
	}
}

static int save_entry_time_stamp(unsigned int key, u64 entry_time_stamp)
{
	struct entry_stamp_hash_entry *new_entry;
	hash_for_each_possible(entry_stamp_hash_table, new_entry, node, key)
	{
		if (new_entry != NULL)
		{
			new_entry->entry_time_stamp = entry_time_stamp;
			return 0;
		}
	}
	if ((new_entry = kmalloc(sizeof(*new_entry), GFP_ATOMIC)) == NULL)
	{
		printk(KERN_INFO "No memory to add new entry stamp hash table entry \n");
		return -ENOMEM;
	}
	new_entry->entry_time_stamp = entry_time_stamp;
	hash_add(entry_stamp_hash_table, &new_entry->node, key);
	return 0;
}

static u64 get_entry_time_stamp(unsigned int key)
{
	struct entry_stamp_hash_entry *current_entry;
	struct hlist_node *tmp_node;
	u64 entry_time_stamp = 0;
	printk(KERN_INFO "inside get entry time \n");
	hash_for_each_possible_safe(entry_stamp_hash_table, current_entry, tmp_node, node, key)
	{
		if (current_entry != NULL)
		{
			entry_time_stamp = current_entry->entry_time_stamp;
			hash_del(&current_entry->node);
			kfree(current_entry);
		}
	}
	return entry_time_stamp;
}

static int trace_hash_store_value(unsigned int key, unsigned int pid, unsigned long *stack_log, unsigned int stack_lenght, u64 task_duration)
{
	int i;
	struct trace_hash_entry *new_entry;
	hash_for_each_possible(trace_hash_table, new_entry, node, key)
	{
		if (new_entry != NULL)
		{
			new_entry->freq += 1;
			new_entry->task_duration += task_duration;
			return 0;
		}
	}
	if ((new_entry = kmalloc(sizeof(*new_entry), GFP_ATOMIC)) == NULL)
	{
		printk(KERN_INFO "No memory to add new hash table entry \n");
		return -ENOMEM;
	}
	new_entry->pid = pid;
	new_entry->stack_log_length = stack_lenght;
	new_entry->freq = 1;
	new_entry->task_duration = task_duration;
	for (i = 0; i < stack_lenght && stack_lenght <= MAX_TRACE_SIZE; i++)
	{
		new_entry->stack_log[i] = stack_log[i];
	}
	hash_add(trace_hash_table, &new_entry->node, key);
	return 0;
}

static void trace_hash_print_table(struct seq_file *m)
{
	struct trace_hash_entry *current_entry;
	int bkt, i;
	hash_for_each(trace_hash_table, bkt, current_entry, node)
	{
		seq_printf(m, "PID : %u \t Frequency : %u \t CPU Cycles: %lld  \n", current_entry->pid, current_entry->freq, current_entry->task_duration);
		seq_printf(m, "Stack Trace : \n");
		if (current_entry->stack_log_length == 0)
		{
			seq_printf(m, "No Stack Trace.\n");
		}
		for (i = 0; i < current_entry->stack_log_length; i++)
		{
			seq_printf(m, "%p\n", (void *)current_entry->stack_log[i]);
		}
	}
	seq_printf(m, "\n");
}

static bool time_flag = false;

static int entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int err;
	unsigned long flags;
	unsigned int pid, stack_log_length;
	u32 stack_trace_hash_key;
	u64 task_duration = 0;
	unsigned long current_task_struct_pointer = regs->si;
	struct task_struct *curr_task = (struct task_struct *)current_task_struct_pointer;
	spin_lock_irqsave(&trace_hash_table_lock, flags);
	if (curr_task != NULL)
	{
		pid = (unsigned int)curr_task->pid;
		if (curr_task->mm == NULL)
		{
			stack_log_length = stack_trace_save(&(*stack_trace_log), MAX_TRACE_SIZE, 6);
		}
		else
		{
			spin_unlock_irqrestore(&trace_hash_table_lock, flags);
			return 0;
		}
		stack_trace_hash_key = jhash2((u32 *)stack_trace_log, stack_log_length * 2, 0);
		if (time_flag)
		{
			task_duration = rdtsc() - get_entry_time_stamp(pid);
		}
		err = trace_hash_store_value(stack_trace_hash_key, pid, stack_trace_log, stack_log_length, task_duration);
		err = trace_rbtree_store_value(stack_trace_hash_key, pid, stack_trace_log, stack_log_length, task_duration);
		if (err)
		{
			printk(KERN_INFO "Error in entry_handler \n");
			return err;
		}
	}
	spin_unlock_irqrestore(&trace_hash_table_lock, flags);
	return 0;
}

int ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	unsigned long flags;

	int err;
	unsigned int pid;
	unsigned long current_task_struct_pointer = regs->ax;
	struct task_struct *curr_task = (struct task_struct *)current_task_struct_pointer;
	spin_lock_irqsave(&trace_hash_table_lock, flags);
	if (curr_task != NULL)
	{
		if (curr_task->mm != NULL)
		{
			spin_unlock_irqrestore(&trace_hash_table_lock, flags);
			return 0;
		}
		pid = (unsigned int)curr_task->pid;
		err = save_entry_time_stamp(pid, rdtsc());
		if (err)
		{
			printk(KERN_INFO "Error in ret_handler \n");
			return err;
		}
		time_flag = true;
	}
	spin_unlock_irqrestore(&trace_hash_table_lock, flags);
	return 0;
}

static int proj3(struct seq_file *m, void *v)
{
	unsigned long flags;
	spin_lock_irqsave(&trace_hash_table_lock, flags);
	//trace_hash_print_table(m);
	trace_rbtree_print_value(m, 20);
	spin_unlock_irqrestore(&trace_hash_table_lock, flags);
	return 0;
}

static int perftop_open(struct inode *inode, struct file *file)
{
	return single_open(file, proj3, NULL);
}

static const struct proc_ops perftop_ops = {
	.proc_open = perftop_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static int get_access_to_kallsyms(void)
{
	int lookup_ret;
	lookup_ret = register_kprobe(&kp_lookup);
	if (lookup_ret < 0)
	{
		printk(KERN_INFO "probing kallsyms_lookup_name failed, returned %d\n", lookup_ret);
		return -1;
	}
	my_kallsyms_lookup_name = kp_lookup.addr;
	unregister_kprobe(&kp_lookup);
	return 0;
}

static int __init perftop_init(void)
{

	int ret;
	int lookup_ret = get_access_to_kallsyms();
	if (lookup_ret < 0)
	{
		printk(KERN_INFO "Getting access to kallsyms failed\n");
		return -1;
	}
	pr_alert("We are in perftop init \n");
	kallsyms_stack_trace_save_user = (void *)kallsyms_lookup_name("stack_trace_save_user");
	my_kretprobe.entry_handler = entry_handler;
	my_kretprobe.handler = ret_handler;
	my_kretprobe.kp.symbol_name = probed_function_name;
	ret = register_kretprobe(&my_kretprobe);
	if (ret < 0)
	{
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
