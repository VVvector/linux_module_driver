#include <linux/device.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/kthread.h>

#define KMALLOC_SIZE (1024 * 4)
#define VMALLOC_SIZE (1024 * 40)

struct simple_data_info {
	struct task_struct *pth;
	unsigned char *k_data;
	unsigned char *v_data;
};

struct simple_data_info simple_data;
 

#define assert() BUG()


static int kthread_func(void *para)
{
	int ret = 0;
	int i = 0;
	while (!kthread_should_stop()) {
		i++;
		if (need_resched())
			cond_resched();
	}

	return ret;
}

static int simple_init(void)
{
	int ret = 0;
	simple_data.pth = kthread_run(kthread_func, NULL, "my_kthread%d", 1);
	if (IS_ERR(simple_data.pth)) {
		ret = -1;
		printk(KERN_ERR "kthread creat fail!");
		goto err;
	}

	
	simple_data.k_data = kmalloc(KMALLOC_SIZE, GFP_KERNEL);
	if (simple_data.k_data == NULL)
		printk(KERN_ERR "kmallock memory fail!");
	memset(simple_data.k_data, 0x5a, KMALLOC_SIZE);

	simple_data.v_data = vmalloc(VMALLOC_SIZE);
	if (simple_data.v_data == NULL)
		printk(KERN_ERR "vmalloc memory fail");
	memset(simple_data.v_data, 0x5a, VMALLOC_SIZE);

	
	printk(KERN_ERR "simple_dat:0x%llx", (u64)&simple_data);
	printk(KERN_ERR "k_data:0x%llx, v_data:0x%llx", (u64)simple_data.k_data, (u64)simple_data.v_data);

//	assert();

err:
	return ret;
}

static void simple_exit(void)
{
	int ret = 0;
	ret = kthread_stop(simple_data.pth);
	if (ret)
		printk(KERN_ERR "kthread stop fail!");
}

module_init(simple_init);
module_exit(simple_exit);
MODULE_LICENSE("GPL");

