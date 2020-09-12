/*
 *  linux/drivers/char/ttyprintk.c
 *
 *  Copyright (C) 2010  Samo Pogacnik
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the smems of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 */

/*
 * This pseudo device allows user to make printk messages. It is possible
 * to store "console" messages inline with kernel messages for better analyses
 * of the boot process, for example.
 */

#include <linux/device.h>
#include <linux/serial.h>
#include <linux/tty.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/tty_flip.h>
#include <linux/delay.h>



#define PORT_NR 3

struct ttytest_port {
	struct device *dev[PORT_NR];
	struct tty_port *port[PORT_NR];
	struct mutex port_write_mutex;

	unsigned char test_buf[1024];
	unsigned int count;
	unsigned char cur_port_id;
	unsigned char w_r_flag;
};
static struct ttytest_port tst_port;



void show_termios(struct ktermios *termios)
{
	printk("termios: c_iflag:0x%08x; c_oflag:0x%08x; c_cflag:0x%08x; c_lflag:0x%08x\n",
			termios->c_iflag, termios->c_oflag, termios->c_cflag, termios->c_lflag);
}

/*
 * TTY operations open function.
 */
static int tst_open(struct tty_struct *tty, struct file *filp)
{
	int port_id = tty->index;
	dev_t dev_num = 0;
	struct tty_driver *pdrv = tty->driver;
	tst_port.cur_port_id = port_id;	

	printk("tst open\n");

	dev_num = tty_devnum(tty);
	
	printk("show driver termios:\n");
	show_termios(&pdrv->init_termios);
	
	printk("show tty port termios:\n");
	show_termios(&tty->termios);

	tty->driver_data = tst_port.port[port_id];
	return tty_port_open(tst_port.port[port_id], tty, filp);
}

/*
 * TTY operations close function.
 */
static void tst_close(struct tty_struct *tty, struct file *filp)
{
	struct tty_port *pport = tty->driver_data;
	printk("tst close\n");
	tty_port_close(pport, tty, filp);
}

/*
 * TTY operations read function.
 */
static void tst_read(struct tty_port *tty_port, unsigned char *buf, int count)
{
	printk("tst read func. count:%d \n", count);
	tty_insert_flip_string(tty_port, buf, count);
	tty_flip_buffer_push(tty_port);
}


static void show_buff_hex(unsigned char *buf, int count)
{
	unsigned int i = 0, j = 0;
	unsigned int base = count / 8;
	unsigned int tail = count % 8;
	unsigned char tmp_buf[8] = {0};

	for (i = 0; i < base; i++) {
		printk("0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x\n",
			buf[i], buf[i+1], buf[i+2], buf[i+3], buf[i+4], buf[i+5], buf[i+6], buf[i+7]);
		i *= 8;
	}

	for (j = 0; j < tail; j++) {
		tmp_buf[j] = buf[i + j];
	}

	printk("0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x\n",
		tmp_buf[0], tmp_buf[1], tmp_buf[2], tmp_buf[3], tmp_buf[4], tmp_buf[5], tmp_buf[6], tmp_buf[7]);
}


/*
 * TTY operations write function.
 */
static int tst_write(struct tty_struct *tty,
		const unsigned char *buf, int count)
{
	struct tty_port *pport = tty->driver_data;
	unsigned char *tmp_buf = (unsigned char *)buf;

	printk("tty_write: count[%d]- %s\n", count, buf);
	
	printk("show tty port termios:\n");	
	show_termios(&tty->termios);

	printk("show write buffer::\n");	
	show_buff_hex(tmp_buf, count);

	dump_stack();

#if 1
	if (tst_port.w_r_flag == 1) {
		printk("start tst_read\n");
		tst_port.w_r_flag = 0;
		tst_read(pport, tmp_buf, count);
	
		msleep(20 * 1000);
	}

#else
	if (tst_port.w_r_flag == 1) {
		printk("start tst_read\n");
		tst_port.w_r_flag = 0;
		tst_read(pport, tst_port.test_buf, tst_port.count);
	
		msleep(20 * 1000);
	}
#endif
	return count;
}

/*
 * TTY operations ioctl function.
 */
static int tst_ioctl(struct tty_struct *tty,
			unsigned int cmd, unsigned long arg)
{
	struct tst_port *tstp = tty->driver_data;

	if (!tstp)
		return -EINVAL;

	switch (cmd) {
	/* Stop TIOCCONS */
	case TIOCCONS:
		return -EOPNOTSUPP;
	default:
		return -ENOIOCTLCMD;
	}
	return 0;
}

static const struct tty_operations tst_ops = {
	.open = tst_open,
	.close = tst_close,
	.write = tst_write,
	.ioctl = tst_ioctl,
};

static const struct tty_port_operations null_ops = { };

static struct tty_driver *tst_driver;

static ssize_t show_my_device(struct device *dev,
                  struct device_attribute *attr, char *buf)
{
	printk("show\n");
    return 0;
}

static ssize_t store_my_device(struct device *dev,
                 struct device_attribute *attr,
                 const char *buf, size_t len)
{
	static int seq = 0;
	int ret = 0;
	char data[10] = {0};
	struct tty_buffer *tb;

	struct tty_ldisc *disc;
	struct tty_struct *tty;
	struct tty_struct *itty;
	struct tty_struct *ld_tty;
		
	struct tty_port *tty_port =  tst_port.port[tst_port.cur_port_id];
	
	tb = tty_port->buf.head;
	printk("head: used:%d, size:%d, commit:%d, read:%d\n", tb->used, tb->size,
			tb->commit, tb->read);
	
	tb = tty_port->buf.tail;
	printk("tail: used:%d, size:%d, commit:%d, read:%d\n", tb->used, tb->size,
			tb->commit, tb->read);

	tty = tty_port->tty;
	itty = tty_port->itty;
	if (!tty || !itty) {
		printk("tty, itty error, tty %p, itty %p\n", tty, itty);
		printk("hex: tty, itty error, tty %lx, itty %lx\n", tty, itty);
		goto err;
	}

	disc = itty->ldisc;
	if (!disc) {
		printk("disc error\n");
		goto err;
	}

	ld_tty = disc->tty;
	if (!ld_tty) {
		printk("ld_tty error\n");
		goto err;
	}

//   printk("ldata: read_head %d, \n", ldata->read_head);

	printk("store, set w_r_flag = 1\n");
	tst_port.w_r_flag = 1;
	//tst_read(tty_port, tst_port.test_buf, tst_port.count);
	
	/* write data*/
	snprintf(data, sizeof(data), "hello-%d\n", seq++);
	printk("data: %s", data);
	ret = tty_insert_flip_string(tty_port, data, strlen(data)+1);
	printk("tty_intsert_flip_string: ret=%d\n", ret);

	printk("used:%d, size:%d, commit:%d, read:%d\n", tb->used, tb->size,
			tb->commit, tb->read);

	tty_flip_buffer_push(tty_port);

err:
	return len;
}
static DEVICE_ATTR(my_device_test, S_IWUSR|S_IRUSR, show_my_device, store_my_device);
static struct attribute *tst_dev_attrs[] = {
	&dev_attr_my_device_test.attr,
	NULL
};
static const struct attribute_group tst_attr_grp = {
       .attrs = tst_dev_attrs,
};


static int __init tst_init(void)
{
	
	char *port_name[PORT_NR] = {"ttyz1", "ttyz2", "ttyz3"};
	int ret = -ENOMEM;
	int i = 0;
	struct tty_port *pport = NULL;
	struct device *pdev = NULL;
	printk("tty test driver init1\n");
	mutex_init(&tst_port.port_write_mutex);

	/*alloc tty driver*/
	tst_driver = alloc_tty_driver(PORT_NR);
	if (IS_ERR(tst_driver))
		return PTR_ERR(tst_driver);

	/*init tty driver*/
	tst_driver->driver_name = "tst";
	tst_driver->name = "tst";
	tst_driver->major = 0;
	tst_driver->minor_start = 0;
	tst_driver->subtype = SERIAL_TYPE_NORMAL;
	//tst_driver->flags = TTY_DRIVER_RESET_TERMIOS | TTY_DRIVER_REAL_RAW | TTY_DRIVER_DYNAMIC_DEV | TTY_DRIVER_UNNUMBERED_NODE;
	tst_driver->flags = TTY_DRIVER_REAL_RAW | TTY_DRIVER_DYNAMIC_DEV | TTY_DRIVER_UNNUMBERED_NODE;
	tst_driver->init_termios = tty_std_termios;
	tst_driver->init_termios.c_oflag = OPOST | OCRNL | ONOCR | ONLRET;
	tst_driver->init_termios.c_lflag = 0;
	tty_set_operations(tst_driver, &tst_ops);


	/*register tty driver*/
	ret = tty_register_driver(tst_driver);
	if (ret < 0) {
		printk(KERN_ERR "Couldn't register tst driver\n");
		goto error;
	}

	/*init tty port and device*/
	for (i = 0; i < PORT_NR; i++) {
		tst_driver->name = port_name[i];
		pport = kzalloc(sizeof(struct tty_port), GFP_KERNEL);
		tty_port_init(pport);
		pport->ops = &null_ops;
		pdev = tty_port_register_device(pport, tst_driver ,i, NULL);
		if (IS_ERR(pdev)) {
			ret = PTR_ERR(pdev);
			printk("could not register tty (ret=%i)\n", ret);
		}
		tst_port.port[i] = pport;
		tst_port.dev[i] = pdev;
	}

	/*init device attr*/
	for (i = 0; i < PORT_NR; i++) {
		pdev = tst_port.dev[i];
		ret = sysfs_create_group(&pdev->kobj, &tst_attr_grp);
	}
	
	tst_port.count = 500;
	memset(tst_port.test_buf, 0x00, sizeof(tst_port.test_buf));
	for(i = 0; i < tst_port.count; i++) {
		tst_port.test_buf[i] = i;	
	}
	
	printk("tty driver major:%d\n", tst_driver->major);
	show_termios(&tst_driver->init_termios);
	return 0;

error:
	put_tty_driver(tst_driver);
	for (i = 0; i < PORT_NR; i++) {
		tty_port_destroy(tst_port.port[i]);
	}
	return ret;
}

static void __exit tst_exit(void)
{
	int i = 0;

	for (i = 0; i < PORT_NR; i++) {
		tty_port_unregister_device(tst_port.port[i], tst_driver, i);
		tty_port_destroy(tst_port.port[i]);
	}

	tty_unregister_driver(tst_driver);
	put_tty_driver(tst_driver);
}

device_initcall(tst_init);
module_exit(tst_exit);

MODULE_AUTHOR("Intel");
MODULE_DESCRIPTION("IFX6x60 spi driver");
MODULE_LICENSE("GPL");
MODULE_INFO(Version, "0.1-IFX6x60");

