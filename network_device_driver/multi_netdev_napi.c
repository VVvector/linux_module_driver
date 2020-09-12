#include <linux/device.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/platform_device.h>

#include <linux/tcp.h>
#include <linux/refcount.h>
#include <linux/of_net.h>

#define TEST_MAC_COUNT          2
#define TEST_NAPI_WEIGHT        64

struct test_mac {
    int id;
    struct test_eth *hw;
};

struct test_eth {
    struct device *dev;

    struct platform_device *pdev;
    struct platform_driver *drv;

    struct net_device dummy_dev;
    struct net_device *netdev[TEST_MAC_COUNT];
    struct test_mac *mac[TEST_MAC_COUNT];

    refcount_t dma_refcnt;

    struct napi_struct rx_napi;
};
static struct test_eth g_test_eth;

static int test_open(struct net_device *dev)
{
    struct test_mac *mac = netdev_priv(dev);
    struct test_eth *eth = mac->hw;

    dev_info(eth->dev, "just %s test.\n", __func__);

    /* we run 2 netdevs on the same dma ring so we only bring it up once */
    if (!refcount_read(&eth->dma_refcnt)) {
        napi_enable(&eth->rx_napi);
        refcount_set(&eth->dma_refcnt, 1);
    } else
        refcount_inc(&eth->dma_refcnt);

    netif_carrier_on(dev);
    netif_start_queue(dev);

    return 0;
}

static int test_stop(struct net_device *dev)
{
    struct test_mac *mac = netdev_priv(dev);
    struct test_eth *eth = mac->hw;

    dev_info(eth->dev, "just %s test.\n", __func__);

    if (netif_carrier_ok(dev))
        netif_carrier_off(dev);

    netif_tx_disable(dev);

    /* only shutdown DMA if this is the last user */
    if (!refcount_dec_and_test(&eth->dma_refcnt))
        return 0;

    napi_disable(&eth->rx_napi);

    return 0;
}


static int test_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
    struct test_mac *mac = netdev_priv(dev);
    struct test_eth *eth = mac->hw;

    dev_info(eth->dev, "just %s test.\n", __func__);
    return NETDEV_TX_OK;
}

static const struct net_device_ops test_netdev_ops = {
    .ndo_open       = test_open,
    .ndo_stop       = test_stop,
    .ndo_start_xmit = test_start_xmit,
};

static int add_netdev(struct test_eth *eth, unsigned char netdev_id)
{
    int ret = 0;
    struct net_device *netdev = NULL;
    struct test_mac *mac;

    dev_info(eth->dev, "just %s test.\n", __func__);
    if (netdev_id < 0 || netdev_id >= TEST_MAC_COUNT) {
        dev_err(eth->dev, "the netdev_id err.\n");
        ret = -1;
        goto err;
    }

    eth->netdev[netdev_id] = alloc_etherdev(sizeof(*mac));
    if (!eth->netdev[netdev_id]) {
        dev_err(eth->dev, "alloc_etherdev failed\n");
        return -ENOMEM;
    }

    netdev = eth->netdev[netdev_id];
    ret = dev_alloc_name(netdev, "vecnet%d");
    if (ret < 0) {
        dev_err(eth->dev, "Couldn't get name!\n");
        goto err;
    }

    mac = netdev_priv(eth->netdev[netdev_id]);
    eth->mac[netdev_id] = mac;
    mac->id = netdev_id;
    mac->hw = eth;

    SET_NETDEV_DEV(netdev, eth->dev);
    netdev->watchdog_timeo = 5 * HZ;
    netdev->netdev_ops = &test_netdev_ops;

    netdev->hw_features |= NETIF_F_GRO;
    netdev->features |= NETIF_F_GRO;

err:
    return ret;
}


static int test_poll_rx(struct napi_struct *napi, int budget, 
    struct test_eth *eth)
{
    struct sk_buff *skb ;
    int done = 0;
    struct net_device *netdev;
    int mac = 0;
    unsigned int len = 512;
    dev_info(eth->dev, "just %s test.\n", __func__);

    while (done < budget) {
        /* should receive skb from DMA*/
        //to do
        skb = napi_alloc_skb(napi, len);

        /* get NIC device id that the packet belong to. */
        if (unlikely(mac < 0 || mac >= TEST_MAC_COUNT ||
            !eth->netdev[mac]))
            goto err;

        netdev = eth->netdev[mac];
        skb->dev = netdev;

        /* send skb to network stack */
        napi_gro_receive(napi, skb);

        done++;
    }
err:
    return done;
}


static int test_napi_rx(struct napi_struct *napi, int budget)
{
    int remain_budget = budget;
    struct test_eth *eth = container_of(napi, struct test_eth, rx_napi);
    dev_info(eth->dev, "just rx napi test.\n");
    test_poll_rx(napi, remain_budget, eth);

    return 0;
}

static int test_probe(struct platform_device *pdev)
{
    int i = 0;
    struct test_eth *eth = &g_test_eth;

    dev_info(eth->dev, "just %s test.\n", __func__);
    eth->dev = &pdev->dev;

    /* register net devices */
    for (i = 0; i < TEST_MAC_COUNT; i++) {
        add_netdev(eth, i);
    }

    /* one mac but mulit net device, so we need a dummy device
    * for NAPI to work
    */
    init_dummy_netdev(&eth->dummy_dev);
    netif_napi_add(&eth->dummy_dev, &eth->rx_napi, test_napi_rx,
    TEST_NAPI_WEIGHT);

    platform_set_drvdata(pdev, eth);

    dev_info(eth->dev, "pdev probe done.\n");
    return 0;
}

static int test_free_dev(struct test_eth *eth)
{
    int i;

    for (i = 0; i < TEST_MAC_COUNT; i++) {
        if (!eth->netdev[i])
            continue;
        free_netdev(eth->netdev[i]);
    }

    return 0;
}

static int test_unreg_dev(struct test_eth *eth)
{
    int i;

    for (i = 0; i < TEST_MAC_COUNT; i++) {
        if (!eth->netdev[i])
            continue;
        unregister_netdev(eth->netdev[i]);
    }

    return 0;
}
static int test_cleanup(struct test_eth *eth)
{
    test_unreg_dev(eth);
    test_free_dev(eth);

    return 0;
}

static int test_remove(struct platform_device *pdev)
{
    struct test_eth *eth = platform_get_drvdata(pdev);
    int i;

    dev_info(eth->dev, "just %s test.\n", __func__);

    /* stop all devices to make sure that dma is properly shut down */
    for (i = 0; i < TEST_MAC_COUNT; i++) {
        if (!eth->netdev[i])
            continue;
        test_stop(eth->netdev[i]);
    }

    netif_napi_del(&eth->rx_napi);
    test_cleanup(eth);
    platform_set_drvdata(eth->pdev, NULL);

    return 0;
}

static struct platform_driver test_driver = {
    .probe      = test_probe,
    .remove     = test_remove,
    .driver     = {
        .owner      = THIS_MODULE,
        .name       = "test_dev",
    },
};

static int __init test_driver_init(void)
{
    memset(&g_test_eth, 0x00, sizeof(struct test_eth));
    g_test_eth.pdev = platform_device_alloc("test_dev", -1);
    platform_device_add(g_test_eth.pdev);

    g_test_eth.drv = &test_driver;
    platform_driver_register(g_test_eth.drv);

    return 0;
}

static void test_driver_exit(void)
{
    platform_driver_unregister(g_test_eth.drv);
    platform_device_unregister(g_test_eth.pdev);
}

module_init(test_driver_init);
module_exit(test_driver_exit);

MODULE_AUTHOR("1147059951@qq.com");
MODULE_LICENSE("Dual BSD/GPL");
