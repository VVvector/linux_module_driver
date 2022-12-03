# -*- coding:utf-8 -*-
import subprocess
import json
import argparse
import logging as log
import sys

import os
import signal
import subprocess
import platform
import time


def run_cmd(cmd_string, timeout=20):
    print("cmd：" + cmd_string)
    p = subprocess.Popen(cmd_string, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, shell=True, close_fds=True,
                         start_new_session=True)

    format = 'utf-8'
    if platform.system() == "Windows":
        format = 'gbk'

    try:
        (msg, errs) = p.communicate(timeout=timeout)
        ret_code = p.poll()
        if ret_code:
            code = 1
            msg = "[Error]Called Error ： " + str(msg.decode(format))
        else:
            code = 0
            msg = str(msg.decode(format))
    except subprocess.TimeoutExpired:
        # 注意：不能只使用p.kill和p.terminate，无法杀干净所有的子进程，需要使用os.killpg
        p.kill()
        p.terminate()
        os.killpg(p.pid, signal.SIGTERM)

        # 注意：如果开启下面这两行的话，会等到执行完成才报超时错误，但是可以输出执行结果
        # (outs, errs) = p.communicate()
        # print(outs.decode('utf-8'))

        code = 1
        msg = "[ERROR]Timeout Error : Command '" + cmd_string + "' timed out after " + str(timeout) + " seconds"
    except Exception as e:
        code = 1
        msg = "[ERROR]Unknown Error : " + str(e)

    return code, msg


class CLIENT:
    mac_addr = None
    ipv4_addr = None
    l4_proto = None
    port = None

    def __init__(self, ipv4_addr):
        self.ipv4_addr = ipv4_addr
        cmd = "arp {}".format(self.ipv4_addr)
        ret, msg = run_cmd(cmd)
        log.debug(msg)
        if ret:
            return

        lines = msg.splitlines()
        log.debug(lines)

        temp = lines[1].split()
        log.debug(temp)
        self.mac_addr = temp[2]

        log.info("client: {} - {}".format(self.mac_addr, self.ipv4_addr))

    def update_info(self, l4_proto, port):
        self.l4_proto = l4_proto
        self.port = port
        log.info("client: {}-{}-{}-{}".format(self.mac_addr, self.ipv4_addr, self.l4_proto, self.port))


class SERVER:
    l4_proto = None
    ipv4_addr = None
    port = None

    def update_info(self, ipv4_addr, l4_proto, port):
        self.ipv4_addr = ipv4_addr
        self.l4_proto = l4_proto
        self.port = port
        log.info("server: {}-{}-{}".format(self.ipv4_addr, self.l4_proto, self.port))


class DOWNSTREAM:
    name = None
    if_id = None
    mac_addr = None
    ipv4_addr = None

    def __init__(self, nic_name):
        self.name = nic_name

    # 获取指定downstream的interface id, mac addr, ipv4 addr
    def get_info(self):
        cmd = "ip addr show dev {}".format(self.name)
        ret, msg = run_cmd(cmd)
        log.debug(msg)
        if ret:
            return

        lines = msg.splitlines()
        log.debug(lines)

        # 获取interface id
        temp = lines[0].split(":")
        log.debug(temp)
        self.if_id = temp[0]

        # 获取mac address
        temp = lines[1].split()
        log.debug(temp)
        self.mac_addr = temp[1]

        # 获取ipv4 address
        temp = lines[3].split()
        log.debug(temp)
        temp = temp[1].split("/")
        self.ipv4_addr = temp[0]

        log.info("download: {}-{}-{}-{}".format(self.name, self.if_id, self.mac_addr, self.ipv4_addr))


class UPSTREAM:
    if_id = None
    ipv4_addr = None
    port = None

    def __init__(self, nic_name):
        self.name = nic_name

    # 获取指定downstream的interface id, mac addr, ipv4 addr
    def get_info(self):
        cmd = "ip addr show dev {}".format(self.name)
        ret, msg = run_cmd(cmd)
        log.debug(msg)
        if ret:
            return

        lines = msg.splitlines()
        log.debug(lines)

        # 获取interface id
        temp = lines[0].split(":")
        log.debug(temp)
        self.if_id = temp[0]

        # 获取ipv4 address
        temp = lines[3].split(" ")
        log.debug(temp)
        temp = lines[3].split(" ")
        temp = temp[5].split("/")
        self.ipv4_addr = temp[0]

        log.info("upstream: {}-{}-{}".format(self.name, self.if_id, self.ipv4_addr))


def set_nat_rule(client: CLIENT, upstream: UPSTREAM):
    cmd = "iptables -t nat -A POSTROUTING -o {} -s {}  -j SNAT --to {}".format(
        upstream.name, client.ipv4_addr, upstream.ipv4_addr)
    ret, msg = run_cmd(cmd)
    log.debug(msg)

    cmd = "iptables -t nat -vnL"
    ret, msg = run_cmd(cmd)
    log.info("nat rule: {}".format(msg))

    cmd = "echo 1 > /proc/sys/net/ipv4/ip_forward"
    run_cmd(cmd)
    cmd = "cat /proc/sys/net/ipv4/ip_forward"
    ret, msg = run_cmd(cmd)
    log.info("ipv4 forward status: {}".format(msg))


class TUPLE:
    proto = None
    src_ip = None
    dst_ip = None
    src_port = None
    dst_port = None


class CONNTRACK:
    conntrack_msg = None
    conntrack_tuples = []

    def __init__(self, monitor_interval, link_info, callback):
        self.link_info = link_info
        self.callback = callback
        self.monitor_interval = monitor_interval

    def dump_conntrack_info(self):
        cmd = "conntrack -L -s {}".format(self.link_info["client"].ipv4_addr)
        ret, msg = run_cmd(cmd)
        log.info("conntrack information: {}".format(msg))
        self.conntrack_msg = msg

    def filter_track_event(self, connection):
        if connection.find("ESTABLISHED") != -1 and connection.find(self.link_info["downstream"].ipv4_addr) == -1:
            return True

    def parse_established_conntrack_to_tuple(self):
        lines = self.conntrack_msg.splitlines()
        for line in lines:
            if not self.filter_track_event(line):
                continue

            temp = line.split()
            log.debug(temp)
            tuple = TUPLE()

            tuple.proto = temp[1]
            for info in temp:
                if info.find("src") != -1 and tuple.src_ip is None:
                    tuple.src_ip = info.split("=")[1]
                elif info.find("dst") != -1 and tuple.dst_ip is None:
                    tuple.dst_ip = info.split("=")[1]
                elif info.find("sport") != -1 and tuple.src_port is None:
                    tuple.src_port = info.split("=")[1]
                elif info.find("dport") != -1 and tuple.dst_port is None:
                    tuple.dst_port = info.split("=")[1]

            log.debug("tuple: {}-{}-{}-{}-{}".format(tuple.proto, tuple.src_ip, tuple.dst_ip, tuple.src_port,
                                                     tuple.dst_port))

            # 检查是否以及存在了
            tuple_is_exist = False
            for rule in self.conntrack_tuples:
                if rule.proto == tuple.proto and rule.src_ip == tuple.src_ip and rule.dst_ip == tuple.dst_ip and rule.src_port == tuple.src_port and rule.dst_port == tuple.dst_port:
                    tuple_is_exist = True

            if tuple_is_exist is not True:
                log.info(
                    "new tuple: {}-{}-{}-{}-{}".format(tuple.proto, tuple.src_ip, tuple.dst_ip, tuple.src_port,
                                                       tuple.dst_port))
                self.conntrack_tuples.append(tuple)
                self.callback(tuple)

    def monitor_conntrack(self):
        while True:
            self.dump_conntrack_info()
            self.parse_established_conntrack_to_tuple()

            time.sleep(self.monitor_interval)


link_info = dict()


def set_tc_tethering_offload_rule(tuple: TUPLE):
    log.info("add tethering offload rule")

    client = link_info["client"]
    server = link_info["server"]
    downstream = link_info["downstream"]
    upstream = link_info["upstream"]

    client.update_info(tuple.proto, tuple.src_port)
    server.update_info(tuple.dst_ip, tuple.proto, tuple.dst_port)

    upstream.port = server.port
    downstream.l3_addr = "0x0800"  # ipv4
    downstream.port = client.port

    cmd = "./tc_tethering_user -C {}-{}-{}-{} -S {}-{}-{} -U {}-{}-{} -D {}-{}-{}-{}-{}".format(client.mac_addr,
                                                                                                client.ipv4_addr,
                                                                                                client.l4_proto,
                                                                                                client.port,
                                                                                                server.ipv4_addr,
                                                                                                server.l4_proto,
                                                                                                server.port,
                                                                                                upstream.if_id,
                                                                                                upstream.ipv4_addr,
                                                                                                upstream.port,
                                                                                                downstream.if_id,
                                                                                                downstream.mac_addr,
                                                                                                downstream.l3_addr,
                                                                                                downstream.ipv4_addr,
                                                                                                downstream.port)

    log.info(cmd)
    ret, msg = run_cmd(cmd)
    log.info("setting tc tethering rule: ret={}, msg={}".format(ret, msg))


def load_tc_bpf(downstream: DOWNSTREAM, upstream: UPSTREAM):
    #load downstream tc ingress
    cmd = "tc qdisc show dev {}".format(downstream.name)
    run_cmd(cmd)

    cmd = "tc qdisc add dev {} clsact".format(downstream.name)
    run_cmd(cmd)

    cmd = "tc filter add dev {} ingress bpf da obj {} sec {}".format(downstream.name, "tc_tethering_kern.o",
                                                                     "sched_cls_tether_downstream4_ether")
    run_cmd(cmd)

    cmd = "tc qdisc show dev {} ingress".format(downstream.name)
    ret, msg = run_cmd(cmd)
    log.info("dev {} ingress: {}".format(downstream.name, msg))

    #load upstream tc ingress
    cmd = "tc qdisc show dev {}".format(upstream.name)
    run_cmd(cmd)

    cmd = "tc qdisc add dev {} clsact".format(upstream.name)
    run_cmd(cmd)

    cmd = "tc filter add dev {} ingress bpf da obj {} sec {}".format(upstream.name, "tc_tethering_kern.o",
                                                                     "sched_cls_tether_upstream4_rawip")
    run_cmd(cmd)

    cmd = "tc qdisc show dev {} ingress".format(upstream.name)
    ret, msg = run_cmd(cmd)
    log.info("dev {} ingress: {}".format(upstream.name, msg))

def main():
    parser = argparse.ArgumentParser(description="This is a example program")
    parser.add_argument('-d', '--downstream_nic_name', default=None, help='the downstream NIC name')
    parser.add_argument('-u', '--upstream_nic_name', default=None, help='the upstream NIC name')
    parser.add_argument('-c', '--client_ipv4_addr', default=None, help='the client ipv4 address')
    parser.add_argument('-R', '--recovery', action='store_true', help='clean the iptabels NAT setting')
    args = parser.parse_args()

    if args.recovery:
        cmd = "iptables -t nat -F"
        run_cmd(cmd)
        log.info("clean the iptables NAT rules")

        cmd = "iptables -t nat -vnL"
        ret, msg = run_cmd(cmd)
        log.info("nat rule: {}".format(msg))
        return

    if args.downstream_nic_name is None or args.upstream_nic_name is None or args.client_ipv4_addr is None:
        log.info("please input the downstream_nic_name, upstream_nic_name, client_ipv4_addr")
        return

    downstream = DOWNSTREAM(args.downstream_nic_name)
    downstream.get_info()

    upstream = UPSTREAM(args.upstream_nic_name)
    upstream.get_info()

    client = CLIENT(args.client_ipv4_addr)
    server = SERVER()

    load_tc_bpf(downstream, upstream)
    set_nat_rule(client, upstream)

    link_info["downstream"] = downstream
    link_info["upstream"] = upstream
    link_info["client"] = client
    link_info["server"] = server

    conntrack = CONNTRACK(2, link_info, set_tc_tethering_offload_rule)
    conntrack.monitor_conntrack()


if __name__ == '__main__':
    log.basicConfig(level=log.DEBUG,
                    format='%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s')
    main()
