# -*- coding:utf-8 -*-
import argparse
import logging as log
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
    l4_port = None

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

    def update_info(self, l4_proto, l4_port):
        self.l4_proto = l4_proto
        self.l4_port = l4_port
        log.info("client: {}-{}-{}-{}".format(self.mac_addr, self.ipv4_addr, self.l4_proto, self.l4_port))


class SERVER:
    l4_proto = None
    l4_port = None
    ipv4_addr = None


    def update_info(self, ipv4_addr, l4_proto, l4_port):
        self.ipv4_addr = ipv4_addr
        self.l4_proto = l4_proto
        self.l4_port = l4_port
        log.info("server: {}-{}-{}".format(self.ipv4_addr, self.l4_proto, self.l4_port))


class DOWNSTREAM:
    name = None
    if_id = None
    mac_addr = None
    l3_proto = "0x0800"  # ipv4
    ipv4_addr = None
    l4_port = None


    def __init__(self, nic_name):
        self.name = nic_name

        # 获取指定downstream的interface id, mac addr, ipv4 addr
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

    def update_info(self, l4_port):
        self.l4_port = l4_port
        log.info("download: {}-{}-{}-{}".format(self.name, self.if_id, self.mac_addr, self.l3_proto, self.ipv4_addr, self.l4_port))


class UPSTREAM:
    if_id = None
    ipv4_addr = None
    l4_port = None

    def __init__(self, nic_name):
        self.name = nic_name

        # 获取指定downstream的interface id, mac addr, ipv4 addr
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

    def update_info(self, l4_port):
        self.l4_port = l4_port
        log.info("upstream: {}-{}-{}-{}".format(self.name, self.if_id, self.ipv4_addr, self.l4_port))


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


######### conntrack monitor ########################
class TUPLE:
    proto_num = None
    src_ip = None
    dst_ip = None
    src_port = None
    dst_port = None


def check_tuple_equle(src: TUPLE, dst: TUPLE):
    if (src.proto_num == dst.proto_num and src.src_ip == dst.src_ip and src.dst_ip == dst.dst_ip and
            src.src_port == dst.src_port and src.dst_port == dst.dst_port):
        return True


class CONNTRACKMESSAGE:
    # Original direction conntrack tuple.
    tuple_orig = TUPLE()
    # Reply direction conntrack tuple.
    tuple_reply = TUPLE()

    def __init__(self, conntrack_msg):
        self.msg = conntrack_msg

    def parse_conntrack_msg(self):
        temp = self.msg.split()
        log.debug(temp)

        self.tuple_orig.proto_num = temp[1]
        self.tuple_reply.proto_num = temp[1]
        for info in temp:
            if info.find("src") != -1:
                if self.tuple_orig.src_ip is None:
                    self.tuple_orig.src_ip = info.split("=")[1]
                else:
                    self.tuple_reply.src_ip = info.split("=")[1]
            elif info.find("dst") != -1:
                if self.tuple_orig.dst_ip is None:
                    self.tuple_orig.dst_ip = info.split("=")[1]
                else:
                    self.tuple_reply.dst_ip = info.split("=")[1]
            elif info.find("sport") != -1:
                if self.tuple_orig.src_port is None:
                    self.tuple_orig.src_port = info.split("=")[1]
                else:
                    self.tuple_reply.src_port = info.split("=")[1]
            elif info.find("dport") != -1:
                if self.tuple_orig.dst_port is None:
                    self.tuple_orig.dst_port = info.split("=")[1]
                else:
                    self.tuple_reply.dst_port = info.split("=")[1]

            log.debug("original tuple: {}-{}-{}-{}-{}".format(self.tuple_orig.proto_num, self.tuple_orig.src_ip,
                                                              self.tuple_orig.dst_ip, self.tuple_orig.src_port,
                                                              self.tuple_orig.dst_port))
            log.debug("reply tuple: {}-{}-{}-{}-{}".format(self.tuple_reply.proto_num, self.tuple_reply.src_ip,
                                                           self.tuple_reply.dst_ip, self.tuple_reply.src_port,
                                                           self.tuple_reply.dst_port))


class CONNTRACKMONITOR:
    conntrack_message_list = []

    def __init__(self, monitor_interval, link_info, callback):
        self.callback = callback
        self.monitor_interval = monitor_interval
        # Source address from original direction
        self.orig_src = link_info["client"].ipv4_addr
        # Destination address from original direction
        self.orig_dst = link_info["downstream"].ipv4_addr

    def dump_conntrack_msgs(self):
        cmd = "conntrack -L -s {}".format(self.orig_src)
        ret, msg = run_cmd(cmd)
        log.debug("conntrack information: {}".format(msg))
        self.conntrack_msg = msg

    def need_offload_conntrack_event(self, msg):
        if msg.find("ESTABLISHED") != -1 and msg.find(self.orig_dst) == -1:
            return True

    def check_contrack_msg_is_exist(self, conntrack_msg: CONNTRACKMESSAGE):
        is_exist = False
        for item in self.conntrack_message_list:
            if check_tuple_equle(conntrack_msg.tuple_orig, item.tuple_orig) and \
                    check_tuple_equle(conntrack_msg.tuple_reply, item.tuple_reply):
                is_exist = True
                break

        return is_exist

    def parse_conntrack_msgs(self):
        msgs = self.conntrack_msg.splitlines()
        for msg in msgs:
            if not self.need_offload_conntrack_event(msg):
                continue

            conntrack_msg = CONNTRACKMESSAGE(msg)
            conntrack_msg.parse_conntrack_msg()
            if self.check_contrack_msg_is_exist(conntrack_msg) is not True:
                log.info("original tuple: {}-{}-{}-{}-{}".format(conntrack_msg.tuple_orig.proto_num,
                                                                 conntrack_msg.tuple_orig.src_ip,
                                                                 conntrack_msg.tuple_orig.dst_ip,
                                                                 conntrack_msg.tuple_orig.src_port,
                                                                 conntrack_msg.tuple_orig.dst_port))
                log.info("reply tuple: {}-{}-{}-{}-{}".format(conntrack_msg.tuple_reply.proto_num,
                                                              conntrack_msg.tuple_reply.src_ip,
                                                              conntrack_msg.tuple_reply.dst_ip,
                                                              conntrack_msg.tuple_reply.src_port,
                                                              conntrack_msg.tuple_reply.dst_port))
                self.conntrack_message_list.append(conntrack_msg)
                self.callback(conntrack_msg)

    def monitor_conntrack(self):
        while True:
            self.dump_conntrack_msgs()
            self.parse_conntrack_msgs()
            time.sleep(self.monitor_interval)


link_info = dict()


def set_tc_tethering_offload_rule(conntrack_msg: CONNTRACKMESSAGE):
    log.info("add tethering offload rule:")

    downstream = link_info["downstream"]
    upstream = link_info["upstream"]
    client = link_info["client"]
    server = link_info["server"]

    downstream.update_info(conntrack_msg.tuple_orig.dst_port)
    upstream.update_info(conntrack_msg.tuple_reply.dst_port)
    client.update_info(conntrack_msg.tuple_orig.proto_num, conntrack_msg.tuple_orig.src_port)
    server.update_info(conntrack_msg.tuple_reply.src_ip, conntrack_msg.tuple_reply.proto_num,
                       conntrack_msg.tuple_orig.src_port)

    cmd = "./tc_tethering_user -C {}-{}-{}-{} -S {}-{}-{} -U {}-{}-{} -D {}-{}-{}-{}-{}".format(client.mac_addr,
                                                                                                client.ipv4_addr,
                                                                                                client.l4_proto,
                                                                                                client.l4_port,
                                                                                                server.ipv4_addr,
                                                                                                server.l4_proto,
                                                                                                server.l4_port,
                                                                                                upstream.if_id,
                                                                                                upstream.ipv4_addr,
                                                                                                upstream.l4_port,
                                                                                                downstream.if_id,
                                                                                                downstream.mac_addr,
                                                                                                downstream.l3_proto,
                                                                                                downstream.ipv4_addr,
                                                                                                downstream.l4_port)

    log.info(cmd)
    ret, msg = run_cmd(cmd)
    log.info("setting tc tethering rule: ret={}, msg={}".format(ret, msg))


def load_tc_bpf(downstream: DOWNSTREAM, upstream: UPSTREAM):
    # load downstream NIC tc ingress
    cmd = "tc qdisc show dev {}".format(downstream.name)
    run_cmd(cmd)

    cmd = "tc qdisc add dev {} clsact".format(downstream.name)
    run_cmd(cmd)

    cmd = "tc filter add dev {} ingress bpf da obj {} sec {}".format(downstream.name, "tc_tethering_kern.o",
                                                                     "sched_cls_tether_upstream4_ether")
    run_cmd(cmd)

    cmd = "tc qdisc show dev {} ingress".format(downstream.name)
    ret, msg = run_cmd(cmd)
    log.info("dev {} ingress: {}".format(downstream.name, msg))

    # load upstream NIC tc ingress
    cmd = "tc qdisc show dev {}".format(upstream.name)
    run_cmd(cmd)

    cmd = "tc qdisc add dev {} clsact".format(upstream.name)
    run_cmd(cmd)

    cmd = "tc filter add dev {} ingress bpf da obj {} sec {}".format(upstream.name, "tc_tethering_kern.o",
                                                                     "sched_cls_tether_downstream4_rawip")
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
    upstream = UPSTREAM(args.upstream_nic_name)
    client = CLIENT(args.client_ipv4_addr)
    server = SERVER()

    load_tc_bpf(downstream, upstream)
    set_nat_rule(client, upstream)

    link_info["downstream"] = downstream
    link_info["upstream"] = upstream
    link_info["client"] = client
    link_info["server"] = server

    conntrack = CONNTRACKMONITOR(2, link_info, set_tc_tethering_offload_rule)
    conntrack.monitor_conntrack()


if __name__ == '__main__':
    log.basicConfig(level=log.INFO,
                    format='%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s')
    main()
