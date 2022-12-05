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
    def update_info(self, mac_addr, ipv4_addr, l4_proto, l4_port):
        self.mac_addr = mac_addr
        self.ipv4_addr = ipv4_addr
        self.l4_proto = l4_proto
        self.l4_port = l4_port
        log.info("client: {}-{}-{}-{}".format(self.mac_addr, self.ipv4_addr, self.l4_proto, self.l4_port))


class SERVER:
    def update_info(self, ipv4_addr, l4_proto, l4_port):
        self.ipv4_addr = ipv4_addr
        self.l4_proto = l4_proto
        self.l4_port = l4_port
        log.info("server: {}-{}-{}".format(self.ipv4_addr, self.l4_proto, self.l4_port))


# 获取指定downstream的interface id, mac addr, ipv4 addr
def parse_nic_information(nic_name):
    if_id = None
    mac_addr = None
    ipv4_addr = None

    cmd = "ip addr show dev {}".format(nic_name)
    ret, msg = run_cmd(cmd)
    log.debug(msg)
    if ret:
        log.error("get {} information fail!".format(nic_name))
        return if_id, mac_addr, ipv4_addr

    lines = msg.splitlines()
    log.debug(lines)

    for line in lines:
        # 获取interface id
        if line.find("{}: ".format(nic_name)) != -1:
            temp = line.split(":")
            log.debug(temp)
            if_id = temp[0]

        # 获取mac address
        if line.find("link/ether ") != -1:
            temp = line.split()
            log.debug(temp)
            mac_addr = temp[1]

        # 获取ipv4 address
        if line.find("inet ") != -1:
            temp = line.split()
            log.debug(temp)
            temp = temp[1].split("/")
            ipv4_addr = temp[0]

    log.info("{}: {}-{}-{}".format(nic_name, if_id, mac_addr, ipv4_addr))

    return if_id, mac_addr, ipv4_addr


class DOWNSTREAM:
    l3_proto = "0x0800"  # ipv4

    def __init__(self, nic_name):
        self.name = nic_name
        if_id, mac_addr, ipv4_addr = parse_nic_information(self.name)
        self.if_id = if_id
        self.mac_addr = mac_addr
        self.ipv4_addr = ipv4_addr

    def update_info(self, l4_port):
        self.l4_port = l4_port
        log.info(
            "downstream: {}-{}-{}-{}-{}-{}".format(self.name, self.if_id, self.mac_addr, self.l3_proto, self.ipv4_addr,
                                                   self.l4_port))


class UPSTREAM:
    def __init__(self, nic_name):
        self.name = nic_name
        if_id, mac_addr, ipv4_addr = parse_nic_information(self.name)
        self.if_id = if_id
        self.ipv4_addr = ipv4_addr

    def update_info(self, l4_port):
        self.l4_port = l4_port
        log.info("upstream: {}-{}-{}-{}".format(self.name, self.if_id, self.ipv4_addr, self.l4_port))

    def check_ip_equal_upstream(self, ipv4_addr):
        if self.ipv4_addr == ipv4_addr:
            return True
        else:
            return False


###################neighbor ######################################################################################
def set_nat_rule(client_ipv4_addr, upstream: UPSTREAM):
    cmd = "iptables -t nat -A POSTROUTING -o {} -s {}  -j SNAT --to {}".format(
        upstream.name, client_ipv4_addr, upstream.ipv4_addr)
    ret, msg = run_cmd(cmd)
    log.debug(msg)

    cmd = "iptables -t nat -vnL"
    ret, msg = run_cmd(cmd)
    log.info("nat rule: {}".format(msg))

    cmd = "echo 1 > /proc/sys/net/ipv4/ip_forward"
    run_cmd(cmd)
    cmd = "cat /proc/sys/net/ipv4/ip_forward"
    ret, msg = run_cmd(cmd)
    log.debug("ipv4 forward status: {}".format(msg))


class NEIGHBOR_MESSAGE:

    def __init__(self, neighbor_msg):
        self.msg = neighbor_msg
        self.ipv4_addr = None
        self.mac = None

    def parse_neighbor_msg(self):
        temp = self.msg.split()
        log.debug(temp)
        if (len(temp) != 4):
            log.info("not complete neighbor message: {}".format(self.msg))
            return -1
        self.ipv4_addr = temp[0]
        self.mac = temp[2]
        log.debug("neighbor: {}-{}".format(self.ipv4_addr, self.mac))
        return 0


class NEIGHBOR_MONITOR:

    def __init__(self, dev_name, link_info, callback):
        self.neighbor_message_list = []
        self.neighbor_msg = None
        self.dev_name = dev_name
        self.link_info = link_info
        self.callback = callback

    def dump_neighbor_msgs(self):
        cmd = "ip neighbor show dev {} nud reachable".format(self.dev_name)
        ret, msg = run_cmd(cmd)
        log.debug("neighbor information: {}".format(msg))
        self.neighbor_msg = msg
        return msg

    def check_neighbor_equle(self, src: NEIGHBOR_MESSAGE, dst: NEIGHBOR_MESSAGE):
        if (src.ipv4_addr == dst.ipv4_addr):
            return True
        else:
            return False

    def check_neighbor_msg_is_exist(self, neighbor_msg: NEIGHBOR_MESSAGE):
        is_exist = False
        for item in self.neighbor_message_list:
            if self.check_neighbor_equle(neighbor_msg, item):
                is_exist = True
                break

        return is_exist

    def check_neighbor_is_exit_by_ipv4_addr(self, ipv4_addr):
        is_exist = False
        for item in self.neighbor_message_list:
            if ipv4_addr == item.ipv4_addr:
                is_exist = True
                break

        return is_exist

    def get_neighbor_mac_by_ip(self, ipv4_addr):
        mac = None
        for item in self.neighbor_message_list:
            if ipv4_addr == item.ipv4_addr:
                mac = item.mac
                break

        return mac

    def update_neighbor_messages(self):
        log.info("update neighbor information")
        self.dump_neighbor_msgs()
        msgs = self.neighbor_msg.splitlines()
        log.debug(msgs)
        for msg in msgs:
            neighbor_message = NEIGHBOR_MESSAGE(msg)
            if neighbor_message.parse_neighbor_msg() == -1:
                continue

            if self.check_neighbor_msg_is_exist(neighbor_message):
                continue

            self.neighbor_message_list.append(neighbor_message)
            log.info("neighbor: {}-{}".format(neighbor_message.ipv4_addr, neighbor_message.mac))

            self.callback(neighbor_message.ipv4_addr, self.link_info["upstream"])


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
    else:
        return False


def check_tuple_is_valid(tuple: TUPLE):
    if (tuple.proto_num is not None and tuple.src_ip is not None and tuple.dst_ip is not None and
            tuple.src_port is not None and tuple.dst_port is not None):
        return True
    else:
        return False


class CONNTRACK_MESSAGE:

    def __init__(self, conntrack_msg):
        self.msg = conntrack_msg
        # Original direction conntrack tuple.
        self.tuple_orig = TUPLE()
        # Reply direction conntrack tuple.
        self.tuple_reply = TUPLE()
        self.orig_src_mac = None

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

        if check_tuple_is_valid(self.tuple_orig) and check_tuple_is_valid(self.tuple_reply):
            return 0
        else:
            return -1

    def show_msssage(self):
        log.info("original tuple: {}-{}-{}-{}-{}".format(self.tuple_orig.proto_num,
                                                         self.tuple_orig.src_ip,
                                                         self.tuple_orig.dst_ip,
                                                         self.tuple_orig.src_port,
                                                         self.tuple_orig.dst_port))
        log.info("reply tuple: {}-{}-{}-{}-{}".format(self.tuple_reply.proto_num,
                                                      self.tuple_reply.src_ip,
                                                      self.tuple_reply.dst_ip,
                                                      self.tuple_reply.src_port,
                                                      self.tuple_reply.dst_port))


class CONNTRACK_MONITOR:
    conntrack_message_list = []
    conntrack_msg = None

    def __init__(self, monitor_interval, link_info, callback):
        self.callback = callback
        self.monitor_interval = monitor_interval
        self.neighbor_monitor: NEIGHBOR_MONITOR = link_info["neighbor"]
        self.upstream: UPSTREAM = link_info["upstream"]

    def dump_conntrack_msgs(self):
        cmd = "conntrack -L"
        ret, msg = run_cmd(cmd)
        log.debug("conntrack information: {}".format(msg))
        self.conntrack_msg = msg
        return msg

    def need_offload_conntrack_event(self, conntrack_msg: CONNTRACK_MESSAGE):
        if conntrack_msg.msg.find("ESTABLISHED") != -1 and \
                self.neighbor_monitor.check_neighbor_is_exit_by_ipv4_addr(conntrack_msg.tuple_orig.src_ip) and \
                self.upstream.check_ip_equal_upstream(conntrack_msg.tuple_reply.dst_ip):
            conntrack_msg.orig_src_mac = self.neighbor_monitor.get_neighbor_mac_by_ip(conntrack_msg.tuple_orig.src_ip)
            return True
        else:
            return False

    def check_contrack_msg_is_exist(self, conntrack_msg: CONNTRACK_MESSAGE):
        is_exist = False
        for item in self.conntrack_message_list:
            if check_tuple_equle(conntrack_msg.tuple_orig, item.tuple_orig) and \
                    check_tuple_equle(conntrack_msg.tuple_reply, item.tuple_reply):
                is_exist = True
                break

        return is_exist

    def update_conntrack_messages(self):
        log.info("update conntrack information")
        self.dump_conntrack_msgs()
        msgs = self.conntrack_msg.splitlines()
        for msg in msgs:
            conntrack_msg = CONNTRACK_MESSAGE(msg)
            if conntrack_msg.parse_conntrack_msg() != 0:
                continue
            if self.check_contrack_msg_is_exist(conntrack_msg) is True:
                continue

            if self.need_offload_conntrack_event(conntrack_msg):
                conntrack_msg.show_msssage()
                self.conntrack_message_list.append(conntrack_msg)
                self.callback(conntrack_msg)

    def monitor_conntrack(self):
        while True:
            self.neighbor_monitor.update_neighbor_messages()
            self.update_conntrack_messages()
            time.sleep(self.monitor_interval)


link_info = dict()


def set_tc_tethering_offload_rule(conntrack_msg: CONNTRACK_MESSAGE):
    log.info("add tethering offload rule:")
    downstream: DOWNSTREAM = link_info["downstream"]
    upstream: UPSTREAM = link_info["upstream"]
    client: CLIENT = link_info["client"]
    server: SERVER = link_info["server"]

    downstream.update_info(conntrack_msg.tuple_orig.dst_port)
    upstream.update_info(conntrack_msg.tuple_reply.dst_port)
    client.update_info(conntrack_msg.orig_src_mac, conntrack_msg.tuple_orig.src_ip,
                       conntrack_msg.tuple_orig.proto_num, conntrack_msg.tuple_orig.src_port)
    server.update_info(conntrack_msg.tuple_reply.src_ip, conntrack_msg.tuple_reply.proto_num,
                       conntrack_msg.tuple_reply.src_port)

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
    log.info("tc_tethering_user log:  ret={}, msg={}".format(ret, msg))


def load_tc_bpf(downstream: DOWNSTREAM, upstream: UPSTREAM):
    # load downstream NIC tc ingress - upstream4_map
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

    # load upstream NIC tc ingress - downstream4_map
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


def clean_setting(upstream_nic_name, downstream_nic_name):
    log.info("clean NAT setting:")
    cmd = "iptables -t nat -F"
    run_cmd(cmd)
    log.info("clean the iptables NAT rules")

    cmd = "iptables -t nat -vnL"
    ret, msg = run_cmd(cmd)
    log.info("nat rule: {}".format(msg))

    log.info("clean tc setting")
    cmd = "tc filter del dev {} ingress".format(upstream_nic_name)
    run_cmd(cmd)
    cmd = "tc qdisc add dev {} clsact".format(upstream_nic_name)
    run_cmd(cmd)

    cmd = "tc filter del dev {} ingress".format(downstream_nic_name)
    run_cmd(cmd)
    cmd = "tc qdisc add dev {} clsact".format(downstream_nic_name)
    run_cmd(cmd)


def main():
    parser = argparse.ArgumentParser(description="This is a example program")
    parser.add_argument('-d', '--downstream_nic_name', default=None, help='the downstream NIC name')
    parser.add_argument('-u', '--upstream_nic_name', default=None, help='the upstream NIC name')
    parser.add_argument('-r', '--recovery', action='store_true', help='clean the iptabels NAT setting')
    args = parser.parse_args()

    if args.downstream_nic_name is None or args.upstream_nic_name is None:
        log.info("please input the downstream_nic_name, upstream_nic_name")
        return

    if args.recovery:
        clean_setting(args.upstream_nic_name, args.downstream_nic_name)
        return

    downstream = DOWNSTREAM(args.downstream_nic_name)
    upstream = UPSTREAM(args.upstream_nic_name)
    client = CLIENT()
    server = SERVER()

    load_tc_bpf(downstream, upstream)

    link_info["downstream"] = downstream
    link_info["upstream"] = upstream
    link_info["client"] = client
    link_info["server"] = server

    neighbor_monitor = NEIGHBOR_MONITOR(args.downstream_nic_name, link_info, set_nat_rule)
    neighbor_monitor.update_neighbor_messages()
    link_info["neighbor"] = neighbor_monitor

    conntrack = CONNTRACK_MONITOR(2, link_info, set_tc_tethering_offload_rule)
    conntrack.monitor_conntrack()


if __name__ == '__main__':
    log.basicConfig(level=log.INFO,
                    format='%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s')
    main()
