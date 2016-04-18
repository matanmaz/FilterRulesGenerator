"""
All the utilities to generate filter rules
Inputs: pcap
Outputs: snort conf file
"""
from scapy.all import *
import sys


class SnortRule:

    global rule_base
    rule_base = 25000
    global rule_count
    rule_count = 0

    def __init__(self, signature):
        global rule_base
        global rule_count

        self.sid = rule_base + rule_count
        rule_count += 1
        self.msg = "alert from rule {sid}".format(sid = self.sid)
        self.dport = signature['UDP'].dport
        self.sport = signature['UDP'].sport
        if (self.dport > 1000) :
            self.dport = 'any'
        else:
            self.sport = 'any'

        temp_bytes = bytearray(signature.lastlayer().original)
        buff = '"|'
        for i in range(0,len(temp_bytes)):
            buff += int2hexstr(temp_bytes[i]) + ' '
        buff += '|"'
        self.text = buff


    def __str__(self):
        return "alert udp any {sport} -> any {dport} (sid:{sid}; content:{content}; msg:{msg};)".format(
            sport = self.sport, dport=self.dport, sid = self.sid, content = self.text, msg = self.msg)


def int2hexstr(integer):
    a = hex(integer / 16)[-1:]
    b = hex(integer % 16)[-1:]
    return "{0}{1}".format(a,b)


def get_snort_rules_from_pcap(pcap_file_name):
    packets = rdpcap(pcap_file_name)
    rules = [SnortRule(packet) for packet in packets]
    return rules


def write_snort_file(snort_file_name, snort_rules):
    f = open(snort_file_name, 'w')
    snort_config = '''
config alertfile: /home/osboxes/projects/FilterRulesGenerator/alert_file

config logdir: /home/osboxes/projects/FilterRulesGenerator/log
'''
    f.write(snort_config)
    snort_lines = [rule.__str__() + '\n' for rule in snort_rules]
    f.writelines(snort_lines)


def send_pcap_packets(pcap_file_name):
    packets = rdpcap(pcap_file_name)
    payloads = [p.lastlayer().original for p in packets]
    packets = [IP(dst='8.8.8.8') / UDP(sport=10000, dport=161) / payload for payload in payloads]
    map(send, packets)

if __name__ == "__main__":
    pcap_file_name = sys.argv[1]
    snort_file_name = sys.argv[2]

    snort_rules = get_snort_rules_from_pcap(pcap_file_name)
    write_snort_file(snort_file_name, snort_rules)