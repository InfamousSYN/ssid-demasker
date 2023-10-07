#!/usr/bin/python3
import argparse
import os
from scapy.all import *
import time

parser = argparse.ArgumentParser(description='Automated tool for extract the public key presented by WPA2-Enterprise wireless networks')
parser.add_argument('-w', '--wordlist', dest='wordlist_file', default='ssid.lst', help='Specify wordlist containing SSID values to test. (Default: ssid.lst)')
parser.add_argument('-i', '--interface', dest='interface', help='Specify used to broadcast packets', required=True)
parser.add_argument('-r', '--resend', dest='count', default=1, help='Specify how many times each SSID should be sent to account for transmission issues. (Default: 1)')
parser.add_argument('-m', '--mode', dest='mode', default=1, type=int, choices=[1,2], help='Specify where to use a pre-generated wordlist (1), or generate a wordlist at runtime (0). (Default: 1)', required=True)

hashcat = parser.add_argument_group(description='Specify control for just in time wordlist generation')
hashcat.add_argument('--increment', dest='increment', action='store_true', default=False, help='Enable incremental loops')
hashcat.add_argument('--fixed', dest='fixed', type=int, default=1, help='Control the mask length when not using incremental loops')
hashcat.add_argument('--min', dest='min', type=int, default=1, help='Set the floor of the incremental loop. (Default: 1)')
hashcat.add_argument('--max', dest='max', type=int, help='Set the upper boundary of the incremental loop. ')
hashcat.add_argument('--mask', dest='mask', type=str, default='?l?u?d', help='Specify the mask to use, do Not include the full mask as the specified value will be multiplied by the --fixed or each incremental loop. (Default: ?l?u?d)')

args, leftover = parser.parse_known_args()
options = args.__dict__

# Disable verbose mode
conf.verb = False

if __name__ == '__main__':
    bssid = dst = 'ff:ff:ff:ff:ff:ff'
    interface = options['interface']
    count = options['count']
    if(options['mode'] == 1):
        with open(options['wordlist_file'], 'r') as f:
            lines = f.readlines()
    elif(options['mode'] == 2):
        if(not options['increment']):
            process = subprocess.Popen(['hashcat', '-a', '3', '-1 {}'.format(options['mask']), '{}'.format('?1'*options['fixed']), '--quiet', '--stdout'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            lines, error = process.communicate()
            lines=lines.decode('utf-8').split('\n')
        else:
            loop = 1
            while loop <= options['max']:
                process = subprocess.Popen(['hashcat', '-a', '3', '-i', '-1 {}'.format(options['mask']), '{}'.format('?1'*loop), '--increment-min', '1', '--increment-max', '{}'.format(options['max']), '--quiet', '--stdout'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                lines, error = process.communicate()
                lines=lines.decode('utf-8').split('\n')
    else:
        exit(0)
    for ssid in lines:
        ssid = ssid.strip('\n')
        packet = RadioTap()/Dot11(type=0, subtype=4, addr1=dst, addr2=os.popen('cat /sys/class/net/{}/address'.format(interface)).read().strip('\n'), addr3=bssid)/Dot11ProbeReq()/Dot11Elt(ID='SSID', info=ssid, len=len(ssid))/Dot11EltRates()
        packet.timestamp = time.time()
        junk = sendp(packet, iface=interface, inter=1, count=options['count'])
