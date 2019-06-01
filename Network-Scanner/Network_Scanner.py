#!usr/bin/env python
import os
os.sys.path.append('/usr/local/lib/python2.7/site-packages')
import scapy.all as scapy
import argparse # successor of optparse [deprecated]

print('''    _                      _    
| \ | | ___| |___      _____  _ __| | __
|  \| |/ _ \ __\ \ /\ / / _ \| '__| |/ /
| |\  |  __/ |_ \ V  V / (_) | |  |   < 
|_| \_|\___|\__| \_/\_/ \___/|_|  |_|\_\
                                        
 ____                                  
/ ___|  ___ __ _ _ __  _ __   ___ _ __ 
\___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
 ___) | (_| (_| | | | | | | |  __/ |   
|____/ \___\__,_|_| |_|_| |_|\___|_| 
''')
print('''        
                            #### 5H4D0W-R007 #####    
XX   MMMMMMMMMMMMMMMMss'''                          '''ssMMMMMMMMMMMMMMMM   XX
XX   MMMMMMMMMMMMyy''                                    ''yyMMMMMMMMMMMM   XX
XX   MMMMMMMMyy''                                            ''yyMMMMMMMM   XX
XX   MMMMMy''                                                    ''yMMMMM   XX
XX   MMMy'                                                          'yMMM   XX
XX   Mh'                                                              'hM   XX
XX   -                                                                  -   XX
XX                                                                          XX
XX   ::                                                                ::   XX
XX   MMhh.        ..hhhhhh..                      ..hhhhhh..        .hhMM   XX
XX   MMMMMh   ..hhMMMMMMMMMMhh.                .hhMMMMMMMMMMhh..   hMMMMM   XX
XX   ---MMM .hMMMMdd:::dMMMMMMMhh..        ..hhMMMMMMMd:::ddMMMMh. MMM---   XX
XX   MMMMMM MMmm''      'mmMMMMMMMMyy.  .yyMMMMMMMMmm'      ''mmMM MMMMMM   XX
XX   ---mMM ''             'mmMMMMMMMM  MMMMMMMMmm'             '' MMm---   XX
XX   yyyym'    .              'mMMMMm'  'mMMMMm'              .    'myyyy   XX
XX   mm''    .y'     ..yyyyy..  ''''      ''''  ..yyyyy..     'y.    ''mm   XX
XX           MN    .sMMMMMMMMMss.   .    .   .ssMMMMMMMMMs.    NM           XX
XX           N`    MMMMMMMMMMMMMN   M    M   NMMMMMMMMMMMMM    `N           XX
XX            +  .sMNNNNNMMMMMN+   `N    N`   +NMMMMMNNNNNMs.  +            XX
XX              o+++     ++++Mo    M      M    oM++++     +++o              XX
XX                                oo      oo                                XX
XX           oM                 oo          oo                 Mo           XX
XX         oMMo                M              M                oMMo         XX
XX       +MMMM                 s              s                 MMMM+       XX
XX      +MMMMM+            +++NNNN+        +NNNN+++            +MMMMM+      XX
XX     +MMMMMMM+       ++NNMMMMMMMMN+    +NMMMMMMMMNN++       +MMMMMMM+     XX
XX     MMMMMMMMMNN+++NNMMMMMMMMMMMMMMNNNNMMMMMMMMMMMMMMNN+++NNMMMMMMMMM     XX
XX     yMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMy     XX
XX   m  yMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMy  m   XX
XX   MMm yMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMy mMM   XX
XX   MMMm .yyMMMMMMMMMMMMMMMM     MMMMMMMMMM     MMMMMMMMMMMMMMMMyy. mMMM   XX
XX   MMMMd   ''''hhhhh       odddo          obbbo        hhhh''''   dMMMM   XX
XX   MMMMMd             'hMMMMMMMMMMddddddMMMMMMMMMMh'             dMMMMM   XX
XX   MMMMMMd              'hMMMMMMMMMMMMMMMMMMMMMMh'              dMMMMMM   XX
XX   MMMMMMM-               ''ddMMMMMMMMMMMMMMdd''               -MMMMMMM   XX
XX   MMMMMMMM                   '::dddddddd::'                   MMMMMMMM   XX
XX   MMMMMMMM-                                                  -MMMMMMMM   XX
XX   MMMMMMMMM                                                  MMMMMMMMM   XX
XX   MMMMMMMMMy                                                yMMMMMMMMM   XX
XX   MMMMMMMMMMy.                                            .yMMMMMMMMMM   XX
XX   MMMMMMMMMMMMy.                                        .yMMMMMMMMMMMM   XX
XX   MMMMMMMMMMMMMMy.                                    .yMMMMMMMMMMMMMM   XX
XX   MMMMMMMMMMMMMMMMs.                                .sMMMMMMMMMMMMMMMM   XX
XX   MMMMMMMMMMMMMMMMMMss.           ....           .ssMMMMMMMMMMMMMMMMMM   XX
XX   MMMMMMMMMMMMMMMMMMMMNo         oNNNNo         oNMMMMMMMMMMMMMMMMMMMM   XX
''')

print('''
 ____  _   _ _  _   ____   _____        __    ____   ___   ___ _____ 
| ___|| | | | || | |  _ \ / _ \ \      / /   |  _ \ / _ \ / _ \___  |
|___ \| |_| | || |_| | | | | | \ \ /\ / /____| |_) | | | | | | | / / 
 ___) |  _  |__   _| |_| | |_| |\ V  V /_____|  _ <| |_| | |_| |/ /  
|____/|_| |_|  |_| |____/ \___/  \_/\_/      |_| \_\\___/ \___//_/   

''')
def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--ip", dest = "targetip", help = "Enter target IP/IP Range ------ 5H4D0W-R007 -------")
    values = parser.parse_args()
    if not values.targetip:
        parser.error("[-] Please specify an IP Address, use --help for more info")
    return values

def scanner(ip):
    #scapy.arping(ip)   -> arp requests directed to broadcast MAC

    arp_request = scapy.ARP(pdst = ip)   # 1. set IP to pdst field in ARP Class
    #scapy.ls(scapy.ARP())
    #arp_request.show()
    broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")          # 2. set destination MAC to broadcast MAC in Ether Class
    #scapy.ls(scapy.Ether())
    #broadcast.show()
    arp_request_broadcast = broadcast/arp_request  # combining frames
    #arp_request_broadcast.show()
    #print(arp_request.summary())
    #  srp() returns 2 lists, answered & unanswered
    answered_summary, unanswered_summary = scapy.srp(arp_request_broadcast, timeout = 1, verbose = False) #remove extra details
    #print(answered_summary.summary())

    results_list = []  # list of dictionaries
    for i in answered_summary:
        #print(i[1].psrc + "\t\t\t" + i[1].hwsrc) Source IP and MAC from 1st element of answered list
        results_dict = {"ip":i[1].psrc, "mac":i[1].hwsrc}  # a dictionary with ip and mac as keys
        results_list.append(results_dict)

    return results_list

def result(result_list):
    print("----------------------------------------------------")
    print("IP Address\t\t\tMAC Address")
    print("----------------------------------------------------")
    for client in result_list:
        print(client["ip"] + "\t\t\t" + client["mac"])

option = get_args()
scan_result = scanner(option.targetip)
result(scan_result)
