#!/usr/bin/env python
import subprocess
import optparse
import re
print(''' 
   /  |/  /   | / ____/  / ____/ /_  ____ _____  ____ ____  _____
  / /|_/ / /| |/ /      / /   / __ \/ __ `/ __ \/ __ `/ _ \/ ___/
 / /  / / ___ / /___   / /___/ / / / /_/ / / / / /_/ /  __/ /    
/_/  /_/_/  |_\____/   \____/_/ /_/\__,_/_/ /_/\__, /\___/_/     
                                              /____/             
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

def get_values():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Interface to change its MAC  address ------ 5H4D0W-R007 -------")
    parser.add_option("-m", "--mac", dest="new_mac", help="New MAC  address ------ 5H4D0W-R007 -------")
    (values, attributes) = parser.parse_args()
    if not values.interface and not values.new_mac:
        parser.error("[-] use --help for more info")
    if not values.interface:
        parser.error("[-] Please specify an interface, use --help for more info")
    if not values.new_mac:
        parser.error("[-] Please specify a MAC address, use --help for more info")
    return values

def mac_changer(interface, new_mac):
    print("[+] Changing MAC of " + interface + " to " + new_mac + "...")

    ###############################################
    #                                             #
    #     Vulnerable to Command Injection         #
    #                                             #
    ###############################################

    # print("ifconfig "+interface+" down")
    # subprocess.call("ifconfig "+interface +" down",shell=True)
    # subprocess.call("ifconfig "+interface+ " hw ether "+new_mac,shell=True)
    # subprocess.call("ifconfig "+interface+" up",shell=True)

    ###############################################
    #                                             #
    #                  Safer Code                 #
    #                                             #
    ###############################################

    subprocess.call(["ifconfig", interface, "down"])
    subprocess.call(["ifconfig", interface, "hw", "ether", new_mac])
    subprocess.call(["ifconfig", interface, "up"])

    print("[+] MAC address changed successfully!")

def get_current_mac(interface):
    ifconfig_result = subprocess.check_output(["ifconfig", interface])
    #print(type(str(ifconfig_result)))
    current_mac = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", str(ifconfig_result))  # convert byte type to string for comparison

    if current_mac:
        return current_mac.group(0)
    else:
        print("[-] Can`t find any MAC address")


#interface = input("Enter Interface > ")
#new_mac = input("Enter New MAC > ")

values = get_values()
interface = values.interface
new_mac = values.new_mac
current_mac = get_current_mac(interface)
print("Current MAC Address: " + str(current_mac))  # converting to string so as to deal with non-zero exit status
mac_changer(interface,new_mac)
#after changing the mac
current_mac = get_current_mac(interface)
if current_mac == new_mac:
    print("[+] MAC changed to " + new_mac)
else:
    print("[-] MAC didn't change")



