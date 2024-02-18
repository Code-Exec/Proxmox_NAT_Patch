# Proxmox_NAT_Patch
Proxmox patch gives ability to create firewall NAT rules using the standard PVE web UI.

Full problem and working explanation (RU) - [link](https://github.com/Code-Exec/Proxmox_NAT_Patch/explanation_ru.md)

# Installation

**1. Patch pve-firewall.**

Download the latest release from the releases page [Releases](https://github.com/Code-Exec/Proxmox_NAT_Patch/releases) and extract it to any convenient place. Go to this folder and write in the console - 
        
        $ ./patcher.sh run

This command will patch the `/usr/share/perl5/PVE/Firewall.pm` file, making a backup. If it is successful, we will see "Patch done".

**WARNING!** The modified file has a line for binding to the external interface (needed for NAT rules).

        my $ext_if = 'vmbr0'; #external interface

If you have a different architecture scheme, change the value to your interface.

**2. Make the changes necessary for NAT**

Following the recommendations of the official site - [Link](https://pve.proxmox.com/wiki/Network_Configuration#_masquerading_nat_with_tt_span_class_monospaced_iptables_span_tt).

Modify the file /etc/network/interfaces

        auto vmbr1
        #private sub network
        iface vmbr1 inet static
                address 10.10.10.10.1
                netmask 255.255.255.255.0
                bridge-ports none
                bridge-stp off
                bridge-fd 1

                post-up echo 1 > /proc/sys/net/ipv4/ip_forward
                post-up iptables -t raw -I PREROUTING -i fwbr+ -j CT --zone 1
                post-down iptables -t raw -D PREROUTING -i fwbr+ -j CT --zone 1

In fact, we add three lines to our virtual network interface (which will also be the gateway for the entire network)

                post-up echo 1 > /proc/sys/net/ipv4/ip_forward
                post-up iptables -t raw -I PREROUTING -i fwbr+ -j CT --zone 1
                post-down iptables -t raw -D PREROUTING -i fwbr+ -j CT --zone 1

The first line adds the ability to allow "passing traffic", without it NAT will not work at all.

The second line fixes the problem with contrack (the part of NAT that allows you not to write double rules for ingress and egress, based on link state analysis and packet flags). The problem is that contrack sometimes gets confused in traffic between virtual and non-virtual networks. 

The first two are triggered when the interface is enabled. The third one, when disconnected, overrides the second one.....

**3. Restart** 

It is better to restart the whole server. But if this is not possible, you can do it in the console:

        service pvedaemon restart
        service pvepoxy restart
        pve-firewall restart

# Usage

**NAT rules are created only when the rule comment starts with the string "NAT"!

Rules are not applied instantly... Sometimes it can take up to a minute. But very rarely. The architecture of the solution is such that rules are all cleaned up, then new ones are created.

Example NAT in:

![Sample_NAT_in](https://github.com/Code-Exec/Proxmox_NAT_Patch/blob/master/img/Sample_NAT_in.PNG)

In this example, in addition to the standard rule allowing 123.123.123.123.123.123:822 -> 10.10.10.107:22, another NAT will be created. That is, by creating such a rule and knocking from IP 123.123.123.123.123 on port 822 to the IP address of our server, we will be routed to 10.10.10.107:22 . If you don't fill in the source, any IP will be able to connect through port 822.

**IMPORTANT!** In my architecture all virtual machines have a static IP so when I create such a rule I know exactly which machine it will go to. It is very convenient to use the VMID as the last digit of the IP, but this is my personal opinion.

Example NAT out:

![Sample_NAT_out](https://github.com/Code-Exec/Proxmox_NAT_Patch/blob/master/img/Sample_NAT_out.PNG)

Everything is similar in this example. A second NAT rule will be created to forward traffic from 10.10.10.10.105 (this is a specific VM) to 123.123.123.123.123:443. So if we try to connect to 123.123.123.123.123.123:443 from this VM, the NAT will work and let us through.

**IMPORTANT!** Eliases or aliases are not supported yet. You will only have to use IPs.

# Uninstall

Uninstall are going by the steps as install but in back order:
1. Type the command -  

         ./patcher.sh rollback

This command will restore the original file from the backup. If everything was successful we will see "Rollback done".

2. Delete lines from "/etc/network/interfaces".
3. Reboot.

Translated with DeepL.com (free version)