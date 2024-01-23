# essstat - TP-Link Easy Smart Switch port statistics

[TP-Link Easy Smart Switches](https://www.tp-link.com/us/business-networking/easy-smart-switch/) are a family of managed switches capable of supporting QoS, VLANs and Link Aggregation Groups (LAGs).
They are managed through a web based interface, giving access a number of functions, including basic packets counters per-port. 
Unfortunately, these switches do not implement SNMP for access to these counters, nor do they appear to implement a discrete URL for
direct access to this information. This project addresses this issue to produce per-port statistics from a single command line invocation 
with output that can be trivially parsed for formatted output, or entered into a monitoring system like Zabbix.

This project has been tested against TP-Link switch models TL-SG1016DE and TL-SG108E. It should also be compatible with the other 
members of this family, including the TL-SG105E and TL-SG1024DE.

The output should be easy to parse for a Zabbix agent.

***
<p align="center">
<B>*** WARNING ***</B>
</p>

The Easy Smart Switch family has a number of unresolved vulnerabilities, including [CVE-2017-17746](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-17746). As described in [https://seclists.org/fulldisclosure/2017/Dec/67](https://seclists.org/fulldisclosure/2017/Dec/67), once a user from a given source IP address authenticates to the web-based management interface of the switch, any other user from that same source IP address is treated as authenticated. 

**The Python scripts in this project should be used only from a host that does not have general user access.**

***


## Major Components

*essstat.py* is a lightweight utility is used to pull port statistics from the switch and output in a readily parsable format. Additional 
code will be added to parse and either output or store these statistics.


### essstat.py

This lightweight Python application performs a quick login through the switch's web based administrative interface, and then queries the 
unit for the current port statistics. Credentials for accessing the unit are passed on the command line. The utility was coded with 
Python&nbsp;3.6 and uses the [Beautiful Soup](https://pypi.org/project/beautifulsoup4/) library.

#### Usage

    essstat.py [-h] [-1] [-d] -p TPpswd [-s] [-u TPuser] TPhost
    
#### Options

##### positional arguments:

    TPhost                IP address or hostname of switch

##### optional arguments:

    -h, --help            show this help message and exit
    -1, --1line           output in a single line
    -d, --debug           activate debugging output
    -j, --json            output in JSON format
    -p TPpswd, --password TPpswd
                          password for switch access
    -s, --statsonly       output post statistics only
    -u TPuser, --username TPuser
                          username for switch access

#### Example

    $ essstat.py myswitch -p ChangeMe
    2020-03-28 11:25:15
    max_port_num=8
    1;Enabled;Link Down;0,0,0,0
    2;Enabled;10M Full;3568644976,0,3144940915,0
    3;Enabled;1000M Full;237232286,0,66662515,0
    4;Enabled;1000M Full;4019260430,0,3721138807,0
    5;Enabled;1000M Full;1300360968,0,355032522,0
    6;Enabled;Link Down;0,0,0,0
    7;Enabled;1000M Full;2903398648,0,4293632425,5
    8;Enabled;Link Down;0,0,0,0


## Technical Background

The TP-Link Easy Smart Switch has more capabilities than a completely unmanaged switch. However, the management environment is relatively closed, with only a proprietary management client (Easy Smart Configuration Utility) or a web-based management page on the switch available. Furthermore, there is no support for monitoring the switch with SNMP. This means that our only entry into the switch will be via the protocol used by the proprietary client, or by scaping the web-based management interface on the switch.

First, a little background on the UDP-base Easy Smart Configuration Protocol (ESCP) that this project does ***not*** use. The Easy Smart Configuration Utility interacts with the switch over UDP with broadcasts. The client will send a UDP broadcast from port 29809 to 29808 of a specially encoded discovery packet. Compatible switches on the network will broadcast a response from port 29808 to 29809 than includes the name, model and IP address of the switch. From this point, it is up to the client to encode a login sequence and broadcast this on the network, with the expectation that the specific target switch will receive and process the instruction. This could be to send back information in another broadcast packet, modify the configuration of the switch, or take some other action. 

This design and implementation has a number of issues that should cause some concern which have been highlighted by security researchers ([@chrisdcmoore]( https://twitter.com/chrisdcmoore) in [Information disclosure vulnerability in TP-Link Easy Smart switches](https://www.chrisdcmoore.co.uk/post/tplink-easy-smart-switch-vulnerabilities/) and [@chmod7850](https://twitter.com/chmod750) in [Vulnerability disclosure TP-Link multiples CVEs](https://chmod750.wordpress.com/2017/04/23/vulnerability-disclosure-tp-link/)). While hacking into the ESCP would be easy enough, I really did not like the idea of literally broadcasting credentials across the network on a regular basis to grab statistics.

The apprach that this project does use, the web-based client, is problematic as well. Using a TCP unicast connections is better, but SSL is not implemented by the switch. While it is possible to reconfigure the switch to use a different administrative username, there is only one username for accessing the switch. This precludes employing role-based access with a dedicated username for reading statistics only. The credential we use to grab the statistics could also be used to access the management interface allowing resetting of counters, reconfiguring the switch or even replacing the firmware. 

**Worse still are the vulnerabilities reported in [CVE-2017-17746](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-17746)**. As described in [https://seclists.org/fulldisclosure/2017/Dec/67](https://seclists.org/fulldisclosure/2017/Dec/67), once a user from a given source IP address authenticates to the web-based management interface of the switch, any other user from that same source IP address is treated as authenticated. This condition is created by the execution of the Python scripts in this project, where other users logged into or tunneling through the same host would then have unauthenticated access to the management interface of the switch. This problem can be mitigated by running the scripts from a dedicated management host. Use of a dedicated out-of-band management LAN could offer protection as well, but these switches are unlikely to be used in such an elaborately structured environment.

___

Forked from [Peter Smode](https://github.com/psmode/essstat) - Thanks for your Work !
