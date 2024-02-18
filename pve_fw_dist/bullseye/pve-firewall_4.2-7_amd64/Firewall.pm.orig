package PVE::Firewall;

use warnings;
use strict;

use Digest::SHA;
use Encode;
use File::Basename;
use File::Path;
use IO::File;
use Net::IP;
use POSIX;
use Socket qw(AF_INET AF_INET6 inet_ntop inet_pton);
use Storable qw(dclone);

use PVE::Cluster;
use PVE::Corosync;
use PVE::Exception qw(raise raise_param_exc);
use PVE::INotify;
use PVE::JSONSchema qw(register_standard_option get_standard_option);
use PVE::Network;
use PVE::ProcFSTools;
use PVE::SafeSyslog;
use PVE::Tools qw($IPV4RE $IPV6RE);
use PVE::Tools qw(run_command lock_file dir_glob_foreach);

use PVE::Firewall::Helpers;

my $pvefw_conf_dir = "/etc/pve/firewall";
my $clusterfw_conf_filename = "$pvefw_conf_dir/cluster.fw";

# dynamically include PVE::QemuServer and PVE::LXC
# to avoid dependency problems
my $have_qemu_server;
eval {
    require PVE::QemuServer;
    require PVE::QemuConfig;
    $have_qemu_server = 1;
};

my $have_lxc;
eval {
    require PVE::LXC;
    $have_lxc = 1;
};

my $pve_fw_status_dir = "/var/lib/pve-firewall";

mkdir $pve_fw_status_dir; # make sure this exists

my $security_group_name_pattern = '[A-Za-z][A-Za-z0-9\-\_]+';
my $ipset_name_pattern = '[A-Za-z][A-Za-z0-9\-\_]+';
our $ip_alias_pattern = '[A-Za-z][A-Za-z0-9\-\_]+';

my $max_alias_name_length = 64;
my $max_ipset_name_length = 64;
my $max_group_name_length = 18;

my $PROTOCOLS_WITH_PORTS = {
    udp => 1,     17 => 1,
    udplite => 1, 136 => 1,
    tcp => 1,     6 => 1,
    dccp => 1,    33 => 1,
    sctp => 1,    132 => 1,
};

PVE::JSONSchema::register_format('IPorCIDR', \&pve_verify_ip_or_cidr);
sub pve_verify_ip_or_cidr {
    my ($cidr, $noerr) = @_;

    if ($cidr =~ m!^(?:$IPV6RE|$IPV4RE)(/(\d+))?$!) {
	return $cidr if Net::IP->new($cidr);
	return undef if $noerr;
	die Net::IP::Error() . "\n";
    }
    return undef if $noerr;
    die "value does not look like a valid IP address or CIDR network\n";
}

PVE::JSONSchema::register_format('IPorCIDRorAlias', \&pve_verify_ip_or_cidr_or_alias);
sub pve_verify_ip_or_cidr_or_alias {
    my ($cidr, $noerr) = @_;

    return if $cidr =~ m/^(?:$ip_alias_pattern)$/;

    return pve_verify_ip_or_cidr($cidr, $noerr);
}

PVE::JSONSchema::register_standard_option('ipset-name', {
    description => "IP set name.",
    type => 'string',
    pattern => $ipset_name_pattern,
    minLength => 2,
    maxLength => $max_ipset_name_length,
});

PVE::JSONSchema::register_standard_option('pve-fw-alias', {
    description => "Alias name.",
    type => 'string',
    pattern => $ip_alias_pattern,
    minLength => 2,
    maxLength => $max_alias_name_length,
});

PVE::JSONSchema::register_standard_option('pve-fw-loglevel' => {
    description => "Log level.",
    type => 'string',
    enum => ['emerg', 'alert', 'crit', 'err', 'warning', 'notice', 'info', 'debug', 'nolog'],
    optional => 1,
});

PVE::JSONSchema::register_standard_option('pve-security-group-name', {
    description => "Security Group name.",
    type => 'string',
    pattern => $security_group_name_pattern,
    minLength => 2,
    maxLength => $max_group_name_length,
});

my $feature_ipset_nomatch = 0;
eval  {
    my (undef, undef, $release) = POSIX::uname();
    if ($release =~ m/^(\d+)\.(\d+)\.\d+-/) {
	my ($major, $minor) = ($1, $2);
	$feature_ipset_nomatch = 1 if ($major > 3) ||
	    ($major == 3 && $minor >= 7);
    }

};

my $nodename = PVE::INotify::nodename();
my $hostfw_conf_filename = "/etc/pve/nodes/$nodename/host.fw";

my $pve_fw_lock_filename = "/var/lock/pvefw.lck";

my $default_log_level = 'nolog'; # avoid logs by default
my $global_log_ratelimit = '--limit 1/sec';

my $log_level_hash = {
    debug => 7,
    info => 6,
    notice => 5,
    warning => 4,
    err => 3,
    crit => 2,
    alert => 1,
    emerg => 0,
};

my $verbose = 0;
sub set_verbose {
    $verbose = shift;
}

# %rule
#
# name => optional
# enable => [0|1]
# action =>
# proto =>
# sport => port[,port[,port]].. or port:port
# dport => port[,port[,port]].. or port:port
# log => optional, loglevel
# logmsg => optional, logmsg - overwrites default
# iface_in => incomin interface
# iface_out => outgoing interface
# match => optional, overwrites generation of match
# target => optional, overwrites action

# we need to overwrite some macros for ipv6
my $pve_ipv6fw_macros = {
    'Ping' => [
	{ action => 'PARAM', proto => 'icmpv6', dport => 'echo-request' },
    ],
    'NeighborDiscovery' => [
	"IPv6 neighbor solicitation, neighbor and router advertisement",
	{ action => 'PARAM', proto => 'icmpv6', dport => 'router-solicitation' },
	{ action => 'PARAM', proto => 'icmpv6', dport => 'router-advertisement' },
	{ action => 'PARAM', proto => 'icmpv6', dport => 'neighbor-solicitation' },
	{ action => 'PARAM', proto => 'icmpv6', dport => 'neighbor-advertisement' },
    ],
    'DHCPv6' => [
	"DHCPv6 traffic",
	{ action => 'PARAM', proto => 'udp', dport => '546:547', sport => '546:547' },
    ],
    'Trcrt' => [
	{ action => 'PARAM', proto => 'udp', dport => '33434:33524' },
	{ action => 'PARAM', proto => 'icmpv6', dport => 'echo-request' },
    ],
 };

# imported/converted from: /usr/share/shorewall/macro.*
my $pve_fw_macros = {
    'Amanda' => [
	"Amanda Backup",
	{ action => 'PARAM', proto => 'udp', dport => '10080' },
	{ action => 'PARAM', proto => 'tcp', dport => '10080' },
    ],
    'Auth' => [
	"Auth (identd) traffic",
	{ action => 'PARAM', proto => 'tcp', dport => '113' },
    ],
    'BGP' => [
	"Border Gateway Protocol traffic",
	{ action => 'PARAM', proto => 'tcp', dport => '179' },
    ],
    'BitTorrent' => [
	"BitTorrent traffic for BitTorrent 3.1 and earlier",
	{ action => 'PARAM', proto => 'tcp', dport => '6881:6889' },
	{ action => 'PARAM', proto => 'udp', dport => '6881' },
    ],
    'BitTorrent32' => [
	"BitTorrent traffic for BitTorrent 3.2 and later",
	{ action => 'PARAM', proto => 'tcp', dport => '6881:6999' },
	{ action => 'PARAM', proto => 'udp', dport => '6881' },
    ],
    'Ceph' => [
        "Ceph Storage Cluster traffic (Ceph Monitors, OSD & MDS Daemons)",
	# Legacy port for protocol v1
        { action => 'PARAM', proto => 'tcp', dport => '6789' },
	# New port for protocol v2
        { action => 'PARAM', proto => 'tcp', dport => '3300' },
        { action => 'PARAM', proto => 'tcp', dport => '6800:7300' },
    ],
    'CVS' => [
	"Concurrent Versions System pserver traffic",
	{ action => 'PARAM', proto => 'tcp', dport => '2401' },
    ],
    'Citrix' => [
	"Citrix/ICA traffic (ICA, ICA Browser, CGP)",
	{ action => 'PARAM', proto => 'tcp', dport => '1494' },
	{ action => 'PARAM', proto => 'udp', dport => '1604' },
	{ action => 'PARAM', proto => 'tcp', dport => '2598' },
    ],
    'DAAP' => [
	"Digital Audio Access Protocol traffic (iTunes, Rythmbox daemons)",
	{ action => 'PARAM', proto => 'tcp', dport => '3689' },
	{ action => 'PARAM', proto => 'udp', dport => '3689' },
    ],
    'DCC' => [
	"Distributed Checksum Clearinghouse spam filtering mechanism",
	{ action => 'PARAM', proto => 'tcp', dport => '6277' },
    ],
    'DHCPfwd' => [
	"Forwarded DHCP traffic",
	{ action => 'PARAM', proto => 'udp', dport => '67:68', sport => '67:68' },
    ],
    'DNS' => [
	"Domain Name System traffic (upd and tcp)",
	{ action => 'PARAM', proto => 'udp', dport => '53' },
	{ action => 'PARAM', proto => 'tcp', dport => '53' },
    ],
    'Distcc' => [
	"Distributed Compiler service",
	{ action => 'PARAM', proto => 'tcp', dport => '3632' },
    ],
    'FTP' => [
	"File Transfer Protocol",
	{ action => 'PARAM', proto => 'tcp', dport => '21' },
    ],
    'Finger' => [
	"Finger protocol (RFC 742)",
	{ action => 'PARAM', proto => 'tcp', dport => '79' },
    ],
    'GNUnet' => [
	"GNUnet secure peer-to-peer networking traffic",
	{ action => 'PARAM', proto => 'tcp', dport => '2086' },
	{ action => 'PARAM', proto => 'udp', dport => '2086' },
	{ action => 'PARAM', proto => 'tcp', dport => '1080' },
	{ action => 'PARAM', proto => 'udp', dport => '1080' },
    ],
    'GRE' => [
	"Generic Routing Encapsulation tunneling protocol",
	{ action => 'PARAM', proto => '47' },
    ],
    'Git' => [
	"Git distributed revision control traffic",
	{ action => 'PARAM', proto => 'tcp', dport => '9418' },
    ],
    'HKP' => [
	"OpenPGP HTTP key server protocol traffic",
	{ action => 'PARAM', proto => 'tcp', dport => '11371' },
    ],
    'HTTP' => [
	"Hypertext Transfer Protocol (WWW)",
	{ action => 'PARAM', proto => 'tcp', dport => '80' },
    ],
    'HTTPS' => [
	"Hypertext Transfer Protocol (WWW) over SSL",
	{ action => 'PARAM', proto => 'tcp', dport => '443' },
    ],
    'ICPV2' => [
	"Internet Cache Protocol V2 (Squid) traffic",
	{ action => 'PARAM', proto => 'udp', dport => '3130' },
    ],
    'ICQ' => [
	"AOL Instant Messenger traffic",
	{ action => 'PARAM', proto => 'tcp', dport => '5190' },
    ],
    'IMAP' => [
	"Internet Message Access Protocol",
	{ action => 'PARAM', proto => 'tcp', dport => '143' },
    ],
    'IMAPS' => [
	"Internet Message Access Protocol over SSL",
	{ action => 'PARAM', proto => 'tcp', dport => '993' },
    ],
    'IPIP' => [
	"IPIP capsulation traffic",
	{ action => 'PARAM', proto => '94' },
    ],
    'IPsec' => [
	"IPsec traffic",
	{ action => 'PARAM', proto => 'udp', dport => '500', sport => '500' },
	{ action => 'PARAM', proto => '50' },
    ],
    'IPsecah' => [
	"IPsec authentication (AH) traffic",
	{ action => 'PARAM', proto => 'udp', dport => '500', sport => '500' },
	{ action => 'PARAM', proto => '51' },
    ],
    'IPsecnat' => [
	"IPsec traffic and Nat-Traversal",
	{ action => 'PARAM', proto => 'udp', dport => '500' },
	{ action => 'PARAM', proto => 'udp', dport => '4500' },
	{ action => 'PARAM', proto => '50' },
    ],
    'IRC' => [
	"Internet Relay Chat traffic",
	{ action => 'PARAM', proto => 'tcp', dport => '6667' },
    ],
    'Jetdirect' => [
	"HP Jetdirect printing",
	{ action => 'PARAM', proto => 'tcp', dport => '9100' },
    ],
    'L2TP' => [
	"Layer 2 Tunneling Protocol traffic",
	{ action => 'PARAM', proto => 'udp', dport => '1701' },
    ],
    'LDAP' => [
	"Lightweight Directory Access Protocol traffic",
	{ action => 'PARAM', proto => 'tcp', dport => '389' },
    ],
    'LDAPS' => [
	"Secure Lightweight Directory Access Protocol traffic",
	{ action => 'PARAM', proto => 'tcp', dport => '636' },
    ],
    'MSNP' => [
	"Microsoft Notification Protocol",
	{ action => 'PARAM', proto => 'tcp', dport => '1863' },
    ],
    'MSSQL' => [
	"Microsoft SQL Server",
	{ action => 'PARAM', proto => 'tcp', dport => '1433' },
    ],
    'Mail' => [
	"Mail traffic (SMTP, SMTPS, Submission)",
	{ action => 'PARAM', proto => 'tcp', dport => '25' },
	{ action => 'PARAM', proto => 'tcp', dport => '465' },
	{ action => 'PARAM', proto => 'tcp', dport => '587' },
    ],
    'MDNS' => [
	"Multicast DNS",
	{ action => 'PARAM', proto => 'udp', dport => '5353' },
    ],
    'Munin' => [
	"Munin networked resource monitoring traffic",
	{ action => 'PARAM', proto => 'tcp', dport => '4949' },
    ],
    'MySQL' => [
	"MySQL server",
	{ action => 'PARAM', proto => 'tcp', dport => '3306' },
    ],
    'NNTP' => [
	"NNTP traffic (Usenet).",
	{ action => 'PARAM', proto => 'tcp', dport => '119' },
    ],
    'NNTPS' => [
	"Encrypted NNTP traffic (Usenet)",
	{ action => 'PARAM', proto => 'tcp', dport => '563' },
    ],
    'NTP' => [
	"Network Time Protocol (ntpd)",
	{ action => 'PARAM', proto => 'udp', dport => '123' },
    ],
    'OSPF' => [
	"OSPF multicast traffic",
	{ action => 'PARAM', proto => '89' },
    ],
    'OpenVPN' => [
	"OpenVPN traffic",
	{ action => 'PARAM', proto => 'udp', dport => '1194' },
    ],
    'PCA' => [
	"Symantec PCAnywere (tm)",
	{ action => 'PARAM', proto => 'udp', dport => '5632' },
	{ action => 'PARAM', proto => 'tcp', dport => '5631' },
    ],
    'PMG' => [
	"Proxmox Mail Gateway web interface",
	{ action => 'PARAM', proto => 'tcp', dport => '8006' },
    ],
    'POP3' => [
	"POP3 traffic",
	{ action => 'PARAM', proto => 'tcp', dport => '110' },
    ],
    'POP3S' => [
	"Encrypted POP3 traffic",
	{ action => 'PARAM', proto => 'tcp', dport => '995' },
    ],
    'PPtP' => [
	"Point-to-Point Tunneling Protocol",
	{ action => 'PARAM', proto => '47' },
	{ action => 'PARAM', proto => 'tcp', dport => '1723' },
    ],
    'Ping' => [
	"ICMP echo request",
	{ action => 'PARAM', proto => 'icmp', dport => 'echo-request' },
    ],
    'PostgreSQL' => [
	"PostgreSQL server",
	{ action => 'PARAM', proto => 'tcp', dport => '5432' },
    ],
    'Printer' => [
	"Line Printer protocol printing",
	{ action => 'PARAM', proto => 'tcp', dport => '515' },
    ],
    'RDP' => [
	"Microsoft Remote Desktop Protocol traffic",
	{ action => 'PARAM', proto => 'tcp', dport => '3389' },
    ],
    'RIP' => [
	"Routing Information Protocol (bidirectional)",
	{ action => 'PARAM', proto => 'udp', dport => '520' },
    ],
    'RNDC' => [
	"BIND remote management protocol",
	{ action => 'PARAM', proto => 'tcp', dport => '953' },
    ],
    'Razor' => [
	"Razor Antispam System",
	{ action => 'PARAM', proto => 'tcp', dport => '2703' },
    ],
    'Rdate' => [
	"Remote time retrieval (rdate)",
	{ action => 'PARAM', proto => 'tcp', dport => '37' },
    ],
    'Rsync' => [
	"Rsync server",
	{ action => 'PARAM', proto => 'tcp', dport => '873' },
    ],
    'SANE' => [
	"SANE network scanning",
	{ action => 'PARAM', proto => 'tcp', dport => '6566' },
    ],
    'SMB' => [
	"Microsoft SMB traffic",
	{ action => 'PARAM', proto => 'udp', dport => '135,445' },
	{ action => 'PARAM', proto => 'udp', dport => '137:139' },
	{ action => 'PARAM', proto => 'udp', dport => '1024:65535', sport => '137' },
	{ action => 'PARAM', proto => 'tcp', dport => '135,139,445' },
    ],
    'SMBswat' => [
	"Samba Web Administration Tool",
	{ action => 'PARAM', proto => 'tcp', dport => '901' },
    ],
    'SMTP' => [
	"Simple Mail Transfer Protocol",
	{ action => 'PARAM', proto => 'tcp', dport => '25' },
    ],
    'SMTPS' => [
	"Encrypted Simple Mail Transfer Protocol",
	{ action => 'PARAM', proto => 'tcp', dport => '465' },
    ],
    'SNMP' => [
	"Simple Network Management Protocol",
	{ action => 'PARAM', proto => 'udp', dport => '161:162' },
	{ action => 'PARAM', proto => 'tcp', dport => '161' },
    ],
    'SPAMD' => [
	"Spam Assassin SPAMD traffic",
	{ action => 'PARAM', proto => 'tcp', dport => '783' },
    ],
    'SSH' => [
	"Secure shell traffic",
	{ action => 'PARAM', proto => 'tcp', dport => '22' },
    ],
    'SVN' => [
	"Subversion server (svnserve)",
	{ action => 'PARAM', proto => 'tcp', dport => '3690' },
    ],
    'SixXS' => [
	"SixXS IPv6 Deployment and Tunnel Broker",
	{ action => 'PARAM', proto => 'tcp', dport => '3874' },
	{ action => 'PARAM', proto => 'udp', dport => '3740' },
	{ action => 'PARAM', proto => '41' },
	{ action => 'PARAM', proto => 'udp', dport => '5072,8374' },
    ],
    'SPICEproxy' => [
	"Proxmox VE SPICE display proxy traffic",
	{ action => 'PARAM', proto => 'tcp', dport => '3128' },
    ],
    'Squid' => [
	"Squid web proxy traffic",
	{ action => 'PARAM', proto => 'tcp', dport => '3128' },
    ],
    'Submission' => [
	"Mail message submission traffic",
	{ action => 'PARAM', proto => 'tcp', dport => '587' },
    ],
    'Syslog' => [
	"Syslog protocol (RFC 5424) traffic",
	{ action => 'PARAM', proto => 'udp', dport => '514' },
	{ action => 'PARAM', proto => 'tcp', dport => '514' },
    ],
    'TFTP' => [
	"Trivial File Transfer Protocol traffic",
	{ action => 'PARAM', proto => 'udp', dport => '69' },
    ],
    'Telnet' => [
	"Telnet traffic",
	{ action => 'PARAM', proto => 'tcp', dport => '23' },
    ],
    'Telnets' => [
	"Telnet over SSL",
	{ action => 'PARAM', proto => 'tcp', dport => '992' },
    ],
    'Time' => [
	"RFC 868 Time protocol",
	{ action => 'PARAM', proto => 'tcp', dport => '37' },
    ],
    'Trcrt' => [
	"Traceroute (for up to 30 hops) traffic",
	{ action => 'PARAM', proto => 'udp', dport => '33434:33524' },
	{ action => 'PARAM', proto => 'icmp', dport => 'echo-request' },
    ],
    'VNC' => [
	"VNC traffic for VNC display's 0 - 99",
	{ action => 'PARAM', proto => 'tcp', dport => '5900:5999' },
    ],
    'VNCL' => [
	"VNC traffic from Vncservers to Vncviewers in listen mode",
	{ action => 'PARAM', proto => 'tcp', dport => '5500' },
    ],
    'Web' => [
	"WWW traffic (HTTP and HTTPS)",
	{ action => 'PARAM', proto => 'tcp', dport => '80' },
	{ action => 'PARAM', proto => 'tcp', dport => '443' },
    ],
    'Webcache' => [
	"Web Cache/Proxy traffic (port 8080)",
	{ action => 'PARAM', proto => 'tcp', dport => '8080' },
    ],
    'Webmin' => [
	"Webmin traffic",
	{ action => 'PARAM', proto => 'tcp', dport => '10000' },
    ],
    'Whois' => [
	"Whois (nicname, RFC 3912) traffic",
	{ action => 'PARAM', proto => 'tcp', dport => '43' },
    ],
};

my $pve_fw_parsed_macros;
my $pve_fw_macro_descr;
my $pve_fw_macro_ipversion = {};
my $pve_fw_preferred_macro_names = {};

my $FWACCEPTMARK_ON  = "0x80000000/0x80000000";
my $FWACCEPTMARK_OFF = "0x00000000/0x80000000";

my $pve_std_chains = {};
my $pve_std_chains_conf = {};
$pve_std_chains_conf->{4} = {
    'PVEFW-SET-ACCEPT-MARK' => [
	{ target => "-j MARK --set-mark $FWACCEPTMARK_ON" },
    ],
    'PVEFW-DropBroadcast' => [
	# same as shorewall 'Broadcast'
	# simply DROP BROADCAST/MULTICAST/ANYCAST
	# we can use this to reduce logging
	{ action => 'DROP', dsttype => 'BROADCAST' },
	{ action => 'DROP', dsttype => 'MULTICAST' },
	{ action => 'DROP', dsttype => 'ANYCAST' },
	{ action => 'DROP', dest => '224.0.0.0/4' },
    ],
    'PVEFW-reject' => [
	# same as shorewall 'reject'
	{ action => 'DROP', dsttype => 'BROADCAST' },
	{ action => 'DROP', source => '224.0.0.0/4' },
	{ action => 'DROP', proto => 'icmp' },
	{ match => '-p tcp', target => '-j REJECT --reject-with tcp-reset' },
	{ match => '-p udp', target => '-j REJECT --reject-with icmp-port-unreachable' },
	{ match => '-p icmp', target => '-j REJECT --reject-with icmp-host-unreachable' },
	{ target => '-j REJECT --reject-with icmp-host-prohibited' },
    ],
    'PVEFW-Drop' => [
	# same as shorewall 'Drop', which is equal to DROP,
	# but REJECT/DROP some packages to reduce logging,
	# and ACCEPT critical ICMP types
	# we are not interested in BROADCAST/MULTICAST/ANYCAST
	{ action => 'PVEFW-DropBroadcast' },
	# ACCEPT critical ICMP types
	{ action => 'ACCEPT', proto => 'icmp', dport => 'fragmentation-needed' },
	{ action => 'ACCEPT', proto => 'icmp', dport => 'time-exceeded' },
	# Drop packets with INVALID state
	{ action => 'DROP', match => '-m conntrack --ctstate INVALID', },
	# Drop Microsoft SMB noise
	{ action => 'DROP', proto => 'udp', dport => '135,445' },
	{ action => 'DROP', proto => 'udp', dport => '137:139' },
	{ action => 'DROP', proto => 'udp', dport => '1024:65535', sport => 137 },
	{ action => 'DROP', proto => 'tcp', dport => '135,139,445' },
	{ action => 'DROP', proto => 'udp', dport => 1900 }, # UPnP
	# Drop new/NotSyn traffic so that it doesn't get logged
	{ action => 'DROP', match => '-p tcp -m tcp ! --tcp-flags FIN,SYN,RST,ACK SYN' },
	# Drop DNS replies
	{ action => 'DROP', proto => 'udp', sport => 53 },
    ],
    'PVEFW-Reject' => [
	# same as shorewall 'Reject', which is equal to Reject,
	# but REJECT/DROP some packages to reduce logging,
	# and ACCEPT critical ICMP types
	# we are not interested in BROADCAST/MULTICAST/ANYCAST
	{ action => 'PVEFW-DropBroadcast' },
	# ACCEPT critical ICMP types
	{ action => 'ACCEPT', proto => 'icmp', dport => 'fragmentation-needed' },
	{ action => 'ACCEPT', proto => 'icmp', dport => 'time-exceeded' },
	# Drop packets with INVALID state
	{ action => 'DROP', match => '-m conntrack --ctstate INVALID', },
	# Drop Microsoft SMB noise
	{ action => 'PVEFW-reject', proto => 'udp', dport => '135,445' },
	{ action => 'PVEFW-reject', proto => 'udp', dport => '137:139'},
	{ action => 'PVEFW-reject', proto => 'udp', dport => '1024:65535', sport => 137 },
	{ action => 'PVEFW-reject', proto => 'tcp', dport => '135,139,445' },
	{ action => 'DROP', proto => 'udp', dport => 1900 }, # UPnP
	# Drop new/NotSyn traffic so that it doesn't get logged
	{ action => 'DROP', match => '-p tcp -m tcp ! --tcp-flags FIN,SYN,RST,ACK SYN' },
	# Drop DNS replies
	{ action => 'DROP', proto => 'udp', sport => 53 },
    ],
    'PVEFW-tcpflags' => [
	# same as shorewall tcpflags action.
	# Packets arriving on this interface are checked for some illegal combinations of TCP flags
	{ match => '-p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,PSH,URG', target => '-g PVEFW-logflags' },
	{ match => '-p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE', target => '-g PVEFW-logflags' },
	{ match => '-p tcp -m tcp --tcp-flags SYN,RST SYN,RST', target => '-g PVEFW-logflags' },
	{ match => '-p tcp -m tcp --tcp-flags FIN,SYN FIN,SYN', target => '-g PVEFW-logflags' },
	{ match => '-p tcp -m tcp --sport 0 --tcp-flags FIN,SYN,RST,ACK SYN', target => '-g PVEFW-logflags' },
    ],
    'PVEFW-smurfs' => [
	# same as shorewall smurfs action
	# Filter packets for smurfs (packets with a broadcast address as the source).
	{ match => '-s 0.0.0.0/32', target => '-j RETURN' }, # allow DHCP
	{ match => '-m addrtype --src-type BROADCAST', target => '-g PVEFW-smurflog' },
	{ match => '-s 224.0.0.0/4', target => '-g PVEFW-smurflog' },
    ],
    'PVEFW-smurflog' => [
	{ action => 'DROP', logmsg => 'DROP: ' },
    ],
    'PVEFW-logflags' => [
	{ action => 'DROP', logmsg => 'DROP: ' },
    ],
};

$pve_std_chains_conf->{6} = {
    'PVEFW-SET-ACCEPT-MARK' => [
	{ target => "-j MARK --set-mark $FWACCEPTMARK_ON" },
    ],
    'PVEFW-DropBroadcast' => [
	# same as shorewall 'Broadcast'
	# simply DROP BROADCAST/MULTICAST/ANYCAST
	# we can use this to reduce logging
	#{ action => 'DROP', dsttype => 'BROADCAST' }, #no broadcast in ipv6
	# ipv6 addrtype does not work with kernel 2.6.32
	#{ action => 'DROP', dsttype => 'MULTICAST' },
	#{ action => 'DROP', dsttype => 'ANYCAST' },
	{ action => 'DROP', dest => 'ff00::/8' },
	#{ action => 'DROP', dest => '224.0.0.0/4' },
    ],
    'PVEFW-reject' => [
	{ action => 'DROP', proto => 'icmpv6' },
	{ match => '-p tcp', target => '-j REJECT --reject-with tcp-reset' },
	{ match => '-p udp', target => '-j REJECT --reject-with icmp6-port-unreachable' },
	{ target => '-j REJECT --reject-with icmp6-adm-prohibited' },
    ],
    'PVEFW-Drop' => [
	# same as shorewall 'Drop', which is equal to DROP,
	# but REJECT/DROP some packages to reduce logging,
	# and ACCEPT critical ICMP types
	{ action => 'PVEFW-reject', proto => 'tcp', dport => '43' }, # REJECT 'auth'
	# we are not interested in BROADCAST/MULTICAST/ANYCAST
	{ action => 'PVEFW-DropBroadcast' },
	# ACCEPT critical ICMP types
	{ action => 'ACCEPT', proto => 'icmpv6', dport => 'destination-unreachable' },
	{ action => 'ACCEPT', proto => 'icmpv6', dport => 'time-exceeded' },
	{ action => 'ACCEPT', proto => 'icmpv6', dport => 'packet-too-big' },
	# Drop packets with INVALID state
	{ action => 'DROP', match => '-m conntrack --ctstate INVALID', },
	# Drop Microsoft SMB noise
	{ action => 'DROP', proto => 'udp', dport => '135,445' },
	{ action => 'DROP', proto => 'udp', dport => '137:139'},
	{ action => 'DROP', proto => 'udp', dport => '1024:65535', sport => 137 },
	{ action => 'DROP', proto => 'tcp', dport => '135,139,445' },
	{ action => 'DROP', proto => 'udp', dport => 1900 }, # UPnP
	# Drop new/NotSyn traffic so that it doesn't get logged
	{ action => 'DROP', match => '-p tcp -m tcp ! --tcp-flags FIN,SYN,RST,ACK SYN' },
	# Drop DNS replies
	{ action => 'DROP', proto => 'udp', sport => 53 },
    ],
    'PVEFW-Reject' => [
	# same as shorewall 'Reject', which is equal to Reject,
	# but REJECT/DROP some packages to reduce logging,
	# and ACCEPT critical ICMP types
	{ action => 'PVEFW-reject',  proto => 'tcp', dport => '43' }, # REJECT 'auth'
	# we are not interested in BROADCAST/MULTICAST/ANYCAST
	{ action => 'PVEFW-DropBroadcast' },
	# ACCEPT critical ICMP types
	{ action => 'ACCEPT', proto => 'icmpv6', dport => 'destination-unreachable' },
	{ action => 'ACCEPT', proto => 'icmpv6', dport => 'time-exceeded' },
	{ action => 'ACCEPT', proto => 'icmpv6', dport => 'packet-too-big' },
	# Drop packets with INVALID state
	{ action => 'DROP', match => '-m conntrack --ctstate INVALID', },
	# Drop Microsoft SMB noise
	{ action => 'PVEFW-reject', proto => 'udp', dport => '135,445' },
	{ action => 'PVEFW-reject', proto => 'udp', dport => '137:139' },
	{ action => 'PVEFW-reject', proto => 'udp', dport => '1024:65535', sport => 137 },
	{ action => 'PVEFW-reject', proto => 'tcp', dport => '135,139,445' },
	{ action => 'DROP', proto => 'udp', dport => 1900 }, # UPnP
	# Drop new/NotSyn traffic so that it doesn't get logged
	{ action => 'DROP', match => '-p tcp -m tcp ! --tcp-flags FIN,SYN,RST,ACK SYN' },
	# Drop DNS replies
	{ action => 'DROP', proto => 'udp', sport => 53 },
    ],
    'PVEFW-tcpflags' => [
	# same as shorewall tcpflags action.
	# Packets arriving on this interface are checked for some illegal combinations of TCP flags
	{ match => '-p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,PSH,URG', target => '-g PVEFW-logflags' },
	{ match => '-p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE', target => '-g PVEFW-logflags' },
	{ match => '-p tcp -m tcp --tcp-flags SYN,RST SYN,RST', target => '-g PVEFW-logflags' },
	{ match => '-p tcp -m tcp --tcp-flags FIN,SYN FIN,SYN', target => '-g PVEFW-logflags' },
	{ match => '-p tcp -m tcp --sport 0 --tcp-flags FIN,SYN,RST,ACK SYN', target => '-g PVEFW-logflags' },
    ],
    'PVEFW-logflags' => [
	{ action => 'DROP', logmsg => 'DROP: ' },
    ],
};

# iptables -p icmp -h
my $icmp_type_names = {
    any => 1,
    'echo-reply' => 1,
    'destination-unreachable' => 1,
    'network-unreachable' => 1,
    'host-unreachable' => 1,
    'protocol-unreachable' => 1,
    'port-unreachable' => 1,
    'fragmentation-needed' => 1,
    'source-route-failed' => 1,
    'network-unknown' => 1,
    'host-unknown' => 1,
    'network-prohibited' => 1,
    'host-prohibited' => 1,
    'TOS-network-unreachable' => 1,
    'TOS-host-unreachable' => 1,
    'communication-prohibited' => 1,
    'host-precedence-violation' => 1,
    'precedence-cutoff' => 1,
    'source-quench' => 1,
    'redirect' => 1,
    'network-redirect' => 1,
    'host-redirect' => 1,
    'TOS-network-redirect' => 1,
    'TOS-host-redirect' => 1,
    'echo-request' => 1,
    'router-advertisement' => 1,
    'router-solicitation' => 1,
    'time-exceeded' => 1,
    'ttl-zero-during-transit' => 1,
    'ttl-zero-during-reassembly' => 1,
    'parameter-problem' => 1,
    'ip-header-bad' => 1,
    'required-option-missing' => 1,
    'timestamp-request' => 1,
    'timestamp-reply' => 1,
    'address-mask-request' => 1,
    'address-mask-reply' => 1,
};

# ip6tables -p icmpv6 -h

my $icmpv6_type_names = {
    'destination-unreachable' => 1,
    'no-route' => 1,
    'communication-prohibited' => 1,
    'beyond-scope' => 1,
    'address-unreachable' => 1,
    'port-unreachable' => 1,
    'failed-policy' => 1,
    'reject-route' => 1,
    'packet-too-big' => 1,
    'time-exceeded' => 1,
    'ttl-zero-during-transit' => 1,
    'ttl-zero-during-reassembly' => 1,
    'parameter-problem' => 1,
    'bad-header' => 1,
    'unknown-header-type' => 1,
    'unknown-option' => 1,
    'echo-request' => 1,
    'echo-reply' => 1,
    'router-solicitation' => 1,
    'router-advertisement' => 1,
    'neighbor-solicitation' => 1,
    'neighbour-solicitation' => 1,
    'neighbor-advertisement' => 1,
    'neighbour-advertisement' => 1,
    'redirect' => 1,
};

my $is_valid_icmp_type = sub {
    my ($type, $valid_types) = @_;

    if ($type =~ m/^\d+$/) {
	# values for icmp-type range between 0 and 255 (8 bit field)
	die "invalid icmp-type '$type'\n" if $type > 255;
    } else {
	die "unknown icmp-type '$type'\n" if !defined($valid_types->{$type});
    }
};

sub init_firewall_macros {

    $pve_fw_parsed_macros = {};

    my $parse = sub {
	my ($k, $macro) = @_;
	my $lc_name = lc($k);
	$pve_fw_macro_ipversion->{$k} = 0;
	while (!ref($macro->[0])) {
	    my $desc = shift @$macro;
	    if ($desc eq 'ipv4only') {
		$pve_fw_macro_ipversion->{$k} = 4;
	    } elsif ($desc eq 'ipv6only') {
		$pve_fw_macro_ipversion->{$k} = 6;
	    } else {
		$pve_fw_macro_descr->{$k} = $desc;
	    }
	}
	$pve_fw_preferred_macro_names->{$lc_name} = $k;
	$pve_fw_parsed_macros->{$k} = $macro;
    };

    foreach my $k (keys %$pve_fw_macros) {
	&$parse($k, $pve_fw_macros->{$k});
    }

    foreach my $k (keys %$pve_ipv6fw_macros) {
	next if $pve_fw_parsed_macros->{$k};
	&$parse($k, $pve_ipv6fw_macros->{$k});
	$pve_fw_macro_ipversion->{$k} = 6;
    }
}

init_firewall_macros();

sub get_macros {
    return wantarray ? ($pve_fw_parsed_macros, $pve_fw_macro_descr): $pve_fw_parsed_macros;
}

my $etc_services;

sub get_etc_services {

    return $etc_services if $etc_services;

    my $filename = "/etc/services";

    my $fh = IO::File->new($filename, O_RDONLY);
    if (!$fh) {
	warn "unable to read '$filename' - $!\n";
	return {};
    }

    my $services = {};

    while (my $line = <$fh>) {
	chomp ($line);
	next if $line =~m/^#/;
	next if ($line =~m/^\s*$/);

	if ($line =~ m!^(\S+)\s+(\S+)/(tcp|udp|sctp).*$!) {
	    $services->{byid}->{$2}->{name} = $1;
	    $services->{byid}->{$2}->{port} = $2;
	    $services->{byid}->{$2}->{$3} = 1;
	    $services->{byname}->{$1} = $services->{byid}->{$2};
	}
    }

    close($fh);

    $etc_services = $services;


    return $etc_services;
}

sub parse_protocol_file {
    my ($filename) = @_;

    my $fh = IO::File->new($filename, O_RDONLY);
    if (!$fh) {
	warn "unable to read '$filename' - $!\n";
	return {};
    }

    my $protocols = {};

    while (my $line = <$fh>) {
	chomp ($line);
	next if $line =~m/^#/;
	next if ($line =~m/^\s*$/);

	if ($line =~ m!^(\S+)\s+(\d+)(?:\s+.*)?$!) {
	    $protocols->{byid}->{$2}->{name} = $1;
	    $protocols->{byname}->{$1} = $protocols->{byid}->{$2};
	}
    }

    close($fh);

    return $protocols;
}

my $etc_protocols;

sub get_etc_protocols {
    return $etc_protocols if $etc_protocols;

    my $protocols = parse_protocol_file('/etc/protocols');

    # add special case for ICMP v6
    $protocols->{byid}->{icmpv6}->{name} = "icmpv6";
    $protocols->{byname}->{icmpv6} = $protocols->{byid}->{icmpv6};

    $etc_protocols = $protocols;

    return $etc_protocols;
}

my $etc_ethertypes;

sub get_etc_ethertypes {
    $etc_ethertypes = parse_protocol_file('/etc/ethertypes')
	if !$etc_ethertypes;
    return $etc_ethertypes;
}

my $__local_network;

sub local_network {
    my ($new_value) = @_;

    $__local_network = $new_value if defined($new_value);

    return $__local_network if defined($__local_network);

    eval {
	my $nodename = PVE::INotify::nodename();

	my $ip = PVE::Cluster::remote_node_ip($nodename);

	my $testip = Net::IP->new($ip);

	my $isv6 = $testip->version == 6;
	my $routes = $isv6 ? PVE::ProcFSTools::read_proc_net_ipv6_route()
	                   : PVE::ProcFSTools::read_proc_net_route();
	foreach my $entry (@$routes) {
	    my $mask;
	    if ($isv6) {
		$mask = $entry->{prefix};
		next if !$mask; # skip the default route...
	    } else {
		$mask = $PVE::Network::ipv4_mask_hash_localnet->{$entry->{mask}};
		next if !defined($mask);
	    }
	    my $cidr = "$entry->{dest}/$mask";
	    my $testnet = Net::IP->new($cidr);
	    my $overlap = $testnet->overlaps($testip);
	    if ($overlap == $Net::IP::IP_B_IN_A_OVERLAP ||
	        $overlap == $Net::IP::IP_IDENTICAL)
	    {
		$__local_network = $cidr;
		return;
	    }
	}
    };
    warn $@ if $@;

    return $__local_network;
}

# ipset names are limited to 31 characters,
# and we use '-v4' or '-v6' to indicate IP versions,
# and we use '_swap' suffix for atomic update,
# for example PVEFW-${VMID}-${ipset_name}_swap

my $max_iptables_ipset_name_length = 31 - length("PVEFW-") - length("_swap");

sub compute_ipset_chain_name {
    my ($vmid, $ipset_name, $ipversion) = @_;

    $vmid = 0 if !defined($vmid);

    my $id = "$vmid-${ipset_name}-v$ipversion";

    if (length($id) > $max_iptables_ipset_name_length) {
	$id = PVE::Tools::fnv31a_hex($id);
    }

    return "PVEFW-$id";
}

sub compute_ipfilter_ipset_name {
    my ($iface) = @_;

    return "ipfilter-$iface";
}

sub parse_address_list {
    my ($str) = @_;

    if ($str =~ m/^(\+)(\S+)$/) { # ipset ref
	die "ipset name too long\n" if length($str) > ($max_ipset_name_length + 1);
	return;
    }

    if ($str =~ m/^${ip_alias_pattern}$/) {
	die "alias name too long\n" if length($str) > $max_alias_name_length;
	return;
    }

    my $count = 0;
    my $iprange = 0;
    my $ipversion;

    my @elements = split(/,/, $str);
    die "extraneous commas in list\n" if $str ne join(',', @elements);
    foreach my $elem (@elements) {
	$count++;
	my $ip = Net::IP->new($elem);
	if (!$ip) {
	    my $err = Net::IP::Error();
	    die "invalid IP address: $err\n";
	}
	$iprange = 1 if $elem =~ m/-/;

	my $new_ipversion = Net::IP::ip_is_ipv6($ip->ip()) ? 6 : 4;

	die "detected mixed ipv4/ipv6 addresses in address list '$str'\n"
	    if $ipversion && ($new_ipversion != $ipversion);

	$ipversion = $new_ipversion;
    }

    die "you can't use a range in a list\n" if $iprange && $count > 1;

    return $ipversion;
}

sub parse_port_name_number_or_range {
    my ($str, $dport) = @_;

    my $services = PVE::Firewall::get_etc_services();
    my $count = 0;
    my $icmp_port = 0;

    my @elements = split(/,/, $str);
    die "extraneous commas in list\n" if $str ne join(',', @elements);
    foreach my $item (@elements) {
	if ($item =~ m/^([0-9]+):([0-9]+)$/) {
	    $count += 2;
	    my ($port1, $port2) = ($1, $2);
	    die "invalid port '$port1'\n" if $port1 > 65535;
	    die "invalid port '$port2'\n" if $port2 > 65535;
	    die "backwards range '$port1:$port2' not allowed, did you mean '$port2:$port1'?\n" if $port1 > $port2;
	} elsif ($item =~ m/^([0-9]+)$/) {
	    $count += 1;
	    my $port = $1;
	    die "invalid port '$port'\n" if $port > 65535;
	} else {
	    if ($dport && $icmp_type_names->{$item}) {
		$icmp_port = 1;
	    } elsif ($dport && $icmpv6_type_names->{$item}) {
		$icmp_port = 1;
	    } else {
		die "invalid port '$item'\n" if !$services->{byname}->{$item};
	    }
	}
    }

    die "ICMP ports not allowed in port range\n" if $icmp_port && $count > 0;

    # I really don't like to use the word number here, but it's the only thing
    # that makes sense in a literal way. The range 1:100 counts as 2, not as
    # one and not as 100...
    die "too many entries in port list (> 15 numbers)\n"
	if $count > 15;

    return (scalar(@elements) > 1);
}

PVE::JSONSchema::register_format('pve-fw-sport-spec', \&pve_fw_verify_sport_spec);
sub pve_fw_verify_sport_spec {
   my ($portstr) = @_;

   parse_port_name_number_or_range($portstr, 0);

   return $portstr;
}

PVE::JSONSchema::register_format('pve-fw-dport-spec', \&pve_fw_verify_dport_spec);
sub pve_fw_verify_dport_spec {
   my ($portstr) = @_;

   parse_port_name_number_or_range($portstr, 1);

   return $portstr;
}

PVE::JSONSchema::register_format('pve-fw-addr-spec', \&pve_fw_verify_addr_spec);
sub pve_fw_verify_addr_spec {
   my ($list) = @_;

   parse_address_list($list);

   return $list;
}

PVE::JSONSchema::register_format('pve-fw-protocol-spec', \&pve_fw_verify_protocol_spec);
sub pve_fw_verify_protocol_spec {
   my ($proto) = @_;

   my $protocols = get_etc_protocols();

   die "unknown protocol '$proto'\n" if $proto &&
       !(defined($protocols->{byname}->{$proto}) ||
	 defined($protocols->{byid}->{$proto}));

   return $proto;
}

PVE::JSONSchema::register_format('pve-fw-icmp-type-spec', \&pve_fw_verify_icmp_type_spec);
sub pve_fw_verify_icmp_type_spec {
    my ($icmp_type) = @_;

    if ($icmp_type_names->{$icmp_type} ||  $icmpv6_type_names->{$icmp_type}) {
	return $icmp_type;
    }

    die "invalid icmp-type value '$icmp_type'\n" if $icmp_type ne '';

    return $icmp_type;
}


# helper function for API

sub copy_opject_with_digest {
    my ($object) = @_;

    my $sha = Digest::SHA->new('sha1');

    my $res = {};
    foreach my $k (sort keys %$object) {
	my $v = $object->{$k};
	next if !defined($v);
	$res->{$k} = $v;
	$sha->add($k, ':', $v, "\n");
    }

    my $digest = $sha->hexdigest;

    $res->{digest} = $digest;

    return wantarray ? ($res, $digest) : $res;
}

sub copy_list_with_digest {
    my ($list) = @_;

    my $sha = Digest::SHA->new('sha1');

    my $res = [];
    foreach my $entry (@$list) {
	my $data = {};
	foreach my $k (sort keys %$entry) {
	    my $v = $entry->{$k};
	    next if !defined($v);
	    $data->{$k} = $v;
	    # Note: digest ignores refs ($rule->{errors})
	    # since Digest::SHA expects a series of bytes,
	    #  we have to encode the value here to prevent errors when
	    #  using utf8 characters (eg. in comments)
	    $sha->add($k, ':', encode_utf8($v), "\n") if !ref($v); ;
	}
	push @$res, $data;
    }

    my $digest = $sha->hexdigest;

    foreach my $entry (@$res) {
	$entry->{digest} = $digest;
    }

    return wantarray ? ($res, $digest) : $res;
}

our $cluster_option_properties = {
    enable => {
	description => "Enable or disable the firewall cluster wide.",
	type => 'integer',
	minimum => 0,
	optional => 1,
    },
    ebtables => {
	description => "Enable ebtables rules cluster wide.",
	type => 'boolean',
	default => 1,
	optional => 1,
    },
    policy_in => {
	description => "Input policy.",
	type => 'string',
	optional => 1,
	enum => ['ACCEPT', 'REJECT', 'DROP'],
    },
    policy_out => {
	description => "Output policy.",
	type => 'string',
	optional => 1,
	enum => ['ACCEPT', 'REJECT', 'DROP'],
    },
    log_ratelimit => {
	description => "Log ratelimiting settings",
	type => 'string', format => {
	    enable => {
		default_key => 1,
		description => 'Enable or disable log rate limiting',
		type => 'boolean',
		default => '1',
	    },
	    rate => {
		type => 'string',
		description => 'Frequency with which the burst bucket gets refilled',
		optional => 1,
		pattern => '[1-9][0-9]*\/(second|minute|hour|day)',
		format_description => 'rate',
		default => '1/second',
	    },
	    burst => {
		type => 'integer',
		minimum => 0,
		optional => 1,
		description => 'Initial burst of packages which will always get logged before the rate is applied',
		default => 5,
	    },
	},
	optional => 1,
    },
};

our $host_option_properties = {
    enable => {
	description => "Enable host firewall rules.",
	type => 'boolean',
	optional => 1,
    },
    log_level_in =>  get_standard_option('pve-fw-loglevel', {
	description => "Log level for incoming traffic." }),
    log_level_out =>  get_standard_option('pve-fw-loglevel', {
	description => "Log level for outgoing traffic." }),
    tcp_flags_log_level =>  get_standard_option('pve-fw-loglevel', {
	description => "Log level for illegal tcp flags filter." }),
    smurf_log_level =>  get_standard_option('pve-fw-loglevel', {
	description => "Log level for SMURFS filter." }),
    nosmurfs => {
	description => "Enable SMURFS filter.",
	type => 'boolean',
	optional => 1,
    },
    tcpflags => {
	description => "Filter illegal combinations of TCP flags.",
	type => 'boolean',
	default => 0,
	optional => 1,
    },
    nf_conntrack_max => {
	description => "Maximum number of tracked connections.",
	type => 'integer',
	optional => 1,
	default => 262144,
	minimum => 32768,
    },
    nf_conntrack_tcp_timeout_established => {
	description => "Conntrack established timeout.",
	type => 'integer',
	optional => 1,
	default => 432000,
	minimum => 7875,
    },
    nf_conntrack_tcp_timeout_syn_recv => {
	description => "Conntrack syn recv timeout.",
	type => 'integer',
	optional => 1,
	default => 60,
	minimum => 30,
	maximum => 60,
    },
    ndp => {
	description => "Enable NDP (Neighbor Discovery Protocol).",
	type => 'boolean',
	default => 0,
	optional => 1,
    },
    nf_conntrack_allow_invalid => {
	description => "Allow invalid packets on connection tracking.",
	type => 'boolean',
	default => 0,
	optional => 1,
    },
    protection_synflood => {
	description => "Enable synflood protection",
	type => 'boolean',
	default => 0,
	optional => 1,
    },
    protection_synflood_rate => {
	description => "Synflood protection rate syn/sec by ip src.",
	type => 'integer',
	optional => 1,
	default => 200,
    },
    protection_synflood_burst => {
	description => "Synflood protection rate burst by ip src.",
	type => 'integer',
	optional => 1,
	default => 1000,
    },
    log_nf_conntrack => {
	description => "Enable logging of conntrack information.",
	type => 'boolean',
	default => 0,
	optional => 1
    },
};

our $vm_option_properties = {
    enable => {
	description => "Enable/disable firewall rules.",
	type => 'boolean',
	default => 0,
	optional => 1,
    },
    macfilter => {
	description => "Enable/disable MAC address filter.",
	type => 'boolean',
	default => 1,
	optional => 1,
    },
    dhcp => {
	description => "Enable DHCP.",
	type => 'boolean',
	default => 0,
	optional => 1,
    },
    ndp => {
	description => "Enable NDP (Neighbor Discovery Protocol).",
	type => 'boolean',
	default => 0,
	optional => 1,
    },
    radv => {
	description => "Allow sending Router Advertisement.",
	type => 'boolean',
	optional => 1,
    },
    ipfilter => {
	description => "Enable default IP filters. " .
	   "This is equivalent to adding an empty ipfilter-net<id> ipset " .
	   "for every interface. Such ipsets implicitly contain sane default " .
	   "restrictions such as restricting IPv6 link local addresses to " .
	   "the one derived from the interface's MAC address. For containers " .
	   "the configured IP addresses will be implicitly added.",
	type => 'boolean',
	optional => 1,
    },
    policy_in => {
	description => "Input policy.",
	type => 'string',
	optional => 1,
	enum => ['ACCEPT', 'REJECT', 'DROP'],
    },
    policy_out => {
	description => "Output policy.",
	type => 'string',
	optional => 1,
	enum => ['ACCEPT', 'REJECT', 'DROP'],
    },
    log_level_in =>  get_standard_option('pve-fw-loglevel', {
	description => "Log level for incoming traffic." }),
    log_level_out =>  get_standard_option('pve-fw-loglevel', {
	description => "Log level for outgoing traffic." }),

};


my $addr_list_descr = "This can refer to a single IP address, an IP set ('+ipsetname') or an IP alias definition. You can also specify an address range like '20.34.101.207-201.3.9.99', or a list of IP addresses and networks (entries are separated by comma). Please do not mix IPv4 and IPv6 addresses inside such lists.";

my $port_descr = "You can use service names or simple numbers (0-65535), as defined in '/etc/services'. Port ranges can be specified with '\\d+:\\d+', for example '80:85', and you can use comma separated list to match several ports or ranges.";

my $rule_properties = {
    pos => {
	description => "Update rule at position <pos>.",
	type => 'integer',
	minimum => 0,
	optional => 1,
    },
    digest => get_standard_option('pve-config-digest'),
    type => {
	description => "Rule type.",
	type => 'string',
	optional => 1,
	enum => ['in', 'out', 'group'],
    },
    action => {
	description => "Rule action ('ACCEPT', 'DROP', 'REJECT') or security group name.",
	type => 'string',
	optional => 1,
	pattern => $security_group_name_pattern,
	maxLength => 20,
	minLength => 2,
    },
    macro => {
	description => "Use predefined standard macro.",
	type => 'string',
	optional => 1,
	maxLength => 128,
    },
    iface => get_standard_option('pve-iface', {
	description => "Network interface name. You have to use network configuration key names for VMs and containers ('net\\d+'). Host related rules can use arbitrary strings.",
	optional => 1
    }),
    source => {
	description => "Restrict packet source address. $addr_list_descr",
	type => 'string', format => 'pve-fw-addr-spec',
	optional => 1,
	maxLength => 512,
    },
    dest => {
	description => "Restrict packet destination address. $addr_list_descr",
	type => 'string', format => 'pve-fw-addr-spec',
	optional => 1,
	maxLength => 512,
    },
    proto => {
	description => "IP protocol. You can use protocol names ('tcp'/'udp') or simple numbers, as defined in '/etc/protocols'.",
	type => 'string', format => 'pve-fw-protocol-spec',
	optional => 1,
    },
    enable => {
	description => "Flag to enable/disable a rule.",
        type => 'integer',
	minimum => 0,
	optional => 1,
    },
    log => get_standard_option('pve-fw-loglevel', {
	description => "Log level for firewall rule.",
    }),
    sport => {
	description => "Restrict TCP/UDP source port. $port_descr",
	type => 'string', format => 'pve-fw-sport-spec',
	optional => 1,
    },
    dport => {
	description => "Restrict TCP/UDP destination port. $port_descr",
	type => 'string', format => 'pve-fw-dport-spec',
	optional => 1,
    },
    comment => {
	description => "Descriptive comment.",
	type => 'string',
	optional => 1,
    },
    'icmp-type' => {
	description => "Specify icmp-type. Only valid if proto equals 'icmp'.",
	type => 'string', format => 'pve-fw-icmp-type-spec',
	optional => 1,
    },
};

sub add_rule_properties {
    my ($properties) = @_;

    foreach my $k (keys %$rule_properties) {
	my $h = $rule_properties->{$k};
	# copy data, so that we can modify later without side effects
	foreach my $opt (keys %$h) { $properties->{$k}->{$opt} = $h->{$opt}; }
    }

    return $properties;
}

sub delete_rule_properties {
    my ($rule, $delete_str) = @_;

    foreach my $opt (PVE::Tools::split_list($delete_str)) {
	raise_param_exc({ 'delete' => "no such property ('$opt')"})
	    if !defined($rule_properties->{$opt});
	raise_param_exc({ 'delete' => "unable to delete required property '$opt'"})
	    if $opt eq 'type' || $opt eq 'action';
	delete $rule->{$opt};
    }

    return $rule;
}

my $apply_macro = sub {
    my ($macro_name, $param, $verify, $ipversion) = @_;

    my $macro_rules = $pve_fw_parsed_macros->{$macro_name};
    die "unknown macro '$macro_name'\n" if !$macro_rules; # should not happen

    if ($ipversion && ($ipversion == 6) && $pve_ipv6fw_macros->{$macro_name}) {
	$macro_rules = $pve_ipv6fw_macros->{$macro_name};
    }

    # skip macros which are specific to another ipversion
    if ($ipversion && (my $required = $pve_fw_macro_ipversion->{$macro_name})) {
	return if $ipversion != $required;
    }

    my $rules = [];

    foreach my $templ (@$macro_rules) {
	my $rule = {};
	my $param_used = {};
	foreach my $k (keys %$templ) {
	    my $v = $templ->{$k};
	    if ($v eq 'PARAM') {
		$v = $param->{$k};
		$param_used->{$k} = 1;
	    } elsif ($v eq 'DEST') {
		$v = $param->{dest};
		$param_used->{dest} = 1;
	    } elsif ($v eq 'SOURCE') {
		$v = $param->{source};
		$param_used->{source} = 1;
	    }

	    if (!defined($v)) {
		my $msg = "missing parameter '$k' in macro '$macro_name'";
		raise_param_exc({ macro => $msg }) if $verify;
		die "$msg\n";
	    }
	    $rule->{$k} = $v;
	}
	foreach my $k (keys %$param) {
	    next if $k eq 'macro';
	    next if !defined($param->{$k});
	    next if $param_used->{$k};
	    if (defined($rule->{$k})) {
		if ($rule->{$k} ne $param->{$k}) {
		    my $msg = "parameter '$k' already define in macro (value = '$rule->{$k}')";
		    raise_param_exc({ $k => $msg }) if $verify;
		    die "$msg\n";
		}
	    } else {
		$rule->{$k} = $param->{$k};
	    }
	}
	push @$rules, $rule;
    }

    return $rules;
};

my $rule_env_iface_lookup = {
    'ct' => 1,
    'vm' => 1,
    'group' => 0,
    'cluster' => 1,
    'host' => 1,
};

sub verify_rule {
    my ($rule, $cluster_conf, $fw_conf, $rule_env, $noerr) = @_;

    my $allow_groups = $rule_env eq 'group' ? 0 : 1;

    my $allow_iface = $rule_env_iface_lookup->{$rule_env};
    die "unknown rule_env '$rule_env'\n" if !defined($allow_iface); # should not happen

    my $errors = $rule->{errors} || {};

    my $error_count = 0;

    my $add_error = sub {
	my ($param, $msg)  = @_;
	chomp $msg;
	raise_param_exc({ $param => $msg }) if !$noerr;
	$error_count++;
	$errors->{$param} = $msg if !$errors->{$param};
    };

    my $ipversion;
    my $set_ip_version = sub {
	my $vers = shift;
	if ($vers) {
	    die "detected mixed ipv4/ipv6 addresses in rule\n"
		if $ipversion && ($vers != $ipversion);
	    $ipversion = $vers;
	}
    };

    my $check_ipset_or_alias_property = sub {
	my ($name, $expected_ipversion) = @_;

	if (my $value = $rule->{$name}) {
	    if ($value =~ m/^\+/) {
		if ($value =~ m/^\+(${ipset_name_pattern})$/) {
		    &$add_error($name, "no such ipset '$1'")
			if !($cluster_conf->{ipset}->{$1} || ($fw_conf && $fw_conf->{ipset}->{$1}));

		} else {
		    &$add_error($name, "invalid ipset name '$value'");
		}
	    } elsif ($value =~ m/^${ip_alias_pattern}$/){
		my $alias = lc($value);
		&$add_error($name, "no such alias '$value'")
		    if !($cluster_conf->{aliases}->{$alias} || ($fw_conf && $fw_conf->{aliases}->{$alias}));
		my $e = $fw_conf ? $fw_conf->{aliases}->{$alias} : undef;
		$e = $cluster_conf->{aliases}->{$alias} if !$e && $cluster_conf;

		&$set_ip_version($e->{ipversion});
	    }
	}
    };

    my $type = $rule->{type};
    my $action = $rule->{action};

    &$add_error('type', "missing property") if !$type;
    &$add_error('action', "missing property") if !$action;

    if ($type) {
	if ($type eq  'in' || $type eq 'out') {
	    &$add_error('action', "unknown action '$action'")
		if $action && ($action !~ m/^(ACCEPT|DROP|REJECT)$/);
	} elsif ($type eq 'group') {
	    &$add_error('type', "security groups not allowed")
		if !$allow_groups;
	    &$add_error('action', "invalid characters in security group name")
		if $action && ($action !~ m/^${security_group_name_pattern}$/);
	} else {
	    &$add_error('type', "unknown rule type '$type'");
	}
    }

    if ($rule->{iface}) {
	&$add_error('type', "parameter -i not allowed for this rule type")
	    if !$allow_iface;
	eval { PVE::JSONSchema::pve_verify_iface($rule->{iface}); };
	&$add_error('iface', $@) if $@;
    	if ($rule_env eq 'vm' || $rule_env eq 'ct') {
	    &$add_error('iface', "value does not match the regex pattern 'net\\d+'")
		if $rule->{iface} !~  m/^net(\d+)$/;
	}
    }

    if ($rule->{macro}) {
	if (my $preferred_name = $pve_fw_preferred_macro_names->{lc($rule->{macro})}) {
	    $rule->{macro} = $preferred_name;
	} else {
	    &$add_error('macro', "unknown macro '$rule->{macro}'");
	}
    }

    if ($rule->{proto}) {
	eval { pve_fw_verify_protocol_spec($rule->{proto}); };
	&$add_error('proto', $@) if $@;
	&$set_ip_version(4) if $rule->{proto} eq 'icmp';
	&$set_ip_version(6) if $rule->{proto} eq 'icmpv6';
	&$set_ip_version(6) if $rule->{proto} eq 'ipv6-icmp';
    }

    if ($rule->{dport}) {
	eval { parse_port_name_number_or_range($rule->{dport}, 1); };
	&$add_error('dport', $@) if $@;
	my $proto = $rule->{proto};
	&$add_error('proto', "missing property - 'dport' requires this property")
	    if !$proto;
	&$add_error('dport', "protocol '$proto' does not support ports")
	    if !$PROTOCOLS_WITH_PORTS->{$proto} &&
		$proto ne 'icmp' && $proto ne 'icmpv6'; # special cases
    }

    if (my $icmp_type = $rule ->{'icmp-type'}) {
	my $proto = $rule->{proto};
	&$add_error('proto', "missing property - 'icmp-type' requires this property")
	    if $proto ne 'icmp' && $proto ne 'icmpv6' && $proto ne 'ipv6-icmp';
	&$add_error('icmp-type', "'icmp-type' cannot be specified together with 'dport'")
	    if $rule->{dport};
	if ($proto eq 'icmp' && !$icmp_type_names->{$icmp_type}) {
	    &$add_error('icmp-type', "invalid icmp-type '$icmp_type' for proto 'icmp'");
	} elsif (($proto eq 'icmpv6' || $proto eq 'ipv6-icmp') && !$icmpv6_type_names->{$icmp_type}) {
	    &$add_error('icmp-type', "invalid icmp-type '$icmp_type' for proto '$proto'");
	}
    }

    if ($rule->{sport}) {
	eval { parse_port_name_number_or_range($rule->{sport}, 0); };
	&$add_error('sport', $@) if $@;
	my $proto = $rule->{proto};
	&$add_error('proto', "missing property - 'sport' requires this property")
	    if !$proto;
	&$add_error('sport', "protocol '$proto' does not support ports")
	    if !$PROTOCOLS_WITH_PORTS->{$proto};
    }

    if ($rule->{source}) {
	eval {
	    my $source_ipversion = parse_address_list($rule->{source});
	    &$set_ip_version($source_ipversion);
	};
	&$add_error('source', $@) if $@;
	&$check_ipset_or_alias_property('source', $ipversion);
    }

    if ($rule->{dest}) {
	eval {
	    my $dest_ipversion = parse_address_list($rule->{dest});
	    &$set_ip_version($dest_ipversion);
	};
	&$add_error('dest', $@) if $@;
	&$check_ipset_or_alias_property('dest', $ipversion);
    }

    $rule->{ipversion} = $ipversion if $ipversion;

    if ($rule->{macro} && !$error_count) {
	eval { &$apply_macro($rule->{macro}, $rule, 1, $ipversion); };
	if (my $err = $@) {
	    if (ref($err) eq "PVE::Exception" && $err->{errors}) {
		my $eh = $err->{errors};
		foreach my $p (keys %$eh) {
		    &$add_error($p, $eh->{$p});
		}
	    } else {
		&$add_error('macro', "$err");
	    }
	}
    }

    $rule->{errors} = $errors if $error_count;

    return $rule;
}

sub copy_rule_data {
    my ($rule, $param) = @_;

    foreach my $k (keys %$rule_properties) {
	if (defined(my $v = $param->{$k})) {
	    if ($v eq '' || $v eq '-') {
		delete $rule->{$k};
	    } else {
		$rule->{$k} = $v;
	    }
	}
    }

    return $rule;
}

sub rules_modify_permissions {
    my ($rule_env) = @_;

    if ($rule_env eq 'host') {
	return {
	    check => ['perm', '/nodes/{node}', [ 'Sys.Modify' ]],
	};
    } elsif ($rule_env eq 'cluster' || $rule_env eq 'group') {
	return {
	    check => ['perm', '/', [ 'Sys.Modify' ]],
	};
    } elsif ($rule_env eq 'vm' || $rule_env eq 'ct') {
	return {
	    check => ['perm', '/vms/{vmid}', [ 'VM.Config.Network' ]],
	}
    }

    return undef;
}

sub rules_audit_permissions {
    my ($rule_env) = @_;

    if ($rule_env eq 'host') {
	return {
	    check => ['perm', '/nodes/{node}', [ 'Sys.Audit' ]],
	};
    } elsif ($rule_env eq 'cluster' || $rule_env eq 'group') {
	return {
	    check => ['perm', '/', [ 'Sys.Audit' ]],
	};
    } elsif ($rule_env eq 'vm' || $rule_env eq 'ct') {
	return {
	    check => ['perm', '/vms/{vmid}', [ 'VM.Audit' ]],
	}
    }

    return undef;
}

# core functions

sub enable_bridge_firewall {


    PVE::ProcFSTools::write_proc_entry("/proc/sys/net/bridge/bridge-nf-call-iptables", "1");
    PVE::ProcFSTools::write_proc_entry("/proc/sys/net/bridge/bridge-nf-call-ip6tables", "1");

    # make sure syncookies are enabled (which is default on newer 3.X kernels anyways)
    PVE::ProcFSTools::write_proc_entry("/proc/sys/net/ipv4/tcp_syncookies", "1");

}

sub iptables_restore_cmdlist {
    my ($cmdlist, $table) = @_;

    $table = 'filter' if !$table;
    run_command(['iptables-restore', '-T', $table, '-n'], input => $cmdlist, errmsg => "iptables_restore_cmdlist");
}

sub ip6tables_restore_cmdlist {
    my ($cmdlist, $table) = @_;

    $table = 'filter' if !$table;
    run_command(['ip6tables-restore', '-T', $table, '-n'], input => $cmdlist, errmsg => "iptables_restore_cmdlist");
}

sub ipset_restore_cmdlist {
    my ($cmdlist) = @_;

    run_command(['ipset', 'restore'], input => $cmdlist, errmsg => "ipset_restore_cmdlist");
}

sub ebtables_restore_cmdlist {
    my ($cmdlist) = @_;

    run_command(['ebtables-restore'], input => $cmdlist, errmsg => "ebtables_restore_cmdlist");
}

sub iptables_get_chains {
    my ($iptablescmd, $t) = @_;

    $iptablescmd = "iptables" if !$iptablescmd;
    $t = 'filter' if !$t;

    my $res = {};

    # check what chains we want to track
    my $is_pvefw_chain = sub {
	my $name = shift;

	return 1 if $name =~ m/^PVEFW-\S+$/;

	return 1 if $name =~ m/^tap\d+i\d+-(?:IN|OUT)$/;

	return 1 if $name =~ m/^veth\d+i\d+-(?:IN|OUT)$/;

	return 1 if $name =~ m/^fwbr\d+(v\d+)?-(?:FW|IN|OUT|IPS)$/;
	return 1 if $name =~ m/^GROUP-(?:$security_group_name_pattern)-(?:IN|OUT)$/;

	return undef;
    };

    my $table = '';

    my $hooks = {};

    my $parser = sub {
	my $line = shift;

	return if $line =~ m/^#/;
	return if $line =~ m/^\s*$/;

	if ($line =~ m/^\*(\S+)$/) {
	    $table = $1;
	    return;
	}

	return if $table ne $t;

	if ($line =~ m/^:(\S+)\s/) {
	    my $chain = $1;
	    return if !&$is_pvefw_chain($chain);
	    $res->{$chain} = "unknown";
	} elsif ($line =~ m/^-A\s+(\S+)\s.*--comment\s+\"PVESIG:(\S+)\"/) {
	    my ($chain, $sig) = ($1, $2);
	    return if !&$is_pvefw_chain($chain);
	    $res->{$chain} = $sig;
	} elsif ($line =~ m/^-A\s+(INPUT|OUTPUT|FORWARD|PREROUTING)\s+-j\s+PVEFW-\1$/) {
	    $hooks->{$1} = 1;
	} else {
	    # simply ignore the rest
	    return;
	}
    };

    run_command(["$iptablescmd-save"], outfunc => $parser);

    return wantarray ? ($res, $hooks) : $res;
}

sub iptables_chain_digest {
    my ($rules) = @_;
    my $digest = Digest::SHA->new('sha1');
    foreach my $rule (@$rules) { # order is important
	$digest->add($rule);
    }
    return $digest->b64digest;
}

sub ipset_chain_digest {
    my ($rules) = @_;

    my $digest = Digest::SHA->new('sha1');
    foreach my $rule (sort @$rules) { # note: sorted
	$digest->add($rule);
    }
    return $digest->b64digest;
}

sub ipset_get_chains {

    my $res = {};
    my $chains = {};

    my $parser = sub {
	my $line = shift;

	return if $line =~ m/^#/;
	return if $line =~ m/^\s*$/;
	if ($line =~ m/^(?:\S+)\s(PVEFW-\S+)\s(?:\S+).*/) {
	    my $chain = $1;
	    # ignore initval from ipset v7.7+, won't set that yet so it'd mess up change detection
	    $line =~ s/\binitval 0x[0-9a-f]+//;
	    $line =~ s/\s+$//; # delete trailing white space
	    push @{$chains->{$chain}}, $line;
	} else {
	    # simply ignore the rest
	    return;
	}
    };

    run_command(['ipset', 'save'], outfunc => $parser);

    # compute digest for each chain
    foreach my $chain (keys %$chains) {
	$res->{$chain} = ipset_chain_digest($chains->{$chain});
    }

    return $res;
}

sub ebtables_get_chains {

    my $res = {};
    my $chains = {};
    my $table;
    my $parser = sub {
	my $line = shift;
	return if $line =~ m/^#/;
	return if $line =~ m/^\s*$/;
	if ($line =~ m/^\*(\S+)$/) {
	    $table = $1;
	    return;
	}

	return if $table ne "filter";

	if ($line =~ m/^:(\S+)\s(ACCEPT|DROP|RETURN)$/) {
	    # Make sure we know chains exist even if they're empty.
	    $chains->{$1} //= [];
	    $res->{$1}->{policy} = $2;
	} elsif ($line =~ m/^(?:\S+)\s(\S+)\s(?:\S+).*/) {
	    my $chain = $1;
	    $line =~ s/\s+$//;
	    push @{$chains->{$chain}}, $line;
	} else {
	    # simply ignore the rest
	    return;
	}
    };

    run_command(['ebtables-save'], outfunc => $parser);
    # compute digest for each chain and store rules as well
    foreach my $chain (keys %$chains) {
	$res->{$chain}->{rules} = $chains->{$chain};
	$res->{$chain}->{sig} = iptables_chain_digest($chains->{$chain});
    }
    return $res;
}

# substitute action of rule according to action hash
sub rule_substitude_action {
    my ($rule, $actions) = @_;

    if (my $action = $rule->{action}) {
	$rule->{action} = $actions->{$action} if defined($actions->{$action});
    }
}

# generate a src or dst match
# $dir(ection) is either d or s
sub ipt_gen_src_or_dst_match {
    my ($adr, $dir, $ipversion, $cluster_conf, $fw_conf) = @_;

    my $srcdst;
    if ($dir eq 's') {
	$srcdst = "src";
    } elsif ($dir eq 'd') {
	$srcdst = "dst";
    } else {
	die "ipt_gen_src_or_dst_match: invalid direction $dir \n";
    }

    my $match;
    if ($adr =~ m/^\+/) {
	if ($adr =~ m/^\+(${ipset_name_pattern})$/) {
	    my $name = $1;
	    my $ipset_chain;
	    if ($fw_conf && $fw_conf->{ipset}->{$name}) {
		$ipset_chain = compute_ipset_chain_name($fw_conf->{vmid}, $name, $ipversion);
	    } elsif ($cluster_conf && $cluster_conf->{ipset}->{$name}) {
		$ipset_chain = compute_ipset_chain_name(0, $name, $ipversion);
	    } else {
		die "no such ipset '$name'\n";
	    }
	    $match = "-m set --match-set ${ipset_chain} ${srcdst}";
	} else {
	    die "invalid security group name '$adr'\n";
	}
    } elsif ($adr =~ m/^${ip_alias_pattern}$/){
	my $alias = lc($adr);
	my $e = $fw_conf ? $fw_conf->{aliases}->{$alias} : undef;
	$e = $cluster_conf->{aliases}->{$alias} if !$e && $cluster_conf;
	die "no such alias '$adr'\n" if !$e;
	$match = "-${dir} $e->{cidr}";
    } elsif ($adr =~ m/\-/){
	$match = "-m iprange --${srcdst}-range $adr";
    } else {
	$match = "-${dir} $adr";
    }

    return $match;
}

# convert a %rule to an array of iptables commands
sub ipt_rule_to_cmds {
    my ($rule, $chain, $ipversion, $cluster_conf, $fw_conf, $vmid) = @_;

    die "ipt_rule_to_cmds unable to handle macro" if $rule->{macro}; #should not happen

    my @match = ();

    if (defined $rule->{match}) {
	push @match, $rule->{match};
    } else {
	push @match, "-i $rule->{iface_in}" if $rule->{iface_in};
	push @match, "-o $rule->{iface_out}" if $rule->{iface_out};

	if ($rule->{source}) {
	    push @match, ipt_gen_src_or_dst_match($rule->{source}, 's', $ipversion, $cluster_conf, $fw_conf);
	}
	if ($rule->{dest}) {
	    push @match, ipt_gen_src_or_dst_match($rule->{dest}, 'd', $ipversion, $cluster_conf, $fw_conf);
	}

	if (my $proto = $rule->{proto}) {
	    push @match, "-p $proto";

	    my $multidport = defined($rule->{dport}) && parse_port_name_number_or_range($rule->{dport}, 1);
	    my $multisport = defined($rule->{sport}) && parse_port_name_number_or_range($rule->{sport}, 0);

	    my $add_dport = sub {
		return if !defined($rule->{dport});

		# NOTE: we re-use dport to store --icmp-type for icmp* protocol
		if ($proto eq 'icmp') {
		    $is_valid_icmp_type->($rule->{dport}, $icmp_type_names);
		    push @match, "-m icmp --icmp-type $rule->{dport}";
		} elsif ($proto eq 'icmpv6') {
		    $is_valid_icmp_type->($rule->{dport}, $icmpv6_type_names);
		    push @match, "-m icmpv6 --icmpv6-type $rule->{dport}";
		} elsif (!$PROTOCOLS_WITH_PORTS->{$proto}) {
		    die "protocol $proto does not have ports\n";
		} elsif ($multidport) {
		    push @match, "--match multiport", "--dports $rule->{dport}";
		} else {
		    return if !$rule->{dport};
		    push @match, "--dport $rule->{dport}";
		}
	    };

	    my $add_sport = sub {
		return if !$rule->{sport};

		die "protocol $proto does not have ports\n"
		    if !$PROTOCOLS_WITH_PORTS->{$proto};
		if ($multisport) {
		    push @match, "--match multiport", "--sports $rule->{sport}";
		} else {
		    push @match, "--sport $rule->{sport}";
		}
	    };

	    my $add_icmp_type = sub {
		return if !defined($rule->{'icmp-type'}) || $rule->{'icmp-type'} eq '';

		die "'icmp-type' can only be set if 'icmp', 'icmpv6' or 'ipv6-icmp' is specified\n"
		    if ($proto ne 'icmp') && ($proto ne 'icmpv6') && ($proto ne 'ipv6-icmp');
		my $type = $proto eq 'icmp' ? 'icmp-type' : 'icmpv6-type';

		push @match, "-m $proto --$type $rule->{'icmp-type'}";
	    };

	    # order matters - single port before multiport!
	    $add_icmp_type->();
	    $add_dport->() if $multisport;
	    $add_sport->();
	    $add_dport->() if !$multisport;
	} elsif ($rule->{dport} || $rule->{sport}) {
	    die "destination port '$rule->{dport}', but no protocol specified\n" if $rule->{dport};
	    die "source port '$rule->{sport}', but no protocol specified\n" if $rule->{sport};
	}

	push @match, "-m addrtype --dst-type $rule->{dsttype}" if $rule->{dsttype};
    }
    my $matchstr = scalar(@match) ? join(' ', @match) : "";

    my $targetstr;
    if (defined $rule->{target}) {
	$targetstr = $rule->{target};
    } else {
	my $action = (defined $rule->{action}) ? $rule->{action} : "";
	my $goto = 1 if $action eq 'PVEFW-SET-ACCEPT-MARK';
	$targetstr = ($goto) ? "-g $action" : "-j $action";
    }

    my @iptcmds;
    my $log = $rule->{log};
    if (defined($log) && $log ne 'nolog') {
	my $loglevel = $log_level_hash->{$log};
	my $logaction = get_log_rule_base($chain, $vmid, $rule->{logmsg}, $loglevel);
	push @iptcmds, "-A $chain $matchstr $logaction";
    }
    push @iptcmds, "-A $chain $matchstr $targetstr";
    return @iptcmds;
}

sub ruleset_generate_rule {
    my ($ruleset, $chain, $ipversion, $rule, $cluster_conf, $fw_conf, $vmid) = @_;

    my $rules;

    if ($rule->{macro}) {
	$rules = &$apply_macro($rule->{macro}, $rule, 0, $ipversion);
    } else {
	$rules = [ $rule ];
    }

    # update all or nothing
    my @ipt_rule_cmds;
    foreach my $r (@$rules) {
	push @ipt_rule_cmds, ipt_rule_to_cmds($r, $chain, $ipversion, $cluster_conf, $fw_conf, $vmid);
    }
    foreach my $c (@ipt_rule_cmds) {
	ruleset_add_ipt_cmd($ruleset, $chain, $c);
    }
}

sub ruleset_create_chain {
    my ($ruleset, $chain) = @_;

    die "Invalid chain name '$chain' (28 char max)\n" if length($chain) > 28;
    die "chain name may not contain collons\n" if $chain =~ m/:/; # because of log format

    die "chain '$chain' already exists\n" if $ruleset->{$chain};

    $ruleset->{$chain} = [];
}

sub ruleset_chain_exist {
    my ($ruleset, $chain) = @_;

    return $ruleset->{$chain} ? 1 : undef;
}

# add an iptables command (like generated by ipt_rule_to_cmds) to a chain
sub ruleset_add_ipt_cmd {
   my ($ruleset, $chain, $iptcmd) = @_;

   die "no such chain '$chain'\n" if !$ruleset->{$chain};

   push @{$ruleset->{$chain}}, $iptcmd;
}

sub ruleset_addrule {
    my ($ruleset, $chain, $match, $action, $log, $logmsg, $vmid) = @_;

    die "no such chain '$chain'\n" if !$ruleset->{$chain};

    if ($log) {
	my $loglevel = $log_level_hash->{$log};
	my $logaction = get_log_rule_base($chain, $vmid, $logmsg, $loglevel);
	push @{$ruleset->{$chain}}, "-A $chain $match $logaction";
    }
    # for stable ebtables digests avoid double-spaces to match ebtables-save output
    $match .= ' ' if length($match);
    push @{$ruleset->{$chain}}, "-A $chain ${match}$action";
}

sub ruleset_insertrule {
   my ($ruleset, $chain, $match, $action, $log) = @_;

   die "no such chain '$chain'\n" if !$ruleset->{$chain};

   unshift @{$ruleset->{$chain}}, "-A $chain $match $action";
}

sub get_log_rule_base {
    my ($chain, $vmid, $msg, $loglevel) = @_;

    $vmid = 0 if !defined($vmid);
    $msg = "" if !defined($msg);

    my $rlimit = '';
    if (defined($global_log_ratelimit)) {
	$rlimit = "-m limit $global_log_ratelimit ";
    }

    # Note: we use special format for prefix to pass further
    # info to log daemon (VMID, LOGLEVEL and CHAIN)
    return "${rlimit}-j NFLOG --nflog-prefix \":$vmid:$loglevel:$chain: $msg\"";
}

sub ruleset_add_chain_policy {
    my ($ruleset, $chain, $ipversion, $vmid, $policy, $loglevel, $accept_action) = @_;

    if ($policy eq 'ACCEPT') {

	my $rule = { action => 'ACCEPT' };
	rule_substitude_action($rule, { ACCEPT =>  $accept_action});
	ruleset_generate_rule($ruleset, $chain, $ipversion, $rule);

    } elsif ($policy eq 'DROP') {

	ruleset_addrule($ruleset, $chain, "", "-j PVEFW-Drop");

	ruleset_addrule($ruleset, $chain, "", "-j DROP", $loglevel, "policy $policy: ", $vmid);
    } elsif ($policy eq 'REJECT') {
	ruleset_addrule($ruleset, $chain, "", "-j PVEFW-Reject");

	ruleset_addrule($ruleset, $chain, "", "-g PVEFW-reject", $loglevel, "policy $policy: ", $vmid);
    } else {
	# should not happen
	die "internal error: unknown policy '$policy'";
    }
}

sub ruleset_chain_add_ndp {
    my ($ruleset, $chain, $ipversion, $options, $direction, $accept) = @_;
    return if $ipversion != 6 || (defined($options->{ndp}) && !$options->{ndp});

    ruleset_addrule($ruleset, $chain, "-p icmpv6 --icmpv6-type router-solicitation", $accept);
    if ($direction ne 'OUT' || $options->{radv}) {
	ruleset_addrule($ruleset, $chain, "-p icmpv6 --icmpv6-type router-advertisement", $accept);
    }
    ruleset_addrule($ruleset, $chain, "-p icmpv6 --icmpv6-type neighbor-solicitation", $accept);
    ruleset_addrule($ruleset, $chain, "-p icmpv6 --icmpv6-type neighbor-advertisement", $accept);
}

sub ruleset_chain_add_conn_filters {
    my ($ruleset, $chain, $allow_invalid, $accept) = @_;

    if (!$allow_invalid) {
	ruleset_addrule($ruleset, $chain, "-m conntrack --ctstate INVALID", "-j DROP");
    }
    ruleset_addrule($ruleset, $chain, "-m conntrack --ctstate RELATED,ESTABLISHED", "-j $accept");
}

sub ruleset_chain_add_input_filters {
    my ($ruleset, $chain, $ipversion, $options, $cluster_conf, $loglevel) = @_;

    if ($cluster_conf->{ipset}->{blacklist}){
	if (!ruleset_chain_exist($ruleset, "PVEFW-blacklist")) {
	    ruleset_create_chain($ruleset, "PVEFW-blacklist");
	    ruleset_addrule($ruleset, "PVEFW-blacklist", "", "-j DROP", $loglevel, "DROP: ", 0);
	}
	my $ipset_chain = compute_ipset_chain_name(0, 'blacklist', $ipversion);
	ruleset_addrule($ruleset, $chain, "-m set --match-set ${ipset_chain} src", "-j PVEFW-blacklist");
    }

    if (!(defined($options->{nosmurfs}) && $options->{nosmurfs} == 0)) {
	if ($ipversion == 4) {
	    ruleset_addrule($ruleset, $chain, "-m conntrack --ctstate INVALID,NEW", "-j PVEFW-smurfs");
	}
    }

    if ($options->{tcpflags}) {
	ruleset_addrule($ruleset, $chain, "-p tcp", "-j PVEFW-tcpflags");
    }
}

sub ruleset_create_vm_chain {
    my ($ruleset, $chain, $ipversion, $options, $macaddr, $ipfilter_ipset, $direction) = @_;

    ruleset_create_chain($ruleset, $chain);
    my $accept = generate_nfqueue($options);

    if (!(defined($options->{dhcp}) && $options->{dhcp} == 0)) {
	if ($ipversion == 4) {
	    if ($direction eq 'OUT') {
		ruleset_generate_rule($ruleset, $chain, $ipversion,
				      { action => 'PVEFW-SET-ACCEPT-MARK',
					proto => 'udp', sport => 68, dport => 67 });
	    } else {
		ruleset_generate_rule($ruleset, $chain, $ipversion,
				      { action => 'ACCEPT',
					proto => 'udp', sport => 67, dport => 68 });
	    }
	} elsif ($ipversion == 6) {
	    if ($direction eq 'OUT') {
		ruleset_generate_rule($ruleset, $chain, $ipversion,
				      { action => 'PVEFW-SET-ACCEPT-MARK',
					proto => 'udp', sport => 546, dport => 547 });
	    } else {
		ruleset_generate_rule($ruleset, $chain, $ipversion,
				      { action => 'ACCEPT',
					proto => 'udp', sport => 547, dport => 546 });
	    }
	}

    }

    if ($direction eq 'OUT') {
	if (defined($macaddr) && !(defined($options->{macfilter}) && $options->{macfilter} == 0)) {
	    ruleset_addrule($ruleset, $chain, "-m mac ! --mac-source $macaddr", "-j DROP");
	}
	if ($ipversion == 6 && !$options->{radv}) {
	    ruleset_addrule($ruleset, $chain, "-p icmpv6 --icmpv6-type router-advertisement", "-j DROP");
	}
	if ($ipfilter_ipset) {
	    ruleset_addrule($ruleset, $chain, "-m set ! --match-set $ipfilter_ipset src", "-j DROP");
	}
	ruleset_addrule($ruleset, $chain, "", "-j MARK --set-mark $FWACCEPTMARK_OFF"); # clear mark
    }

    my $accept_action = $direction eq 'OUT' ? '-g PVEFW-SET-ACCEPT-MARK' : "-j $accept";
    ruleset_chain_add_ndp($ruleset, $chain, $ipversion, $options, $direction, $accept_action);
}

sub ruleset_add_group_rule {
    my ($ruleset, $cluster_conf, $chain, $rule, $direction, $action, $ipversion) = @_;

    my $group = $rule->{action};
    my $group_chain = "GROUP-$group-$direction";
    if(!ruleset_chain_exist($ruleset, $group_chain)){
	generate_group_rules($ruleset, $cluster_conf, $group, $ipversion);
    }

    if ($direction eq 'OUT' && $rule->{iface_out}) {
	ruleset_addrule($ruleset, $chain, "-o $rule->{iface_out}", "-j $group_chain");
    } elsif ($direction eq 'IN' && $rule->{iface_in}) {
	ruleset_addrule($ruleset, $chain, "-i $rule->{iface_in}", "-j $group_chain");
    } else {
	ruleset_addrule($ruleset, $chain, "", "-j $group_chain");
    }

    ruleset_addrule($ruleset, $chain, "-m mark --mark $FWACCEPTMARK_ON", "-j $action");
}

sub ruleset_generate_vm_rules {
    my ($ruleset, $rules, $cluster_conf, $vmfw_conf, $chain, $netid, $direction, $options, $ipversion, $vmid) = @_;

    my $lc_direction = lc($direction);

    my $in_accept = generate_nfqueue($options);

    foreach my $rule (@$rules) {
	next if $rule->{iface} && $rule->{iface} ne $netid;
	next if !$rule->{enable} || $rule->{errors};
	next if $rule->{ipversion} && ($rule->{ipversion} != $ipversion);

	if ($rule->{type} eq 'group') {
	    ruleset_add_group_rule($ruleset, $cluster_conf, $chain, $rule, $direction,
				   $direction eq 'OUT' ? 'RETURN' : $in_accept, $ipversion);
	} else {
	    next if $rule->{type} ne $lc_direction;
	    eval {
		$rule->{logmsg} = "$rule->{action}: ";
		if ($direction eq 'OUT') {
		    rule_substitude_action($rule, { ACCEPT => "PVEFW-SET-ACCEPT-MARK", REJECT => "PVEFW-reject" });
		    ruleset_generate_rule($ruleset, $chain, $ipversion, $rule, $cluster_conf, $vmfw_conf, $vmid);
		} else {
		    rule_substitude_action($rule, { ACCEPT => $in_accept , REJECT => "PVEFW-reject" });
		    ruleset_generate_rule($ruleset, $chain, $ipversion, $rule, $cluster_conf, $vmfw_conf, $vmid);
		}
	    };
	    warn $@ if $@;
	}
    }
}

sub generate_nfqueue {
    my ($options) = @_;

    if ($options->{ips}) {
	my $action = "NFQUEUE";
	if ($options->{ips_queues} && $options->{ips_queues} =~ m/^(\d+)(:(\d+))?$/) {
	    if (defined($3) && defined($1)) {
		$action .= " --queue-balance $1:$3";
	    } elsif (defined($1)) {
		$action .= " --queue-num $1";
	    }
	}
	$action .= " --queue-bypass" if $feature_ipset_nomatch; #need kernel 3.10
	return $action;
    } else {
	return "ACCEPT";
    }
}

sub ruleset_generate_vm_ipsrules {
    my ($ruleset, $options, $direction, $iface) = @_;

    if ($options->{ips} && $direction eq 'IN') {
	my $nfqueue = generate_nfqueue($options);

	if (!ruleset_chain_exist($ruleset, "PVEFW-IPS")) {
	    ruleset_create_chain($ruleset, "PVEFW-IPS");
	}

        ruleset_addrule($ruleset, "PVEFW-IPS", "-m physdev --physdev-out $iface --physdev-is-bridged", "-j $nfqueue");
    }
}

sub generate_tap_rules_direction {
    my ($ruleset, $cluster_conf, $iface, $netid, $macaddr, $vmfw_conf, $vmid, $direction, $ipversion) = @_;

    my $lc_direction = lc($direction);

    my $rules = $vmfw_conf->{rules};

    my $options = $vmfw_conf->{options};
    my $loglevel = get_option_log_level($options, "log_level_${lc_direction}");

    my $tapchain = "$iface-$direction";

    my $ipfilter_name = compute_ipfilter_ipset_name($netid);
    my $ipfilter_ipset = compute_ipset_chain_name($vmid, $ipfilter_name, $ipversion)
	if $options->{ipfilter} || $vmfw_conf->{ipset}->{$ipfilter_name};

    if ($options->{enable}) {
	# create chain with mac and ip filter
	ruleset_create_vm_chain($ruleset, $tapchain, $ipversion, $options, $macaddr, $ipfilter_ipset, $direction);

	ruleset_generate_vm_rules($ruleset, $rules, $cluster_conf, $vmfw_conf, $tapchain, $netid, $direction, $options, $ipversion, $vmid);

	ruleset_generate_vm_ipsrules($ruleset, $options, $direction, $iface);

	# implement policy
	my $policy;

	if ($direction eq 'OUT') {
	    $policy = $options->{policy_out} || 'ACCEPT'; # allow everything by default
	} else {
	    $policy = $options->{policy_in} || 'DROP'; # allow nothing by default
	}

	my $accept = generate_nfqueue($options);
	my $accept_action = $direction eq 'OUT' ? "PVEFW-SET-ACCEPT-MARK" : $accept;
	ruleset_add_chain_policy($ruleset, $tapchain, $ipversion, $vmid, $policy, $loglevel, $accept_action);
    } else {
	my $accept_action = $direction eq 'OUT' ? "PVEFW-SET-ACCEPT-MARK" : 'ACCEPT';
	ruleset_add_chain_policy($ruleset, $tapchain, $ipversion, $vmid, 'ACCEPT', $loglevel, $accept_action);
    }

    # plug the tap chain to bridge chain
    if ($direction eq 'IN') {
	ruleset_addrule($ruleset, "PVEFW-FWBR-IN",
			"-m physdev --physdev-is-bridged --physdev-out $iface", "-j $tapchain");
    } else {
	ruleset_addrule($ruleset, "PVEFW-FWBR-OUT",
			"-m physdev --physdev-is-bridged --physdev-in $iface", "-j $tapchain");
    }
}

sub enable_host_firewall {
    my ($ruleset, $hostfw_conf, $cluster_conf, $ipversion, $corosync_conf) = @_;

    my $options = $hostfw_conf->{options};
    my $cluster_options = $cluster_conf->{options};
    my $rules = $hostfw_conf->{rules};
    my $cluster_rules = $cluster_conf->{rules};

    # corosync preparation
    my $corosync_rule = "-p udp --dport 5404:5405";
    my $corosync_local_addresses = {};
    my $multicast_enabled;
    my $local_hostname = PVE::INotify::nodename();
    if (defined($corosync_conf)) {
	PVE::Corosync::for_all_corosync_addresses($corosync_conf, $ipversion, sub {
	    my ($node_name, $node_ip, $node_ipversion, $key) = @_;

	    if ($node_name eq $local_hostname) {
		$corosync_local_addresses->{$key} = $node_ip;
	    }
	});

	# allow multicast only if enabled in config
	my $corosync_transport = $corosync_conf->{main}->{totem}->{transport};
	$multicast_enabled = defined($corosync_transport) && $corosync_transport eq 'udp';
    }

    # host inbound firewall
    my $chain = "PVEFW-HOST-IN";
    ruleset_create_chain($ruleset, $chain);

    my $loglevel = get_option_log_level($options, "log_level_in");

    ruleset_addrule($ruleset, $chain, "-i lo", "-j ACCEPT");

    ruleset_chain_add_conn_filters($ruleset, $chain, 0, 'ACCEPT');
    ruleset_chain_add_ndp($ruleset, $chain, $ipversion, $options, 'IN', '-j RETURN');
    ruleset_chain_add_input_filters($ruleset, $chain, $ipversion, $options, $cluster_conf, $loglevel);

    # we use RETURN because we need to check also tap rules
    my $accept_action = 'RETURN';

    ruleset_addrule($ruleset, $chain, "-p igmp", "-j $accept_action"); # important for multicast

    # add host rules first, so that cluster wide rules can be overwritten
    foreach my $rule (@$rules, @$cluster_rules) {
	next if !$rule->{enable} || $rule->{errors};
	next if $rule->{ipversion} && ($rule->{ipversion} != $ipversion);

	$rule->{iface_in} = $rule->{iface} if $rule->{iface};

	eval {
	    $rule->{logmsg} = "$rule->{action}: ";
	    if ($rule->{type} eq 'group') {
		ruleset_add_group_rule($ruleset, $cluster_conf, $chain, $rule, 'IN', $accept_action, $ipversion);
	    } elsif ($rule->{type} eq 'in') {
		rule_substitude_action($rule, { ACCEPT => $accept_action, REJECT => "PVEFW-reject" });
		ruleset_generate_rule($ruleset, $chain, $ipversion, $rule, $cluster_conf, $hostfw_conf, 0);
	    }
	};
	warn $@ if $@;
	delete $rule->{iface_in};
    }

    # allow standard traffic for management ipset (includes cluster network)
    my $mngmnt_ipset_chain = compute_ipset_chain_name(0, "management", $ipversion);
    my $mngmntsrc = "-m set --match-set ${mngmnt_ipset_chain} src";
    ruleset_addrule($ruleset, $chain, "$mngmntsrc -p tcp --dport 8006", "-j $accept_action");  # PVE API
    ruleset_addrule($ruleset, $chain, "$mngmntsrc -p tcp --dport 5900:5999", "-j $accept_action");  # PVE VNC Console
    ruleset_addrule($ruleset, $chain, "$mngmntsrc -p tcp --dport 3128", "-j $accept_action");  # SPICE Proxy
    ruleset_addrule($ruleset, $chain, "$mngmntsrc -p tcp --dport 22", "-j $accept_action");  # SSH
    ruleset_addrule($ruleset, $chain, "$mngmntsrc -p tcp --dport 60000:60050", "-j $accept_action");  # Migration

    # corosync inbound rules
    if (defined($corosync_conf)) {
	ruleset_addrule($ruleset, $chain, "-m addrtype --dst-type MULTICAST $corosync_rule", "-j $accept_action")
	    if $multicast_enabled;

	PVE::Corosync::for_all_corosync_addresses($corosync_conf, $ipversion, sub {
	    my ($node_name, $node_ip, $node_ipversion, $key) = @_;
	    my $destination = $corosync_local_addresses->{$key};

	    if ($node_name ne $local_hostname && defined($destination)) {
		# accept only traffic on same ring
		ruleset_addrule($ruleset, $chain, "-d $destination -s $node_ip $corosync_rule", "-j $accept_action");
	    }
	});
    }

    # implement input policy
    my $policy = $cluster_options->{policy_in} || 'DROP'; # allow nothing by default
    ruleset_add_chain_policy($ruleset, $chain, $ipversion, 0, $policy, $loglevel, $accept_action);

    # host outbound firewall
    $chain = "PVEFW-HOST-OUT";
    ruleset_create_chain($ruleset, $chain);

    $loglevel = get_option_log_level($options, "log_level_out");

    ruleset_addrule($ruleset, $chain, "-o lo", "-j ACCEPT");

    ruleset_chain_add_conn_filters($ruleset, $chain, 0, 'ACCEPT');

    # we use RETURN because we may want to check other thigs later
    $accept_action = 'RETURN';
    ruleset_chain_add_ndp($ruleset, $chain, $ipversion, $options, 'OUT', "-j $accept_action");

    ruleset_addrule($ruleset, $chain, "-p igmp", "-j $accept_action"); # important for multicast

    # add host rules first, so that cluster wide rules can be overwritten
    foreach my $rule (@$rules, @$cluster_rules) {
	next if !$rule->{enable} || $rule->{errors};
	next if $rule->{ipversion} && ($rule->{ipversion} != $ipversion);

	$rule->{iface_out} = $rule->{iface} if $rule->{iface};
	eval {
	    $rule->{logmsg} = "$rule->{action}: ";
	    if ($rule->{type} eq 'group') {
		ruleset_add_group_rule($ruleset, $cluster_conf, $chain, $rule, 'OUT', $accept_action, $ipversion);
	    } elsif ($rule->{type} eq 'out') {
		rule_substitude_action($rule, { ACCEPT => $accept_action, REJECT => "PVEFW-reject" });
		ruleset_generate_rule($ruleset, $chain, $ipversion, $rule, $cluster_conf, $hostfw_conf, 0);
	    }
	};
	warn $@ if $@;
	delete $rule->{iface_out};
    }

    # allow standard traffic on cluster network
    my $localnet = $cluster_conf->{aliases}->{local_network}->{cidr};
    my $localnet_ver = $cluster_conf->{aliases}->{local_network}->{ipversion};

    if ($localnet && ($ipversion == $localnet_ver)) {
	ruleset_addrule($ruleset, $chain, "-d $localnet -p tcp --dport 8006", "-j $accept_action");  # PVE API
	ruleset_addrule($ruleset, $chain, "-d $localnet -p tcp --dport 22", "-j $accept_action");  # SSH
	ruleset_addrule($ruleset, $chain, "-d $localnet -p tcp --dport 5900:5999", "-j $accept_action");  # PVE VNC Console
	ruleset_addrule($ruleset, $chain, "-d $localnet -p tcp --dport 3128", "-j $accept_action");  # SPICE Proxy
    }

    # corosync outbound rules
    if (defined($corosync_conf)) {
	ruleset_addrule($ruleset, $chain, "-m addrtype --dst-type MULTICAST $corosync_rule", "-j $accept_action")
	    if $multicast_enabled;

	PVE::Corosync::for_all_corosync_addresses($corosync_conf, $ipversion, sub {
	    my ($node_name, $node_ip, $node_ipversion, $key) = @_;
	    my $source = $corosync_local_addresses->{$key};

	    if ($node_name ne $local_hostname && defined($source)) {
		# accept only traffic on same ring
		ruleset_addrule($ruleset, $chain, "-s $source -d $node_ip $corosync_rule", "-j $accept_action");
	    }
	});
    }

    # implement output policy
    $policy = $cluster_options->{policy_out} || 'ACCEPT'; # allow everything by default
    ruleset_add_chain_policy($ruleset, $chain, $ipversion, 0, $policy, $loglevel, $accept_action);

    ruleset_addrule($ruleset, "PVEFW-OUTPUT", "", "-j PVEFW-HOST-OUT");
    ruleset_addrule($ruleset, "PVEFW-INPUT", "", "-j PVEFW-HOST-IN");
}

sub generate_group_rules {
    my ($ruleset, $cluster_conf, $group, $ipversion) = @_;

    my $rules = $cluster_conf->{groups}->{$group};

    if (!$rules) {
	warn "no such security group '$group'\n";
	$rules = []; # create empty chain
    }

    my $chain = "GROUP-${group}-IN";

    ruleset_create_chain($ruleset, $chain);
    ruleset_addrule($ruleset, $chain, "", "-j MARK --set-mark $FWACCEPTMARK_OFF"); # clear mark

    foreach my $rule (@$rules) {
	next if $rule->{type} ne 'in';
	next if !$rule->{enable} || $rule->{errors};
	next if $rule->{ipversion} && $rule->{ipversion} ne $ipversion;
	rule_substitude_action($rule, { ACCEPT => "PVEFW-SET-ACCEPT-MARK", REJECT => "PVEFW-reject" });
	ruleset_generate_rule($ruleset, $chain, $ipversion, $rule, $cluster_conf);
    }

    $chain = "GROUP-${group}-OUT";

    ruleset_create_chain($ruleset, $chain);
    ruleset_addrule($ruleset, $chain, "", "-j MARK --set-mark $FWACCEPTMARK_OFF"); # clear mark

    foreach my $rule (@$rules) {
	next if $rule->{type} ne 'out';
	next if !$rule->{enable} || $rule->{errors};
	next if $rule->{ipversion} && $rule->{ipversion} ne $ipversion;
	# we use PVEFW-SET-ACCEPT-MARK (Instead of ACCEPT) because we need to
	# check also other tap rules later
	rule_substitude_action($rule, { ACCEPT => 'PVEFW-SET-ACCEPT-MARK', REJECT => "PVEFW-reject" });
	ruleset_generate_rule($ruleset, $chain, $ipversion, $rule, $cluster_conf);
    }
}

my $MAX_NETS = 32;
my $valid_netdev_names = {};
for (my $i = 0; $i < $MAX_NETS; $i++)  {
    $valid_netdev_names->{"net$i"} = 1;
}

sub get_mark_values {
    my ($value, $mask) = @_;
    $value = hex($value) if $value =~ /^0x/;
    $mask = hex($mask) if defined($mask) && $mask =~ /^0x/;
    $mask = 0xffffffff if !defined($mask);
    return ($value, $mask);
}

sub parse_fw_rule {
    my ($prefix, $line, $cluster_conf, $fw_conf, $rule_env) = @_;

    my $orig_line = $line;

    my $rule = {};

    # we can add single line comments to the end of the rule
    if ($line =~ s/#\s*(.*?)\s*$//) {
	$rule->{comment} = decode('utf8', $1);
    }

    # we can disable a rule when prefixed with '|'

    $rule->{enable} = $line =~ s/^\|// ? 0 : 1;

    $line =~ s/^(\S+)\s+(\S+)\s*// ||
 	die "unable to parse rule: $line\n";

    $rule->{type} = lc($1);
    $rule->{action} = $2;

    if ($rule->{type} eq  'in' || $rule->{type} eq 'out') {
	if ($rule->{action} =~ m/^(\S+)\((ACCEPT|DROP|REJECT)\)$/) {
	    $rule->{macro} = $1;
	    $rule->{action} = $2;
	}
    }

    while (length($line)) {
	if ($line =~ s/^-i (\S+)\s*//) {
	    $rule->{iface} = $1;
	    next;
	}

	last if $rule->{type} eq 'group';

	if ($line =~ s/^(?:-p|--?proto) (\S+)\s*//) {
	    $rule->{proto} = $1;
	    next;
	}

	if ($line =~ s/^--?dport (\S+)\s*//) {
	    $rule->{dport} = $1;
	    next;
	}

	if ($line =~ s/^--?sport (\S+)\s*//) {
	    $rule->{sport} = $1;
	    next;
	}
	if ($line =~ s/^--?source (\S+)\s*//) {
	    $rule->{source} = $1;
	    next;
	}
	if ($line =~ s/^--?dest (\S+)\s*//) {
	    $rule->{dest} = $1;
	    next;
	}
	if ($line =~ s/^--?log (emerg|alert|crit|err|warning|notice|info|debug|nolog)\s*//) {
	    $rule->{log} = $1;
	    next;
	}
	if ($line =~ s/^--?icmp-type (\S+)\s*//) {
	    $rule->{'icmp-type'} = $1;
	    next;
	}

	last;
    }

    die "unable to parse rule parameters: $line\n" if length($line);

    $rule = verify_rule($rule, $cluster_conf, $fw_conf, $rule_env, 1);
    if ($rule->{errors}) {
	# The verbose flag really means we're running from the CLI and want
	# output on the console - in the other case we really want such errors
	# to go into the syslog instead.
	my $log = $verbose ? sub { warn @_ } : sub { syslog(err => @_) };
	$log->("$prefix - errors in rule parameters: $orig_line\n");
	foreach my $p (keys %{$rule->{errors}}) {
	    $log->("  $p: $rule->{errors}->{$p}\n");
	}
    }

    return $rule;
}

sub verify_ethertype {
    my ($value) = @_;
    my $types = get_etc_ethertypes();
    die "unknown ethernet protocol type: $value\n"
	if !defined($types->{byname}->{$value}) &&
	   !defined($types->{byid}->{$value});
}

sub parse_vmfw_option {
    my ($line) = @_;

    my ($opt, $value);

    my $loglevels = "emerg|alert|crit|err|warning|notice|info|debug|nolog";

    if ($line =~ m/^(enable|dhcp|ndp|radv|macfilter|ipfilter|ips):\s*(0|1)\s*$/i) {
	$opt = lc($1);
	$value = int($2);
    } elsif ($line =~ m/^(log_level_in|log_level_out):\s*(($loglevels)\s*)?$/i) {
	$opt = lc($1);
	$value = $2 ? lc($3) : '';
    } elsif ($line =~ m/^(policy_(in|out)):\s*(ACCEPT|DROP|REJECT)\s*$/i) {
	$opt = lc($1);
	$value = uc($3);
    } elsif ($line =~ m/^(ips_queues):\s*((\d+)(:(\d+))?)\s*$/i) {
	$opt = lc($1);
	$value = $2;
    } elsif ($line =~ m/^(layer2_protocols):\s*(((\S+)[,]?)+)\s*$/i) {
	$opt = lc($1);
	$value = $2;
	verify_ethertype($_) foreach split(/\s*,\s*/, $value);
    } else {
	die "can't parse option '$line'\n"
    }

    return ($opt, $value);
}

sub parse_hostfw_option {
    my ($line) = @_;

    my ($opt, $value);

    my $loglevels = "emerg|alert|crit|err|warning|notice|info|debug|nolog";

    if ($line =~ m/^(enable|nosmurfs|tcpflags|ndp|log_nf_conntrack|nf_conntrack_allow_invalid|protection_synflood):\s*(0|1)\s*$/i) {
	$opt = lc($1);
	$value = int($2);
    } elsif ($line =~ m/^(log_level_in|log_level_out|tcp_flags_log_level|smurf_log_level):\s*(($loglevels)\s*)?$/i) {
	$opt = lc($1);
	$value = $2 ? lc($3) : '';
    } elsif ($line =~ m/^(nf_conntrack_max|nf_conntrack_tcp_timeout_established|nf_conntrack_tcp_timeout_syn_recv|protection_synflood_rate|protection_synflood_burst|protection_limit):\s*(\d+)\s*$/i) {
	$opt = lc($1);
	$value = int($2);
    } else {
	die "can't parse option '$line'\n"
    }

    return ($opt, $value);
}

sub parse_clusterfw_option {
    my ($line) = @_;

    my ($opt, $value);

    if ($line =~ m/^(enable):\s*(\d+)\s*$/i) {
	$opt = lc($1);
	$value = int($2);
	if (($value > 1) && ((time() - $value) > 60)) {
	    $value = 0
	}
    } elsif ($line =~ m/^(ebtables):\s*(0|1)\s*$/i) {
	$opt = lc($1);
	$value = int($2);
    } elsif ($line =~ m/^(policy_(in|out)):\s*(ACCEPT|DROP|REJECT)\s*$/i) {
	$opt = lc($1);
	$value = uc($3);
    } elsif ($line =~ m/^(log_ratelimit):\s*(\S+)\s*$/) {
	$opt = lc($1);
	$value = $2;
    } else {
	die "can't parse option '$line'\n"
    }

    return ($opt, $value);
}

sub resolve_alias {
    my ($clusterfw_conf, $fw_conf, $cidr) = @_;

    my $alias = lc($cidr);
    my $e = $fw_conf ? $fw_conf->{aliases}->{$alias} : undef;
    $e = $clusterfw_conf->{aliases}->{$alias} if !$e && $clusterfw_conf;

    die "no such alias '$cidr'\n" if !$e;;

    return wantarray ? ($e->{cidr}, $e->{ipversion}) : $e->{cidr};
}

sub parse_ip_or_cidr {
    my ($cidr) = @_;

    my $ipversion;

    if ($cidr =~ m!^(?:$IPV6RE)(/(\d+))?$!) {
	$cidr =~ s|/128$||;
	$ipversion = 6;
    } elsif ($cidr =~ m!^(?:$IPV4RE)(/(\d+))?$!) {
	$cidr =~ s|/32$||;
	$ipversion = 4;
    } else {
	die "value does not look like a valid IP address or CIDR network\n";
    }

    return wantarray ? ($cidr, $ipversion) : $cidr;
}

sub parse_alias {
    my ($line) = @_;

    # we can add single line comments to the end of the line
    my $comment = decode('utf8', $1) if $line =~ s/\s*#\s*(.*?)\s*$//;

    if ($line =~ m/^(\S+)\s(\S+)$/) {
	my ($name, $cidr) = ($1, $2);
	my $ipversion;

	($cidr, $ipversion) = parse_ip_or_cidr($cidr);

	my $data = {
	    name => $name,
	    cidr => $cidr,
	    ipversion => $ipversion,
	};
	$data->{comment} = $comment  if $comment;
	return $data;
    }

    return undef;
}

sub generic_fw_config_parser {
    my ($filename, $cluster_conf, $empty_conf, $rule_env) = @_;

    my $section;
    my $group;

    my $res = $empty_conf;

    my $raw;
    if ($filename =~ m!^/etc/pve/(.*)$!) {
	$raw = PVE::Cluster::get_config($1);
    } else {
	$raw = eval { PVE::Tools::file_get_contents($filename) }; # ignore errors
    }
    return {} if !$raw;

    my $curr_group_keys = {};

    my $linenr = 0;
    while ($raw =~ /^\h*(.*?)\h*$/gm) {
	my $line = $1;
	$linenr++;
	next if $line =~ m/^#/;
	next if $line =~ m/^\s*$/;
	chomp $line;

	my $prefix = "$filename (line $linenr)";

	if ($empty_conf->{options} && ($line =~ m/^\[options\]$/i)) {
	    $section = 'options';
	    next;
	}

	if ($empty_conf->{aliases} && ($line =~ m/^\[aliases\]$/i)) {
	    $section = 'aliases';
	    next;
	}

	if ($empty_conf->{groups} && ($line =~ m/^\[group\s+(\S+)\]\s*(?:#\s*(.*?)\s*)?$/i)) {
	    $section = 'groups';
	    $group = lc($1);
	    my $comment = $2;
	    eval {
		die "security group name too long\n" if length($group) > $max_group_name_length;
		die "invalid security group name '$group'\n" if $group !~ m/^${security_group_name_pattern}$/;
	    };
	    if (my $err = $@) {
		($section, $group, $comment) = undef;
		warn "$prefix: $err";
		next;
	    }

	    $res->{$section}->{$group} = [];
	    $res->{group_comments}->{$group} =  decode('utf8', $comment)
		if $comment;
	    next;
	}

	if ($empty_conf->{rules} && ($line =~ m/^\[rules\]$/i)) {
	    $section = 'rules';
	    next;
	}

	if ($empty_conf->{ipset} && ($line =~ m/^\[ipset\s+(\S+)\]\s*(?:#\s*(.*?)\s*)?$/i)) {
	    $section = 'ipset';
	    $group = lc($1);
	    my $comment = $2;
	    eval {
		die "ipset name too long\n" if length($group) > $max_ipset_name_length;
		die "invalid ipset name '$group'\n" if $group !~ m/^${ipset_name_pattern}$/;
	    };
	    if (my $err = $@) {
		($section, $group, $comment) = undef;
		warn "$prefix: $err";
		next;
	    }

	    $res->{$section}->{$group} = [];
	    $curr_group_keys = {};

	    $res->{ipset_comments}->{$group} = decode('utf8', $comment)
		if $comment;
	    next;
	}

	if (!$section) {
	    warn "$prefix: skip line - no section\n";
	    next;
	}

	if ($section eq 'options') {
	    eval {
		my ($opt, $value);
		if ($rule_env eq 'cluster') {
		    ($opt, $value) = parse_clusterfw_option($line);
		} elsif ($rule_env eq 'host') {
		    ($opt, $value) = parse_hostfw_option($line);
		} else {
		    ($opt, $value) = parse_vmfw_option($line);
		}
		$res->{options}->{$opt} = $value;
	    };
	    warn "$prefix: $@" if $@;
	} elsif ($section eq 'aliases') {
	    eval {
		my $data = parse_alias($line);
		$res->{aliases}->{lc($data->{name})} = $data;
	    };
	    warn "$prefix: $@" if $@;
	} elsif ($section eq 'rules') {
	    my $rule;
	    eval { $rule = parse_fw_rule($prefix, $line, $cluster_conf, $res, $rule_env); };
	    if (my $err = $@) {
		warn "$prefix: $err";
		next;
	    }
	    push @{$res->{$section}}, $rule;
	} elsif ($section eq 'groups') {
	    my $rule;
	    eval { $rule = parse_fw_rule($prefix, $line, $cluster_conf, undef, 'group'); };
	    if (my $err = $@) {
		warn "$prefix: $err";
		next;
	    }
	    push @{$res->{$section}->{$group}}, $rule;
	} elsif ($section eq 'ipset') {
	    # we can add single line comments to the end of the rule
	    my $comment = decode('utf8', $1) if $line =~ s/#\s*(.*?)\s*$//;

	    $line =~ m/^(\!)?\s*(\S+)\s*$/;
	    my $nomatch = $1;
	    my $cidr = $2;
	    my $errors;

	    if ($nomatch && !$feature_ipset_nomatch) {
		$errors->{nomatch} = "nomatch not supported by kernel";
	    }

	    eval {
		if ($cidr =~ m/^${ip_alias_pattern}$/) {
		    resolve_alias($cluster_conf, $res, $cidr); # make sure alias exists
		} else {
		    $cidr = parse_ip_or_cidr($cidr);
		}
		die "duplicate ipset entry for '$cidr'\n"
		    if defined($curr_group_keys->{$cidr});
	    };
	    if (my $err = $@) {
		chomp $err;
		$errors->{cidr} = $err;
	    }

	    if ($cidr =~ m!/0+$!) {
		$errors->{cidr} = "a zero prefix is not allowed in ipset entries\n";
	    }

	    my $entry = { cidr => $cidr };
	    $entry->{nomatch} = 1 if $nomatch;
	    $entry->{comment} = $comment if $comment;
	    $entry->{errors} =  $errors if $errors;

	    if ($verbose && $errors) {
		warn "$prefix - errors in ipset '$group': $line\n";
		foreach my $p (keys %{$errors}) {
		    warn "  $p: $errors->{$p}\n";
		}
	    }

	    push @{$res->{$section}->{$group}}, $entry;
	    $curr_group_keys->{$cidr} = 1;
	} else {
	    warn "$prefix: skip line - unknown section\n";
	    next;
	}
    }

    return $res;
}

# this is only used to prevent concurrent runs of rule compilation/application
# see lock_*_conf for cfs locks protectiong config modification
sub run_locked {
    my ($code, @param) = @_;

    my $timeout = 10;

    my $res = lock_file($pve_fw_lock_filename, $timeout, $code, @param);

    die $@ if $@;

    return $res;
}

sub read_local_vm_config {

    my $qemu = {};
    my $lxc = {};

    my $vmdata = { qemu => $qemu, lxc => $lxc };

    my $vmlist = PVE::Cluster::get_vmlist();
    return $vmdata if !$vmlist || !$vmlist->{ids};
    my $ids = $vmlist->{ids};

    foreach my $vmid (keys %$ids) {
	next if !$vmid; # skip VE0
	my $d = $ids->{$vmid};
	next if !$d->{node} || $d->{node} ne $nodename;
	next if !$d->{type};
	if ($d->{type} eq 'qemu') {
	    if ($have_qemu_server) {
		my $cfspath = PVE::QemuConfig->cfs_config_path($vmid);
		if (my $conf = PVE::Cluster::cfs_read_file($cfspath)) {
		    $qemu->{$vmid} = $conf;
		}
	    }
        } elsif ($d->{type} eq 'lxc') {
	    if ($have_lxc) {
		my $cfspath = PVE::LXC::Config->cfs_config_path($vmid);
		if (my $conf = PVE::Cluster::cfs_read_file($cfspath)) {
		    $lxc->{$vmid} = $conf;
		}
	    }
	}
    }

    return $vmdata;
};

# FIXME: move use sites over to moved helper and break older packages, then remove this here
sub lock_vmfw_conf {
    return PVE::Firewall::Helpers::lock_vmfw_conf(@_);
}

sub load_vmfw_conf {
    my ($cluster_conf, $rule_env, $vmid, $dir) = @_;

    $dir = $pvefw_conf_dir if !defined($dir);
    my $filename = "$dir/$vmid.fw";

    my $empty_conf = {
	rules => [],
	options => {},
	aliases => {},
	ipset => {} ,
	ipset_comments => {},
    };

    my $vmfw_conf = generic_fw_config_parser($filename, $cluster_conf, $empty_conf, $rule_env);
    $vmfw_conf->{vmid} = $vmid;

    return $vmfw_conf;
}

my $format_rules = sub {
    my ($rules, $allow_iface) = @_;

    my $raw = '';

    foreach my $rule (@$rules) {
	if ($rule->{type} eq  'in' || $rule->{type} eq 'out' || $rule->{type} eq 'group') {
	    $raw .= '|' if defined($rule->{enable}) && !$rule->{enable};
	    $raw .= uc($rule->{type});
	    if ($rule->{macro}) {
		$raw .= " $rule->{macro}($rule->{action})";
	    } else {
		$raw .= " " . $rule->{action};
	    }
	    if ($allow_iface && $rule->{iface}) {
		$raw .= " -i $rule->{iface}";
	    }

	    if ($rule->{type} ne  'group')  {
		$raw .= " -source $rule->{source}" if $rule->{source};
		$raw .= " -dest $rule->{dest}" if $rule->{dest};
		$raw .= " -p $rule->{proto}" if $rule->{proto};
		$raw .= " -dport $rule->{dport}" if $rule->{dport};
		$raw .= " -sport $rule->{sport}" if $rule->{sport};
		$raw .= " -log $rule->{log}" if $rule->{log};
		$raw .= " -icmp-type $rule->{'icmp-type'}" if defined($rule->{'icmp-type'}) && $rule->{'icmp-type'} ne '';
	    }

	    $raw .= " # " . encode('utf8', $rule->{comment})
		if $rule->{comment} && $rule->{comment} !~ m/^\s*$/;
	    $raw .= "\n";
	} else {
	    die "unknown rule type '$rule->{type}'";
	}
    }

    return $raw;
};

my $format_options = sub {
    my ($options) = @_;

    my $raw = '';

    $raw .= "[OPTIONS]\n\n";
    foreach my $opt (keys %$options) {
	$raw .= "$opt: $options->{$opt}\n";
    }
    $raw .= "\n";

    return $raw;
};

my $format_aliases = sub {
    my ($aliases) = @_;

    my $raw = '';

    $raw .= "[ALIASES]\n\n";
    foreach my $k (keys %$aliases) {
	my $e = $aliases->{$k};
	$raw .= "$e->{name} $e->{cidr}";
	$raw .= " # " . encode('utf8', $e->{comment})
	    if $e->{comment} && $e->{comment} !~ m/^\s*$/;
	$raw .= "\n";
    }
    $raw .= "\n";

    return $raw;
};

my $format_ipsets = sub {
    my ($fw_conf) = @_;

    my $raw = '';

    foreach my $ipset (sort keys %{$fw_conf->{ipset}}) {
	if (my $comment = $fw_conf->{ipset_comments}->{$ipset}) {
	    my $utf8comment = encode('utf8', $comment);
	    $raw .= "[IPSET $ipset] # $utf8comment\n\n";
	} else {
	    $raw .= "[IPSET $ipset]\n\n";
	}
	my $options = $fw_conf->{ipset}->{$ipset};

	my $nethash = {};
	foreach my $entry (@$options) {
	    my $cidr = $entry->{cidr};
	    if (defined($nethash->{$cidr})) {
		warn "ignoring duplicate ipset entry '$cidr'\n";
		next;
	    }

	    $nethash->{$cidr} = $entry;
	}

	foreach my $cidr (sort keys %$nethash) {
	    my $entry = $nethash->{$cidr};
	    my $line = $entry->{nomatch} ? '!' : '';
	    $line .= $entry->{cidr};
	    $line .= " # " . encode('utf8', $entry->{comment})
		if $entry->{comment} && $entry->{comment} !~ m/^\s*$/;
	    $raw .= "$line\n";
	}

	$raw .= "\n";
    }

    return $raw;
};

sub save_vmfw_conf {
    my ($vmid, $vmfw_conf) = @_;

    my $raw = '';

    my $options = $vmfw_conf->{options};
    $raw .= &$format_options($options) if $options && scalar(keys %$options);

    my $aliases = $vmfw_conf->{aliases};
    $raw .= &$format_aliases($aliases) if $aliases && scalar(keys %$aliases);

    $raw .= &$format_ipsets($vmfw_conf) if $vmfw_conf->{ipset};

    my $rules = $vmfw_conf->{rules} || [];
    if ($rules && scalar(@$rules)) {
	$raw .= "[RULES]\n\n";
	$raw .= &$format_rules($rules, 1);
	$raw .= "\n";
    }

    my $filename = "$pvefw_conf_dir/$vmid.fw";
    if ($raw) {
	mkdir $pvefw_conf_dir;
	PVE::Tools::file_set_contents($filename, $raw);
    } else {
	unlink $filename;
    }
}

# FIXME: remove with 8.0 and break older qemu-server/pve-container
sub remove_vmfw_conf {
    return PVE::Firewall::Helpers::remove_vmfw_conf(@_);
}

# FIXME: remove with 8.0 and break older qemu-server/pve-container
sub clone_vmfw_conf {
    return PVE::Firewall::Helpers::clone_vmfw_conf(@_);
}

sub read_vm_firewall_configs {
    my ($cluster_conf, $vmdata, $dir) = @_;

    my $vmfw_configs = {};

    foreach my $vmid (keys %{$vmdata->{qemu}}) {
	my $vmfw_conf = load_vmfw_conf($cluster_conf, 'vm', $vmid, $dir);
	next if !$vmfw_conf->{options}; # skip if file does not exist
	$vmfw_configs->{$vmid} = $vmfw_conf;
    }
    foreach my $vmid (keys %{$vmdata->{lxc}}) {
        my $vmfw_conf = load_vmfw_conf($cluster_conf, 'ct', $vmid, $dir);
        next if !$vmfw_conf->{options}; # skip if file does not exist
        $vmfw_configs->{$vmid} = $vmfw_conf;
    }

    return $vmfw_configs;
}

sub get_option_log_level {
    my ($options, $k) = @_;

    my $v = $options->{$k};
    $v = $default_log_level if !defined($v);

    return undef if $v eq '' || $v eq 'nolog';

    return $v if defined($log_level_hash->{$v});

    warn "unknown log level ($k = '$v')\n";

    return undef;
}

sub generate_std_chains {
    my ($ruleset, $options, $ipversion) = @_;

    my $std_chains = $pve_std_chains->{$ipversion} || die "internal error";

    my $loglevel = get_option_log_level($options, 'smurf_log_level');
    my $chain = 'PVEFW-smurflog';
    if ( $std_chains->{$chain} ) {
	foreach my $r (@{$std_chains->{$chain}}) {
	  $r->{log} = $loglevel;
	}
    }

    # same as shorewall logflags action.
    $loglevel = get_option_log_level($options, 'tcp_flags_log_level');
    $chain = 'PVEFW-logflags';
    if ( $std_chains->{$chain} ) {
	foreach my $r (@{$std_chains->{$chain}}) {
	  $r->{log} = $loglevel;
	}
    }

    foreach my $chain (keys %$std_chains) {
	ruleset_create_chain($ruleset, $chain);
	foreach my $rule (@{$std_chains->{$chain}}) {
	    if (ref($rule)) {
		ruleset_generate_rule($ruleset, $chain, $ipversion, $rule, 0);
	    } else {
		die "rule $rule as string - should not happen";
	    }
	}
    }
}

sub generate_ipset_chains {
    my ($ipset_ruleset, $clusterfw_conf, $fw_conf, $device_ips, $ipsets) = @_;

    foreach my $ipset (keys %{$ipsets}) {

	my $options = $ipsets->{$ipset};

	if ($device_ips && $ipset =~ /^ipfilter-(net\d+)$/) {
	    if (my $ips = $device_ips->{$1}) {
		$options = [@$options, @$ips];
	    }
	}

	# remove duplicates
	my $nethash = {};
	foreach my $entry (@$options) {
	    next if $entry->{errors}; # skip entries with errors
	    eval {
		my ($cidr, $ver);
		if ($entry->{cidr} =~ m/^${ip_alias_pattern}$/) {
		    ($cidr, $ver) = resolve_alias($clusterfw_conf, $fw_conf, $entry->{cidr});
		} else {
		    ($cidr, $ver) = parse_ip_or_cidr($entry->{cidr});
		}
		#http://backreference.org/2013/03/01/ipv6-address-normalization/
		if ($ver == 6) {
		    # ip_compress_address takes an address only, no CIDR
		    my ($addr, $prefix_len) = ($cidr =~ m@^([^/]*)(/.*)?$@);
		    $cidr = lc(Net::IP::ip_compress_address($addr, 6));
		    $cidr .= $prefix_len if defined($prefix_len);
		    $cidr =~ s|/128$||;
		} else {
		    $cidr =~ s|/32$||;
		}

		$nethash->{$ver}->{$cidr} = { cidr => $cidr, nomatch => $entry->{nomatch} };
	    };
	    warn $@ if $@;
	}

	foreach my $ipversion (4, 6) {
	    my $data = $nethash->{$ipversion};

	    my $name = compute_ipset_chain_name($fw_conf->{vmid}, $ipset, $ipversion);

	    my $hashsize = scalar(@$options);
	    if ($hashsize <= 64) {
		$hashsize = 64;
	    } else {
		$hashsize = round_powerof2($hashsize);
	    }

	    my $bucketsize = 12; # lower than the default of 14, faster but slightly more memory use

	    my $family = $ipversion == "6" ? "inet6" : "inet";

	    $ipset_ruleset->{$name} = [
		"create $name hash:net family $family hashsize $hashsize maxelem $hashsize bucketsize $bucketsize"
	    ];

	    foreach my $cidr (sort keys %$data) {
		my $entry = $data->{$cidr};

		my $cmd = "add $name $cidr";
		if ($entry->{nomatch}) {
		    if ($feature_ipset_nomatch) {
			push @{$ipset_ruleset->{$name}}, "$cmd nomatch";
		    } else {
			warn "ignore !$cidr - nomatch not supported by kernel\n";
		    }
		} else {
		    push @{$ipset_ruleset->{$name}}, $cmd;
		}
	    }
	}
    }
}

sub round_powerof2 {
    my ($int) = @_;

    $int--;
    $int |= $int >> $_ foreach (1,2,4,8,16);
    return ++$int;
}

my $set_global_log_ratelimit = sub {
    my $cluster_opts = shift;

    $global_log_ratelimit = '--limit 1/sec';
    if (defined(my $log_rlimit = $cluster_opts->{log_ratelimit})) {
	my $ll_format = $cluster_option_properties->{log_ratelimit}->{format};
	my $limit = PVE::JSONSchema::parse_property_string($ll_format, $log_rlimit);

	if ($limit->{enable}) {
	    if (my $rate = $limit->{rate}) {
		$global_log_ratelimit = "--limit $rate";
	    }
	    if (my $burst = $limit->{burst}) {
		$global_log_ratelimit .= " --limit-burst $burst";
	    }
	} else {
	    $global_log_ratelimit = undef;
	}
    }
};

sub lock_clusterfw_conf {
    my ($timeout, $code, @param) = @_;

    my $res = PVE::Cluster::cfs_lock_firewall("cluster", $timeout, $code, @param);
    die $@ if $@;

    return $res;
}

sub load_clusterfw_conf {
    my ($filename) = @_;

    $filename = $clusterfw_conf_filename if !defined($filename);
    my $empty_conf = {
	rules => [],
	options => {},
	aliases => {},
	groups => {},
	group_comments => {},
	ipset => {} ,
	ipset_comments => {},
    };

    my $cluster_conf = generic_fw_config_parser($filename, $empty_conf, $empty_conf, 'cluster');
    $set_global_log_ratelimit->($cluster_conf->{options});

    return $cluster_conf;
}

sub save_clusterfw_conf {
    my ($cluster_conf) = @_;

    my $raw = '';

    my $options = $cluster_conf->{options};
    $raw .= &$format_options($options) if $options && scalar(keys %$options);

    my $aliases = $cluster_conf->{aliases};
    $raw .= &$format_aliases($aliases) if $aliases && scalar(keys %$aliases);

    $raw .= &$format_ipsets($cluster_conf) if $cluster_conf->{ipset};

    my $rules = $cluster_conf->{rules};
    if ($rules && scalar(@$rules)) {
	$raw .= "[RULES]\n\n";
	$raw .= &$format_rules($rules, 1);
	$raw .= "\n";
    }

    if ($cluster_conf->{groups}) {
	foreach my $group (sort keys %{$cluster_conf->{groups}}) {
	    my $rules = $cluster_conf->{groups}->{$group};
	    if (my $comment = $cluster_conf->{group_comments}->{$group}) {
		my $utf8comment = encode('utf8', $comment);
		$raw .= "[group $group] # $utf8comment\n\n";
	    } else {
		$raw .= "[group $group]\n\n";
	    }

	    $raw .= &$format_rules($rules, 0);
	    $raw .= "\n";
	}
    }

    if ($raw) {
	mkdir $pvefw_conf_dir;
	PVE::Tools::file_set_contents($clusterfw_conf_filename, $raw);
    } else {
	unlink $clusterfw_conf_filename;
    }
}

sub lock_hostfw_conf : prototype($$$@) {
    my ($node, $timeout, $code, @param) = @_;

    $node = $nodename if !defined($node);

    my $res = PVE::Cluster::cfs_lock_firewall("host-$node", $timeout, $code, @param);
    die $@ if $@;

    return $res;
}

sub load_hostfw_conf {
    my ($cluster_conf, $filename) = @_;

    $filename = $hostfw_conf_filename if !defined($filename);

    my $empty_conf = { rules => [], options => {}};
    return generic_fw_config_parser($filename, $cluster_conf, $empty_conf, 'host');
}

sub save_hostfw_conf {
    my ($hostfw_conf, $filename) = @_;

    $filename = $hostfw_conf_filename if !defined($filename);

    my $raw = '';

    my $options = $hostfw_conf->{options};
    $raw .= &$format_options($options) if $options && scalar(keys %$options);

    my $rules = $hostfw_conf->{rules};
    if ($rules && scalar(@$rules)) {
	$raw .= "[RULES]\n\n";
	$raw .= &$format_rules($rules, 1);
	$raw .= "\n";
    }

    if ($raw) {
	PVE::Tools::file_set_contents($filename, $raw);
    } else {
	unlink $filename;
    }
}

sub compile {
    my ($cluster_conf, $hostfw_conf, $vmdata, $corosync_conf) = @_;

    my $vmfw_configs;

    # fixme: once we read standard chains from config this needs to be put in test/standard cases below
    $pve_std_chains = dclone($pve_std_chains_conf);

    if ($vmdata) { # test mode
	my $testdir = $vmdata->{testdir} || die "no test directory specified";
	my $filename = "$testdir/cluster.fw";
	$cluster_conf = load_clusterfw_conf($filename);

	$filename = "$testdir/host.fw";
	$hostfw_conf = load_hostfw_conf($cluster_conf, $filename);

	$vmfw_configs = read_vm_firewall_configs($cluster_conf, $vmdata, $testdir);
    } else { # normal operation
	$cluster_conf = load_clusterfw_conf(undef) if !$cluster_conf;

	$hostfw_conf = load_hostfw_conf($cluster_conf, undef) if !$hostfw_conf;

	# cfs_update is handled by daemon or API
	$corosync_conf = PVE::Cluster::cfs_read_file("corosync.conf")
	    if !defined($corosync_conf) && PVE::Corosync::check_conf_exists(1);

	$vmdata = read_local_vm_config();
	$vmfw_configs = read_vm_firewall_configs($cluster_conf, $vmdata, undef);
    }

    return ({},{},{},{}) if !$cluster_conf->{options}->{enable};

    my $localnet;
    if ($cluster_conf->{aliases}->{local_network}) {
	$localnet = $cluster_conf->{aliases}->{local_network}->{cidr};
    } else {
	my $localnet_ver;
	($localnet, $localnet_ver) = parse_ip_or_cidr(local_network() || '127.0.0.0/8');

	$cluster_conf->{aliases}->{local_network} = {
	    name => 'local_network', cidr => $localnet, ipversion => $localnet_ver };
    }

    push @{$cluster_conf->{ipset}->{management}}, { cidr => $localnet };

    my $ruleset = {};
    my $rulesetv6 = {};
    $ruleset->{filter} = compile_iptables_filter($cluster_conf, $hostfw_conf, $vmfw_configs, $vmdata, $corosync_conf, 4);
    $ruleset->{raw} = compile_iptables_raw($cluster_conf, $hostfw_conf, $vmfw_configs, $vmdata, $corosync_conf, 4);
    $rulesetv6->{filter} = compile_iptables_filter($cluster_conf, $hostfw_conf, $vmfw_configs, $vmdata, $corosync_conf, 6);
    $rulesetv6->{raw} = compile_iptables_raw($cluster_conf, $hostfw_conf, $vmfw_configs, $vmdata, $corosync_conf, 6);
    my $ebtables_ruleset = compile_ebtables_filter($cluster_conf, $hostfw_conf, $vmfw_configs, $vmdata);
    my $ipset_ruleset = compile_ipsets($cluster_conf, $vmfw_configs, $vmdata);

    return ($ruleset, $ipset_ruleset, $rulesetv6, $ebtables_ruleset);
}

sub compile_iptables_raw {
    my ($cluster_conf, $hostfw_conf, $vmfw_configs, $vmdata, $corosync_conf, $ipversion) = @_;

    my $ruleset = {};

    my $hostfw_options = $hostfw_conf->{options} || {};
    my $protection_synflood = $hostfw_options->{protection_synflood} || 0;

    if($protection_synflood) {

	my $protection_synflood_rate = $hostfw_options->{protection_synflood_rate} ? $hostfw_options->{protection_synflood_rate} : 200;
	my $protection_synflood_burst = $hostfw_options->{protection_synflood_burst} ? $hostfw_options->{protection_synflood_burst} : 1000;
	my $protection_synflood_limit = $hostfw_options->{protection_synflood_limit} ? $hostfw_options->{protection_synflood_limit} : 3000;
 	my $protection_synflood_expire = $hostfw_options->{nf_conntrack_tcp_timeout_syn_recv} ? $hostfw_options->{nf_conntrack_tcp_timeout_syn_recv} : 60;
	$protection_synflood_expire = $protection_synflood_expire * 1000;
	my $protection_synflood_mask = $ipversion == 4 ? 32 : 64;

	ruleset_create_chain($ruleset, "PVEFW-PREROUTING");
	ruleset_addrule($ruleset, "PVEFW-PREROUTING", "-p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -m hashlimit --hashlimit-above $protection_synflood_rate/sec --hashlimit-burst $protection_synflood_burst --hashlimit-mode srcip --hashlimit-name syn --hashlimit-htable-size 2097152 --hashlimit-srcmask $protection_synflood_mask --hashlimit-htable-expire $protection_synflood_expire", "-j DROP");
    }

    return $ruleset;
}

sub compile_iptables_filter {
    my ($cluster_conf, $hostfw_conf, $vmfw_configs, $vmdata, $corosync_conf, $ipversion) = @_;

    my $ruleset = {};

    ruleset_create_chain($ruleset, "PVEFW-INPUT");
    ruleset_create_chain($ruleset, "PVEFW-OUTPUT");

    ruleset_create_chain($ruleset, "PVEFW-FORWARD");

    my $hostfw_options = $hostfw_conf->{options} || {};

    # fixme: what log level should we use here?
    my $loglevel = get_option_log_level($hostfw_options, "log_level_out");

    my $conn_allow_invalid = $hostfw_options->{nf_conntrack_allow_invalid} // 0;
    ruleset_chain_add_conn_filters($ruleset, "PVEFW-FORWARD", $conn_allow_invalid, "ACCEPT");

    ruleset_create_chain($ruleset, "PVEFW-FWBR-IN");
    ruleset_chain_add_input_filters($ruleset, "PVEFW-FWBR-IN", $ipversion, $hostfw_options, $cluster_conf, $loglevel);

    ruleset_addrule($ruleset, "PVEFW-FORWARD", "-m physdev --physdev-is-bridged --physdev-in fwln+", "-j PVEFW-FWBR-IN");

    ruleset_create_chain($ruleset, "PVEFW-FWBR-OUT");
    ruleset_addrule($ruleset, "PVEFW-FORWARD", "-m physdev --physdev-is-bridged --physdev-out fwln+", "-j PVEFW-FWBR-OUT");

    generate_std_chains($ruleset, $hostfw_options, $ipversion);

    my $hostfw_enable = !(defined($hostfw_options->{enable}) && ($hostfw_options->{enable} == 0));

    if ($hostfw_enable) {
	eval { enable_host_firewall($ruleset, $hostfw_conf, $cluster_conf, $ipversion, $corosync_conf); };
	warn $@ if $@; # just to be sure - should not happen
    }

    # generate firewall rules for QEMU VMs
    foreach my $vmid (sort keys %{$vmdata->{qemu}}) {
	eval {
	    my $conf = $vmdata->{qemu}->{$vmid};
	    my $vmfw_conf = $vmfw_configs->{$vmid};
	    return if !$vmfw_conf || !$vmfw_conf->{options}->{enable};

	    foreach my $netid (sort keys %$conf) {
		next if $netid !~ m/^net(\d+)$/;
		my $net = PVE::QemuServer::parse_net($conf->{$netid});
		next if !$net->{firewall};

		my $iface = "tap${vmid}i$1";
		my $macaddr = $net->{macaddr};
		generate_tap_rules_direction($ruleset, $cluster_conf, $iface, $netid, $macaddr,
		                             $vmfw_conf, $vmid, 'IN', $ipversion);
		generate_tap_rules_direction($ruleset, $cluster_conf, $iface, $netid, $macaddr,
		                             $vmfw_conf, $vmid, 'OUT', $ipversion);
	    }
	};
	warn $@ if $@; # just to be sure - should not happen
    }

    # generate firewall rules for LXC containers
    foreach my $vmid (sort keys %{$vmdata->{lxc}}) {
	eval {
	    my $conf = $vmdata->{lxc}->{$vmid};
	    my $vmfw_conf = $vmfw_configs->{$vmid};
	    return if !$vmfw_conf || !$vmfw_conf->{options}->{enable};

	    foreach my $netid (sort keys %$conf) {
		next if $netid !~ m/^net(\d+)$/;
		my $net = PVE::LXC::Config->parse_lxc_network($conf->{$netid});
		next if !$net->{firewall};

		my $iface = "veth${vmid}i$1";
		my $macaddr = $net->{hwaddr};
		generate_tap_rules_direction($ruleset, $cluster_conf, $iface, $netid, $macaddr,
		                             $vmfw_conf, $vmid, 'IN', $ipversion);
		generate_tap_rules_direction($ruleset, $cluster_conf, $iface, $netid, $macaddr,
		                             $vmfw_conf, $vmid, 'OUT', $ipversion);
	    }
	};
	warn $@ if $@; # just to be sure - should not happen
    }

    if (ruleset_chain_exist($ruleset, "PVEFW-IPS")){
	ruleset_insertrule($ruleset, "PVEFW-FORWARD", "-m conntrack --ctstate RELATED,ESTABLISHED", "-j PVEFW-IPS");
    }

    return $ruleset;
}

sub mac_to_linklocal {
    my ($macaddr) = @_;
    my @parts = split(/:/, $macaddr);
    # The standard link local address uses the fe80::/64 prefix with the
    # modified EUI-64 identifier derived from the MAC address by flipping the
    # universal/local bit and inserting FF:FE in the middle.
    # See RFC 4291.
    $parts[0] = sprintf("%02x", hex($parts[0]) ^ 0x02);
    my @meui64 = (@parts[0,1,2], 'ff', 'fe', @parts[3,4,5]);
    return "fe80::$parts[0]$parts[1]:$parts[2]FF:FE$parts[3]:$parts[4]$parts[5]";
}

sub compile_ipsets {
    my ($cluster_conf, $vmfw_configs, $vmdata) = @_;

    my $localnet;
    if ($cluster_conf->{aliases}->{local_network}) {
	$localnet = $cluster_conf->{aliases}->{local_network}->{cidr};
    } else {
	my $localnet_ver;
	($localnet, $localnet_ver) = parse_ip_or_cidr(local_network() || '127.0.0.0/8');

	$cluster_conf->{aliases}->{local_network} = {
	    name => 'local_network', cidr => $localnet, ipversion => $localnet_ver };
    }

    push @{$cluster_conf->{ipset}->{management}}, { cidr => $localnet };


    my $ipset_ruleset = {};

    # generate ipsets for QEMU VMs
    foreach my $vmid (keys %{$vmdata->{qemu}}) {
	eval {
	    my $conf = $vmdata->{qemu}->{$vmid};
	    my $vmfw_conf = $vmfw_configs->{$vmid};
	    return if !$vmfw_conf;

	    # When the 'ipfilter' option is enabled every device for which there
	    # is no 'ipfilter-netX' ipset defined gets an implicit empty default
	    # ipset.
	    # The reason is that ipfilter ipsets are always filled with standard
	    # IPv6 link-local filters.
	    my $ipsets = $vmfw_conf->{ipset};
	    my $implicit_sets = {};

	    my $device_ips = {};
	    foreach my $netid (keys %$conf) {
		next if $netid !~ m/^net(\d+)$/;
		my $net = PVE::QemuServer::parse_net($conf->{$netid});
		next if !$net->{firewall};

		if ($vmfw_conf->{options}->{ipfilter} && !$ipsets->{"ipfilter-$netid"}) {
		    $implicit_sets->{"ipfilter-$netid"} = [];
		}

		my $macaddr = $net->{macaddr};
		my $linklocal = mac_to_linklocal($macaddr);
		$device_ips->{$netid} = [
		    { cidr => $linklocal },
		    { cidr => 'fe80::/10', nomatch => 1 }
		];
	    }

	    generate_ipset_chains($ipset_ruleset, $cluster_conf, $vmfw_conf, $device_ips, $ipsets);
	    generate_ipset_chains($ipset_ruleset, $cluster_conf, $vmfw_conf, $device_ips, $implicit_sets);
	};
	warn $@ if $@; # just to be sure - should not happen
    }

    # generate firewall rules for LXC containers
    foreach my $vmid (keys %{$vmdata->{lxc}}) {
	eval {
	    my $conf = $vmdata->{lxc}->{$vmid};
	    my $vmfw_conf = $vmfw_configs->{$vmid};
	    return if !$vmfw_conf;

	    # When the 'ipfilter' option is enabled every device for which there
	    # is no 'ipfilter-netX' ipset defined gets an implicit empty default
	    # ipset.
	    # The reason is that ipfilter ipsets are always filled with standard
	    # IPv6 link-local filters, as well as the IP addresses configured
	    # for the container.
	    my $ipsets = $vmfw_conf->{ipset};
	    my $implicit_sets = {};

	    my $device_ips = {};
	    foreach my $netid (keys %$conf) {
		next if $netid !~ m/^net(\d+)$/;
		my $net = PVE::LXC::Config->parse_lxc_network($conf->{$netid});
		next if !$net->{firewall};

		if ($vmfw_conf->{options}->{ipfilter} && !$ipsets->{"ipfilter-$netid"}) {
		    $implicit_sets->{"ipfilter-$netid"} = [];
		}

		my $macaddr = $net->{hwaddr};
		my $linklocal = mac_to_linklocal($macaddr);
		my $set = $device_ips->{$netid} = [
		    { cidr => $linklocal },
		    { cidr => 'fe80::/10', nomatch => 1 }
		];
		if (defined($net->{ip}) && $net->{ip} =~ m!^($IPV4RE)(?:/\d+)?$!) {
		    push @$set, { cidr => $1 };
		}
		if (defined($net->{ip6}) && $net->{ip6} =~ m!^($IPV6RE)(?:/\d+)?$!) {
		    push @$set, { cidr => $1 };
		}
	    }

	    generate_ipset_chains($ipset_ruleset, $cluster_conf, $vmfw_conf, $device_ips, $ipsets);
	    generate_ipset_chains($ipset_ruleset, $cluster_conf, $vmfw_conf, $device_ips, $implicit_sets);
	};
	warn $@ if $@; # just to be sure - should not happen
    }

    generate_ipset_chains($ipset_ruleset, undef, $cluster_conf, undef, $cluster_conf->{ipset});

    return $ipset_ruleset;
}

sub compile_ebtables_filter {
    my ($cluster_conf, $hostfw_conf, $vmfw_configs, $vmdata) = @_;

    if (!($cluster_conf->{options}->{ebtables} // 1)) {
	return {};
    }

    my $ruleset = {};

    ruleset_create_chain($ruleset, "PVEFW-FORWARD");

    ruleset_create_chain($ruleset, "PVEFW-FWBR-OUT");
    #for ipv4 and ipv6, check macaddress in iptables, so we use conntrack 'ESTABLISHED', to speedup rules
    ruleset_addrule($ruleset, 'PVEFW-FORWARD', '-p IPv4', '-j ACCEPT');
    ruleset_addrule($ruleset, 'PVEFW-FORWARD', '-p IPv6', '-j ACCEPT');
    ruleset_addrule($ruleset, 'PVEFW-FORWARD', '-o fwln+', '-j PVEFW-FWBR-OUT');

    # generate firewall rules for QEMU VMs
    foreach my $vmid (sort keys %{$vmdata->{qemu}}) {
	eval {
	    my $conf = $vmdata->{qemu}->{$vmid};
	    my $vmfw_conf = $vmfw_configs->{$vmid};
	    return if !$vmfw_conf || !$vmfw_conf->{options}->{enable};
	    my $ipsets = $vmfw_conf->{ipset};

	    foreach my $netid (sort keys %$conf) {
		next if $netid !~ m/^net(\d+)$/;
		my $net = PVE::QemuServer::parse_net($conf->{$netid});
		next if !$net->{firewall};
		my $iface = "tap${vmid}i$1";
		my $macaddr = $net->{macaddr};
		my $arpfilter = [];
		if (defined(my $ipset = $ipsets->{"ipfilter-$netid"})) {
		    foreach my $ipaddr (@$ipset) {
			my($ip, $version) = parse_ip_or_cidr($ipaddr->{cidr});
			next if !$ip || ($version && $version != 4);
			push(@$arpfilter, $ip);
		    }
		}
		generate_tap_layer2filter($ruleset, $iface, $macaddr, $vmfw_conf, $vmid, $arpfilter);
	    }
	};
	warn $@ if $@; # just to be sure - should not happen
    }

    # generate firewall rules for LXC containers
    foreach my $vmid (sort keys %{$vmdata->{lxc}}) {
	eval {
	    my $conf = $vmdata->{lxc}->{$vmid};

	    my $vmfw_conf = $vmfw_configs->{$vmid};
	    return if !$vmfw_conf || !$vmfw_conf->{options}->{enable};
	    my $ipsets = $vmfw_conf->{ipset};

	    foreach my $netid (sort keys %$conf) {
		next if $netid !~ m/^net(\d+)$/;
		my $net = PVE::LXC::Config->parse_lxc_network($conf->{$netid});
		next if !$net->{firewall};
		my $iface = "veth${vmid}i$1";
		my $macaddr = $net->{hwaddr};
		my $arpfilter = [];
		if (defined(my $ipset = $ipsets->{"ipfilter-$netid"})) {
		    foreach my $ipaddr (@$ipset) {
			my($ip, $version) = parse_ip_or_cidr($ipaddr->{cidr});
			next if !$ip || ($version && $version != 4);
			push(@$arpfilter, $ip);
		    }
		}
		if (defined(my $ip = $net->{ip}) && $vmfw_conf->{options}->{ipfilter}) {
		    # ebtables changes this to a .0/MASK network but we just
		    # want the address here, no network - see #2193
		    $ip =~ s|/(\d+)$||;
		    if ($ip ne 'dhcp') {
			push @$arpfilter, $ip;
		    }
		}
		generate_tap_layer2filter($ruleset, $iface, $macaddr, $vmfw_conf, $vmid, $arpfilter);
	    }
	};
	warn $@ if $@; # just to be sure - should not happen
    }

    return $ruleset;
}

sub generate_tap_layer2filter {
    my ($ruleset, $iface, $macaddr, $vmfw_conf, $vmid, $arpfilter) = @_;
    my $options = $vmfw_conf->{options};

    my $tapchain = $iface."-OUT";

    # ebtables remove zeros from mac pairs
    $macaddr =~ s/0([0-9a-f])/$1/ig;
    $macaddr = lc($macaddr);

    ruleset_create_chain($ruleset, $tapchain);

    if (defined($macaddr) && !(defined($options->{macfilter}) && $options->{macfilter} == 0)) {
	ruleset_addrule($ruleset, $tapchain, "-s ! $macaddr", '-j DROP');
    }

    if (@$arpfilter){
	my $arpchain = $tapchain."-ARP";
	ruleset_addrule($ruleset, $tapchain, "-p ARP", "-j $arpchain");
	ruleset_create_chain($ruleset, $arpchain);

	foreach my $ip (@{$arpfilter}) {
	    ruleset_addrule($ruleset, $arpchain, "-p ARP --arp-ip-src $ip", '-j RETURN');
	}
	ruleset_addrule($ruleset, $arpchain, '', '-j DROP');
    }

    if (defined($options->{layer2_protocols})){
	my $protochain = $tapchain."-PROTO";
	ruleset_addrule($ruleset, $tapchain, '', "-j $protochain");
	ruleset_create_chain($ruleset, $protochain);

	foreach my $proto (split(/,/, $options->{layer2_protocols})) {
	    ruleset_addrule($ruleset, $protochain, "-p $proto", '-j RETURN');
	}
	ruleset_addrule($ruleset, $protochain, '', '-j DROP');
    }

    ruleset_addrule($ruleset, $tapchain, '', '-j ACCEPT');

    ruleset_addrule($ruleset, 'PVEFW-FWBR-OUT', "-i $iface", "-j $tapchain");
}

# the parameter $change_only_regex changes two things if defined:
# * all chains not matching it will be left intact
# * both the $active_chains hash and the returned status_hash have different
#   structure (they contain a key named 'rules').
sub get_ruleset_status {
    my ($ruleset, $active_chains, $digest_fn, $change_only_regex) = @_;

    my $statushash = {};

    foreach my $chain (sort keys %$ruleset) {
	my $rules = $ruleset->{$chain};
	my $sig = &$digest_fn($rules);
	my $oldsig;

	$statushash->{$chain}->{sig} = $sig;
	if (defined($change_only_regex)) {
	    $oldsig = $active_chains->{$chain}->{sig};
	    $statushash->{$chain}->{rules} = $rules;
	} else {
	    $oldsig = $active_chains->{$chain};
	}
	if (!defined($oldsig)) {
	    $statushash->{$chain}->{action} = 'create';
	} else {
	    if ($oldsig eq $sig) {
		$statushash->{$chain}->{action} = 'exists';
	    } else {
		$statushash->{$chain}->{action} = 'update';
	    }
	}
	if ($verbose) {
	    print "$statushash->{$chain}->{action} $chain ($sig)\n";
	    foreach my $cmd (@{$rules}) {
		print "\t$cmd\n";
	    }
	}
    }

    foreach my $chain (sort keys %$active_chains) {
	next if defined($ruleset->{$chain});
	my $action = 'delete';
	my $sig = $active_chains->{$chain};
	if (defined($change_only_regex)) {
	    $action = 'ignore' if ($chain !~ m/$change_only_regex/);
	    $statushash->{$chain}->{rules} = $active_chains->{$chain}->{rules};
	    $statushash->{$chain}->{policy} = $active_chains->{$chain}->{policy};
	    $sig = $sig->{sig};
	}
	$statushash->{$chain}->{action} = $action;
	$statushash->{$chain}->{sig} = $sig;
	print "$action $chain ($sig)\n" if $verbose;
    }

    return $statushash;
}

sub print_sig_rule {
    my ($chain, $sig) = @_;

    # We just use this to store a SHA1 checksum used to detect changes
    return "-A $chain -m comment --comment \"PVESIG:$sig\"\n";
}

sub get_ruleset_cmdlist {
    my ($ruleset, $iptablescmd, $table) = @_;

    $table = 'filter' if !$table;

    my $cmdlist = "*$table\n"; # we pass this to iptables-restore;

    my ($active_chains, $hooks) = iptables_get_chains($iptablescmd, $table);
    my $statushash = get_ruleset_status($ruleset, $active_chains, \&iptables_chain_digest);

    # create missing chains first
    foreach my $chain (sort keys %$ruleset) {
	my $stat = $statushash->{$chain};
	die "internal error" if !$stat;
	next if $stat->{action} ne 'create';

	$cmdlist .= ":$chain - [0:0]\n";
    }

    foreach my $h (qw(INPUT OUTPUT FORWARD PREROUTING)) {
	my $chain = "PVEFW-$h";
	if ($ruleset->{$chain} && !$hooks->{$h}) {
	    $cmdlist .= "-A $h -j $chain\n";
	}
    }

    foreach my $chain (sort keys %$ruleset) {
	my $stat = $statushash->{$chain};
	die "internal error" if !$stat;

	if ($stat->{action} eq 'update' || $stat->{action} eq 'create') {
	    $cmdlist .= "-F $chain\n";
	    foreach my $cmd (@{$ruleset->{$chain}}) {
		$cmdlist .= "$cmd\n";
	    }
	    $cmdlist .= print_sig_rule($chain, $stat->{sig});
	} elsif ($stat->{action} eq 'delete') {
	    die "internal error"; # this should not happen
	} elsif ($stat->{action} eq 'exists') {
	    # do nothing
	} else {
	    die "internal error - unknown status '$stat->{action}'";
	}
    }

    foreach my $chain (keys %$statushash) {
	next if $statushash->{$chain}->{action} ne 'delete';
	$cmdlist .= "-F $chain\n";
    }
    foreach my $chain (keys %$statushash) {
	next if $statushash->{$chain}->{action} ne 'delete';
	next if $chain eq 'PVEFW-INPUT';
	next if $chain eq 'PVEFW-OUTPUT';
	next if $chain eq 'PVEFW-FORWARD';
	next if $chain eq 'PVEFW-PREROUTING';
	$cmdlist .= "-X $chain\n";
    }

    my $changes = $cmdlist ne "*$table\n" ? 1 : 0;

    $cmdlist .= "COMMIT\n";

    return wantarray ? ($cmdlist, $changes) : $cmdlist;
}

my $pve_ebtables_chainname_regex = qr/PVEFW-\S+|(?:tap|veth)\d+i\d+-(?:IN|OUT)/;

sub get_ebtables_cmdlist {
    my ($ruleset) = @_;

    my $changes = 0;
    my $cmdlist = "*filter\n";

    my $active_chains = ebtables_get_chains();
    my $statushash = get_ruleset_status($ruleset, $active_chains,
					\&iptables_chain_digest,
					$pve_ebtables_chainname_regex);

    # create chains first and make sure PVE rules are evaluated if active
    my $append_pve_to_forward = '-A FORWARD -j PVEFW-FORWARD';
    my $pve_include = 0;
    foreach my $chain (sort keys %$statushash) {
	next if ($statushash->{$chain}->{action} eq 'delete');
	my $policy = $statushash->{$chain}->{policy} // 'ACCEPT';
	$cmdlist .= ":$chain $policy\n";
	$pve_include = 1 if ($chain eq 'PVEFW-FORWARD');
    }

    foreach my $chain (sort keys %$statushash) {
	my $stat = $statushash->{$chain};
	$changes = 1 if ($stat->{action} !~ 'ignore|exists');
	next if ($stat->{action} eq 'delete');

	foreach my $cmd (@{$statushash->{$chain}->{'rules'}}) {
	    if ($chain eq 'FORWARD' && $cmd eq $append_pve_to_forward) {
		next if ! $pve_include;
		$pve_include = 0;
	    }
	    $cmdlist .= "$cmd\n";
	}
    }
    $cmdlist .= "$append_pve_to_forward\n" if $pve_include;

    return wantarray ? ($cmdlist, $changes) : $cmdlist;
}

sub get_ipset_cmdlist {
    my ($ruleset) = @_;

    my $cmdlist = "";

    my $delete_cmdlist = "";

    my $active_chains = ipset_get_chains();
    my $statushash = get_ruleset_status($ruleset, $active_chains, \&ipset_chain_digest);

    # remove stale _swap chains
    foreach my $chain (keys %$active_chains) {
	if ($chain =~ m/^PVEFW-\S+_swap$/) {
	    $cmdlist .= "destroy $chain\n";
	}
    }

    foreach my $chain (keys %$ruleset) {
	my $stat = $statushash->{$chain};
	die "internal error" if !$stat;

	if ($stat->{action} eq 'create') {
	    foreach my $cmd (@{$ruleset->{$chain}}) {
		$cmdlist .= "$cmd\n";
	    }
	}
    }

    foreach my $chain (keys %$ruleset) {
	my $stat = $statushash->{$chain};
	die "internal error" if !$stat;

	if ($stat->{action} eq 'update') {
	    my $chain_swap = $chain."_swap";

	    foreach my $cmd (@{$ruleset->{$chain}}) {
		$cmd =~ s/$chain/$chain_swap/;
		$cmdlist .= "$cmd\n";
	    }
	    $cmdlist .= "swap $chain_swap $chain\n";
	    $cmdlist .= "flush $chain_swap\n";
	    $cmdlist .= "destroy $chain_swap\n";
	}
    }

     # the remove unused chains
    foreach my $chain (keys %$statushash) {
	next if $statushash->{$chain}->{action} ne 'delete';

	$delete_cmdlist .= "flush $chain\n";
	$delete_cmdlist .= "destroy $chain\n";
    }

    my $changes = ($cmdlist || $delete_cmdlist) ? 1 : 0;

    return ($cmdlist, $delete_cmdlist, $changes);
}

sub apply_ruleset {
    my ($ruleset, $hostfw_conf, $ipset_ruleset, $rulesetv6, $ebtables_ruleset) = @_;

    enable_bridge_firewall();

    my ($ipset_create_cmdlist, $ipset_delete_cmdlist, $ipset_changes) =
	get_ipset_cmdlist($ipset_ruleset);

    my ($cmdlist, $changes) = get_ruleset_cmdlist($ruleset->{filter});
    my ($cmdlistv6, $changesv6) = get_ruleset_cmdlist($rulesetv6->{filter}, "ip6tables");
    my ($ebtables_cmdlist, $ebtables_changes) = get_ebtables_cmdlist($ebtables_ruleset);
    my ($cmdlist_raw, $changes_raw) = get_ruleset_cmdlist($ruleset->{raw}, undef, 'raw');
    my ($cmdlistv6_raw, $changesv6_raw) = get_ruleset_cmdlist($rulesetv6->{raw}, "ip6tables", 'raw');

    if ($verbose) {
	if ($ipset_changes) {
	    print "ipset changes:\n";
	    print $ipset_create_cmdlist if $ipset_create_cmdlist;
	    print $ipset_delete_cmdlist if $ipset_delete_cmdlist;
	}

	if ($changes) {
	    print "iptables changes:\n";
	    print $cmdlist;
	}

	if ($changesv6) {
	    print "ip6tables changes:\n";
	    print $cmdlistv6;
	}

	if ($changes_raw) {
	    print "iptables table raw changes:\n";
	    print $cmdlist_raw;
	}

	if ($changesv6_raw) {
	    print "ip6tables table raw changes:\n";
	    print $cmdlistv6_raw;
	}

	if ($ebtables_changes) {
	    print "ebtables changes:\n";
	    print $ebtables_cmdlist;
	}
    }

    my $tmpfile = "$pve_fw_status_dir/ipsetcmdlist1";
    PVE::Tools::file_set_contents($tmpfile, $ipset_create_cmdlist || '');

    ipset_restore_cmdlist($ipset_create_cmdlist);

    $tmpfile = "$pve_fw_status_dir/ip4cmdlist";
    PVE::Tools::file_set_contents($tmpfile, $cmdlist || '');

    iptables_restore_cmdlist($cmdlist);

    $tmpfile = "$pve_fw_status_dir/ip4cmdlistraw";
    PVE::Tools::file_set_contents($tmpfile, $cmdlist_raw || '');

    iptables_restore_cmdlist($cmdlist_raw, 'raw');

    $tmpfile = "$pve_fw_status_dir/ip6cmdlist";
    PVE::Tools::file_set_contents($tmpfile, $cmdlistv6 || '');

    ip6tables_restore_cmdlist($cmdlistv6);

    $tmpfile = "$pve_fw_status_dir/ip6cmdlistraw";
    PVE::Tools::file_set_contents($tmpfile, $cmdlistv6_raw || '');

    ip6tables_restore_cmdlist($cmdlistv6_raw, 'raw');

    $tmpfile = "$pve_fw_status_dir/ipsetcmdlist2";
    PVE::Tools::file_set_contents($tmpfile, $ipset_delete_cmdlist || '');

    ipset_restore_cmdlist($ipset_delete_cmdlist) if $ipset_delete_cmdlist;

    ebtables_restore_cmdlist($ebtables_cmdlist);

    $tmpfile = "$pve_fw_status_dir/ebtablescmdlist";
    PVE::Tools::file_set_contents($tmpfile, $ebtables_cmdlist || '');

    # test: re-read status and check if everything is up to date
    my $ruleset_filter = $ruleset->{filter};
    my $active_chains = iptables_get_chains();
    my $statushash = get_ruleset_status($ruleset_filter, $active_chains, \&iptables_chain_digest);

    my $errors;
    foreach my $chain (sort keys %$ruleset_filter) {
	my $stat = $statushash->{$chain};
	if ($stat->{action} ne 'exists') {
	    warn "unable to update chain '$chain'\n";
	    $errors = 1;
	}
    }

    my $rulesetv6_filter = $rulesetv6->{filter};
    my $active_chainsv6 = iptables_get_chains("ip6tables");
    my $statushashv6 = get_ruleset_status($rulesetv6_filter, $active_chainsv6, \&iptables_chain_digest);

    foreach my $chain (sort keys %$rulesetv6_filter) {
	my $stat = $statushashv6->{$chain};
	if ($stat->{action} ne 'exists') {
	    warn "unable to update chain '$chain'\n";
	    $errors = 1;
	}
    }

    my $ruleset_raw = $ruleset->{raw};
    my $active_chains_raw = iptables_get_chains(undef, 'raw');
    my $statushash_raw = get_ruleset_status($ruleset_raw, $active_chains_raw, \&iptables_chain_digest);

    foreach my $chain (sort keys %$ruleset_raw) {
	my $stat = $statushash_raw->{$chain};
	if ($stat->{action} ne 'exists') {
	    warn "unable to update chain '$chain'\n";
	    $errors = 1;
	}
    }

    my $rulesetv6_raw = $rulesetv6->{raw};
    my $active_chainsv6_raw = iptables_get_chains("ip6tables", 'raw');
    my $statushashv6_raw = get_ruleset_status($rulesetv6_raw, $active_chainsv6_raw, \&iptables_chain_digest);

    foreach my $chain (sort keys %$rulesetv6_raw) {
	my $stat = $statushashv6_raw->{$chain};
	if ($stat->{action} ne 'exists') {
	    warn "unable to update chain '$chain'\n";
	    $errors = 1;
	}
    }

    my $active_ebtables_chains = ebtables_get_chains();
    my $ebtables_statushash = get_ruleset_status($ebtables_ruleset,
				$active_ebtables_chains, \&iptables_chain_digest,
				$pve_ebtables_chainname_regex);

    foreach my $chain (sort keys %$ebtables_ruleset) {
	my $stat = $ebtables_statushash->{$chain};
	if ($stat->{action} ne 'exists') {
	    warn "ebtables : unable to update chain '$chain'\n";
	    $errors = 1;
	}
    }

    die "unable to apply firewall changes\n" if $errors;

    update_nf_conntrack_max($hostfw_conf);

    update_nf_conntrack_tcp_timeout_established($hostfw_conf);

    update_nf_conntrack_tcp_timeout_syn_recv($hostfw_conf);

    update_nf_conntrack_logging($hostfw_conf);
}

sub update_nf_conntrack_max {
    my ($hostfw_conf) = @_;

    my $max = 262144; # reasonable default (2^16 * 4), see nf_conntrack-sysctl docs

    my $options = $hostfw_conf->{options} || {};

    if (defined($options->{nf_conntrack_max}) && ($options->{nf_conntrack_max} > $max)) {
	$max = $options->{nf_conntrack_max};
	$max = int(($max+ 8191)/8192)*8192; # round to multiples of 8192
    }

    my $filename_nf_conntrack_max = "/proc/sys/net/nf_conntrack_max";
    my $filename_hashsize = "/sys/module/nf_conntrack/parameters/hashsize";

    my $current = int(PVE::Tools::file_read_firstline($filename_nf_conntrack_max) || $max);

    if ($current != $max) {
	my $hashsize = int($max/4);
	PVE::ProcFSTools::write_proc_entry($filename_hashsize, $hashsize);
	PVE::ProcFSTools::write_proc_entry($filename_nf_conntrack_max, $max);
    }
}

sub update_nf_conntrack_tcp_timeout_established {
    my ($hostfw_conf) = @_;

    my $options = $hostfw_conf->{options} || {};

    my $value = defined($options->{nf_conntrack_tcp_timeout_established}) ? $options->{nf_conntrack_tcp_timeout_established} : 432000;

    PVE::ProcFSTools::write_proc_entry("/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_established", $value);
}

sub update_nf_conntrack_tcp_timeout_syn_recv {
    my ($hostfw_conf) = @_;

    my $options = $hostfw_conf->{options} || {};

    my $value = defined($options->{nf_conntrack_tcp_timeout_syn_recv}) ? $options->{nf_conntrack_tcp_timeout_syn_recev} : 60;

    PVE::ProcFSTools::write_proc_entry("/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_syn_recv", $value);
}

my $log_nf_conntrack_enabled = undef;
sub update_nf_conntrack_logging {
    my ($hostfw_conf) = @_;

    my $options = $hostfw_conf->{options} || {};
    my $value = $options->{log_nf_conntrack} || 0;
    if (!defined($log_nf_conntrack_enabled)
	|| $value != $log_nf_conntrack_enabled)
    {
	my $tmpfile = "$pve_fw_status_dir/log_nf_conntrack";
	PVE::Tools::file_set_contents($tmpfile, $value);

	run_command([qw(systemctl try-reload-or-restart pvefw-logger.service)]);
	$log_nf_conntrack_enabled = $value;
    }
}

sub remove_pvefw_chains {

    PVE::Firewall::remove_pvefw_chains_iptables("iptables");
    PVE::Firewall::remove_pvefw_chains_iptables("ip6tables");
    PVE::Firewall::remove_pvefw_chains_iptables("iptables", "raw");
    PVE::Firewall::remove_pvefw_chains_iptables("ip6tables", "raw");
    PVE::Firewall::remove_pvefw_chains_ipset();
    PVE::Firewall::remove_pvefw_chains_ebtables();

}

sub remove_pvefw_chains_iptables {
    my ($iptablescmd, $table) = @_;

    $table = 'filter' if !$table;

    my ($chash, $hooks) = iptables_get_chains($iptablescmd, $table);
    my $cmdlist = "*$table\n";

    foreach my $h (qw(INPUT OUTPUT FORWARD PREROUTING)) {
	if ($hooks->{$h}) {
	    $cmdlist .= "-D $h -j PVEFW-$h\n";
	}
    }

    foreach my $chain (keys %$chash) {
	$cmdlist .= "-F $chain\n";
    }

    foreach my $chain (keys %$chash) {
	$cmdlist .= "-X $chain\n";
    }
    $cmdlist .= "COMMIT\n";

    if($iptablescmd eq "ip6tables") {
	ip6tables_restore_cmdlist($cmdlist, $table);
    } else {
	iptables_restore_cmdlist($cmdlist, $table);
    }
}

sub remove_pvefw_chains_ipset {

    my $ipset_chains = ipset_get_chains();

    my $cmdlist = "";

    foreach my $chain (keys %$ipset_chains) {
	$cmdlist .= "flush $chain\n";
	$cmdlist .= "destroy $chain\n";
    }

    ipset_restore_cmdlist($cmdlist) if $cmdlist;
}

sub remove_pvefw_chains_ebtables {
    # apply empty ruleset = remove all our chains
    ebtables_restore_cmdlist(get_ebtables_cmdlist({}));
}

sub init {
    my $cluster_conf = load_clusterfw_conf();
    my $cluster_options = $cluster_conf->{options};
    my $enable = $cluster_options->{enable};

    return if !$enable;

    # load required modules here
}

sub update {
    my $code = sub {

	my $cluster_conf = load_clusterfw_conf();
	my $cluster_options = $cluster_conf->{options};

	if (!$cluster_options->{enable}) {
	    PVE::Firewall::remove_pvefw_chains();
	    return;
	}

	my $hostfw_conf = load_hostfw_conf($cluster_conf);

	my ($ruleset, $ipset_ruleset, $rulesetv6, $ebtables_ruleset) = compile($cluster_conf, $hostfw_conf);

	apply_ruleset($ruleset, $hostfw_conf, $ipset_ruleset, $rulesetv6, $ebtables_ruleset);
    };

    run_locked($code);
}

1;
