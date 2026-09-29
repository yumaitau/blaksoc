export const SYSLOG_LINES = {
  fortinet: `date=2026-06-01 time=01:02:03 devname="FGT60" type="utm" subtype="ips" level="alert" action="dropped" srcip=203.0.113.10 dstip=198.51.100.20 srcport=54321 dstport=443 proto=6 user="ada"`,
  sophos: `device_name="XG230" log_type="Firewall" log_subtype="Denied" src_ip="203.0.113.11" dst_ip="198.51.100.21" src_port=12345 dst_port=22 protocol="TCP" user_name="sam"`,
  draytek: `<134>Jun 1 01:02:03 DrayTek: [FILTER] BLOCK src=203.0.113.12 dst=198.51.100.22 proto=TCP dport=443`,
  mikrotik: `MikroTik firewall,info chain=input action=drop src=203.0.113.13:54321 dst=198.51.100.23:22 proto=tcp`,
  ubiquiti: `<134>1 2026-06-01T01:02:03Z UDM-Pro ubnt 123 - - [WAN_IN-3001-A] SRC=203.0.113.14 DST=198.51.100.24 PROTO=TCP SPT=54321 DPT=443`,
} as const;
