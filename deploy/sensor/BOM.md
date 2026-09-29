# Sensor hardware

Reference bill of materials for a small office. Parts and roles only.

| Part | Role |
| --- | --- |
| Small x86 box or ARM single-board computer | Host. Runs Suricata with Emerging Threats Open rules. Zeek stays off unless the build asks for it. |
| Second network interface | Dedicated SPAN/mirror or tap port. Management traffic stays on the other interface. |
| Switch mirror port or passive inline tap | Copies office traffic. The default build listens on a SPAN/mirror port. The tap option listens on an inline tap instead. |
| Local disk | Holds the rule set and alert logs. Packet captures are not part of this build. |
