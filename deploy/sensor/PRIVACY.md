# Sensor privacy

There is no payload capture by default.

The reference build writes Suricata alert records with payload, payload-printable, and HTTP body turned off. It does not configure a packet capture log or a file store.

A standard link may also forward flow, DNS, and TLS metadata. A low-bandwidth link, including a satellite link, forwards alerts only. Neither mode includes payloads.

Zeek is off unless the build is run with `--zeek`. That optional file still does not log payloads.

Rule updates pull Emerging Threats Open signatures. They do not turn payload capture on.
