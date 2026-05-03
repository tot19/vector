A new `snmp_trap` source has been added to receive SNMPv1 traps and SNMPv2c traps/informs over UDP (issue #4567)


The source listens for SNMP notifications on a configurable UDP port (typically port 162) and converts them into log events. Each notification is parsed into structured log data, including community string, version, PDU type, trap identifiers, enterprise OID, and typed variable bindings. SNMPv2c traps and informs validate the RFC 3416 `sysUpTime.0` and `snmpTrapOID.0` varbind ordering, and informs are acknowledged with an RFC 3416 Response-PDU after Vector accepts the event for forwarding. Optional MIB loading resolves RFC 2578 SMIv2 object identifier assignments while preserving numeric OIDs and bounding startup-time file scans.

authors: bachgarash and RoseSecurity
