package metadata

components: sources: snmp_trap: {
	_port: 162

	title: "SNMP Trap"

	classes: {
		delivery: "best_effort"
		deployment_roles: ["aggregator"]
		development:   "beta"
		egress_method: "stream"
		stateful:      false
	}

	features: {
		auto_generated:   true
		acknowledgements: false
		multiline: enabled: false
		receive: {
			from: {
				service: services.snmp

				interface: socket: {
					api: {
						title: "SNMP"
						url:   urls.snmp
					}
					direction: "incoming"
					port:      _port
					protocols: ["udp"]
					ssl: "disabled"
				}
			}
			receive_buffer_bytes: enabled: true
			keepalive: enabled:            false
			tls: enabled:                  false
		}
	}

	support: {
		requirements: []
		warnings: [
			"""
				This source supports SNMPv1 and SNMPv2c notifications only. SNMPv3 messages are rejected because [RFC 3414](\(urls.rfc_3414)) USM authentication and timeliness checks, and [RFC 3826](\(urls.rfc_3826)) AES privacy handling, are not implemented.
				""",
		]
	}

	installation: {
		platform_name: null
	}

	configuration: generated.components.sources.snmp_trap.configuration

	output: logs: trap: {
		description: "An individual SNMP trap event"
		fields: {
			snmp_version: {
				description: "The SNMP version of the notification message."
				required:    true
				type: string: {
					examples: ["1", "2c"]
				}
			}
			pdu_type: {
				description: "The SNMP notification PDU type."
				required:    true
				type: string: {
					examples: ["trap_v1", "trap_v2"]
				}
			}
			source_address: {
				description: "The IP address and port of the SNMP agent that sent the notification."
				required:    true
				type: string: {
					examples: ["192.168.1.100:49152"]
				}
			}
			community: {
				description: "The SNMP community string from the trap message."
				required:    true
				type: string: {
					examples: ["public", "private"]
				}
			}
			enterprise_oid: {
				description: "The enterprise OID identifying the device type (SNMPv1 only)."
				required:    false
				type: string: {
					examples: ["1.3.6.1.4.1.8072.3.2.10"]
				}
			}
			agent_address: {
				description: "The IP address of the SNMP agent (SNMPv1 only)."
				required:    false
				type: string: {
					examples: ["192.168.1.100"]
				}
			}
			generic_trap: {
				description: "The generic trap type (SNMPv1 only). Values: 0=coldStart, 1=warmStart, 2=linkDown, 3=linkUp, 4=authenticationFailure, 5=egpNeighborLoss, 6=enterpriseSpecific."
				required:    false
				type: uint: {
					examples: [0, 1, 2, 3, 4, 5, 6]
					unit: null
				}
			}
			generic_trap_name: {
				description: "The RFC 1157 name for the generic trap type (SNMPv1 only)."
				required:    false
				type: string: {
					examples: ["coldStart", "enterpriseSpecific"]
				}
			}
			specific_trap: {
				description: "The specific trap code (SNMPv1 only)."
				required:    false
				type: uint: {
					examples: [1, 2, 100]
					unit: null
				}
			}
			trap_oid: {
				description: "The snmpTrapOID.0 value identifying the notification type. For SNMPv1 traps, this is derived from the generic and specific trap fields as described in [RFC 3584](\(urls.rfc_3584))."
				required:    true
				type: string: {
					examples: ["1.3.6.1.6.3.1.1.5.1"]
				}
			}
			request_id: {
				description: "The request ID from the notification message (SNMPv2c only)."
				required:    false
				type: int: {
					examples: [12345]
					unit: null
				}
			}
			uptime: {
				description: "The TimeTicks system uptime when the notification was generated."
				required:    false
				type: uint: {
					examples: [123456]
					unit: null
				}
			}
			varbinds: {
				description: "An array of variable bindings containing OID, SNMP value type, and string value entries from the notification."
				required:    true
				type: array: items: type: object: options: {
					oid: {
						description: "The OID of the variable."
						required:    true
						type: string: {}
					}
					type: {
						description: "The parsed SNMP value type."
						required:    true
						type: string: {
							examples: ["integer", "octet_string", "object_identifier", "timeticks", "counter32"]
						}
					}
					value: {
						description: "The value of the variable, formatted as a string. Binary SNMP values are formatted as lowercase hexadecimal."
						required:    true
						type: string: {}
					}
					value_bytes_hex: {
						description: "The original bytes for OCTET STRING and other binary SNMP values, encoded as lowercase hexadecimal."
						required:    false
						type: string: {
							examples: ["001122aabbcc", "deadbeef"]
						}
					}
				}
			}
			host: {
				description: "The IP address of the peer that sent the notification. The field name can be changed with the `host_key` option."
				required:    true
				type: string: {
					examples: ["192.168.1.100"]
				}
			}
			source_type: {
				description: "The name of the source type."
				required:    true
				type: string: {
					examples: ["snmp_trap"]
				}
			}
			message: {
				description: "A human-readable summary of the notification."
				required:    true
				type: string: {
					examples: ["SNMPv1 trap from 192.168.1.100:49152 (1.3.6.1.4.1.8072.3.2.10): coldStart"]
				}
			}
			timestamp: {
				description: "The time the trap was received by Vector."
				required:    true
				type: timestamp: {}
			}
		}
	}

	examples: [
		{
			title: "SNMPv2c Trap"
			configuration: {
				address: "0.0.0.0:162"
			}
			input: "[Binary SNMP trap data]"
			output: log: {
				snmp_version:    "2c"
				pdu_type:        "trap_v2"
				source_address:  "192.168.1.100:49152"
				community:       "public"
				request_id:      12345
				trap_oid:        "1.3.6.1.4.1.8072.2.3.0.1"
				uptime:          123456
				varbinds: [
					{oid: "1.3.6.1.2.1.1.3.0", type: "timeticks", value: "123456"},
					{oid: "1.3.6.1.6.3.1.1.4.1.0", type: "object_identifier", value: "1.3.6.1.4.1.8072.2.3.0.1"},
				]
				message:     "SNMPv2c trap from 192.168.1.100:49152: 1.3.6.1.4.1.8072.2.3.0.1"
				host:        "192.168.1.100"
				source_type: "snmp_trap"
				timestamp:   "2024-01-15T10:30:00Z"
			}
		},
	]

	how_it_works: {
		snmp_versions: {
			title: "Supported SNMP Versions"
			body:  """
				This source supports SNMPv1 Trap-PDUs as defined by [RFC 1157](\(urls.rfc_1157))
				and SNMPv2c SNMPv2-Trap-PDUs as defined by
				[RFC 3416](\(urls.rfc_3416)).

				SNMPv1 traps contain enterprise OID, agent address, generic trap type, and
				specific trap code fields. SNMPv2c notifications carry a trap OID and request ID
				instead. So that both versions can be handled the same way, SNMPv1 traps also
				get a `trap_oid` field derived as described in [RFC 3584](\(urls.rfc_3584)).

				SNMPv3 traps are not supported because validating [RFC 3414](\(urls.rfc_3414))
				User-based Security Model authentication and timeliness, and privacy transforms
				such as [RFC 3826](\(urls.rfc_3826)) AES, is required before the source can
				safely accept those messages.
				"""
		}


		community_strings: {
			title: "Community Strings"
			body: """
				Messages whose community string is not valid UTF-8 are rejected as parse errors.

				SNMP community strings are included in the parsed output. SNMPv1 and SNMPv2c
				community strings are sent in plaintext and provide minimal security, so use
				network-level security measures as well when receiving SNMP traps.
				"""
		}

		variable_bindings: {
			title: "Variable Bindings"
			body:  """
				Variable bindings (varbinds) contain the actual data in the trap message. Each
				varbind consists of an OID, a parsed SNMP value type, and a value. Textual values
				are converted to strings for consistency. Binary values are formatted as lowercase
				hexadecimal, and `value_bytes_hex` preserves the original bytes for OCTET STRING,
				BIT STRING, Opaque, NsapAddress, and unknown BER values.

				For SNMPv2c traps, [RFC 3416](\(urls.rfc_3416)) requires the first
				two varbinds to be `sysUpTime.0` and `snmpTrapOID.0`, in that order. Vector
				rejects SNMPv2c notifications that do not follow that ordering or use the wrong
				value types.
				"""
		}


		port_privileges: {
			title: "Port Privileges"
			body: """
				The standard SNMP trap port (162) is a privileged port on Unix systems. You may
				need to run Vector with elevated privileges or use a non-privileged port
				(e.g., 1162) and configure your network to forward traps accordingly.
				"""
		}
	}

	telemetry: metrics: {
		component_received_bytes: components.sources.internal_metrics.output.metrics.component_received_bytes
	}
}
