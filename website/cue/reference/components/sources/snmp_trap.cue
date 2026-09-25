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
			"""
				This source acknowledges SNMPv2c InformRequest-PDUs after Vector accepts the event for forwarding. Unless `communities` is set, informs from any sender are acknowledged. Because InformRequest responses echo request varbinds to the claimed source address, an internet-exposed listener can act as a UDP reflection target. Set `communities` and place the source behind network ACLs or firewall rules appropriate for plaintext SNMPv1 and SNMPv2c traffic.
				""",
		]
	}

	installation: {
		platform_name: null
	}

	configuration: generated.components.sources.snmp_trap.configuration

	output: logs: trap: {
		description: "An individual SNMP trap or inform event"
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
					examples: ["trap_v1", "trap_v2", "inform_request"]
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
			enterprise_oid_name: {
				description: "The Net-SNMP style name of the enterprise OID, such as `SNMPv2-SMI::enterprises.8072.3.2.10` (SNMPv1 only)."
				required:    false
				type: string: {
					examples: ["NET-SNMP-TC::linux"]
				}
			}
			enterprise_oid_module: {
				description: "The MIB module that defined the resolved enterprise OID name (SNMPv1 only)."
				required:    false
				type: string: {
					examples: ["NET-SNMP-TC"]
				}
			}
			enterprise_oid_symbol: {
				description: "The symbol within the defining MIB module for the enterprise OID (SNMPv1 only)."
				required:    false
				type: string: {
					examples: ["linux"]
				}
			}
			enterprise_oid_instance: {
				description: "The OID arcs after the enterprise OID symbol, if the OID extends a known definition (SNMPv1 only)."
				required:    false
				type: string: {
					examples: ["0"]
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
			trap_oid_name: {
				description: "The Net-SNMP style name of the trap OID, using the longest known definition as a prefix."
				required:    false
				type: string: {
					examples: ["SNMPv2-MIB::coldStart", "TEST-MIB::testTrap"]
				}
			}
			trap_oid_module: {
				description: "The MIB module that defined the resolved trap OID name."
				required:    false
				type: string: {
					examples: ["SNMPv2-MIB", "TEST-MIB"]
				}
			}
			trap_oid_symbol: {
				description: "The symbol within the defining MIB module for the trap OID."
				required:    false
				type: string: {
					examples: ["coldStart", "testTrap"]
				}
			}
			trap_oid_instance: {
				description: "The OID arcs after the trap OID symbol, if the OID extends a known definition."
				required:    false
				type: string: {
					examples: ["0"]
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
					oid_name: {
						description: "The Net-SNMP style name of the OID, using the longest known definition as a prefix."
						required:    false
						type: string: {
							examples: ["SNMPv2-MIB::sysUpTime.0", "TEST-MIB::testValue.0"]
						}
					}
					oid_module: {
						description: "The MIB module that defined the resolved OID name."
						required:    false
						type: string: {
							examples: ["SNMPv2-MIB", "TEST-MIB"]
						}
					}
					oid_symbol: {
						description: "The symbol within the defining MIB module for the OID."
						required:    false
						type: string: {
							examples: ["sysUpTime", "testValue"]
						}
					}
					oid_instance: {
						description: "The OID arcs after the symbol, such as the `0` in `SNMPv2-MIB::sysUpTime.0`."
						required:    false
						type: string: {
							examples: ["0"]
						}
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
					value_oid_name: {
						description: "The Net-SNMP style name of the value when the variable value is an ObjectIdentifier."
						required:    false
						type: string: {
							examples: ["SNMPv2-MIB::coldStart", "TEST-MIB::testTrap"]
						}
					}
					value_oid_module: {
						description: "The MIB module that defined the resolved ObjectIdentifier value."
						required:    false
						type: string: {
							examples: ["SNMPv2-MIB", "TEST-MIB"]
						}
					}
					value_oid_symbol: {
						description: "The symbol within the defining MIB module for the ObjectIdentifier value."
						required:    false
						type: string: {
							examples: ["coldStart", "testTrap"]
						}
					}
					value_oid_instance: {
						description: "The OID arcs after the ObjectIdentifier value symbol, if the value extends a known definition."
						required:    false
						type: string: {
							examples: ["0"]
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
				mib_paths: ["/etc/snmp/mibs"]
			}
			input: "[Binary SNMP trap data]"
			output: log: {
				snmp_version:    "2c"
				pdu_type:        "trap_v2"
				source_address:  "192.168.1.100:49152"
				community:       "public"
				request_id:      12345
				trap_oid:        "1.3.6.1.4.1.8072.2.3.0.1"
				trap_oid_name:   "TEST-MIB::testTrap"
				trap_oid_module: "TEST-MIB"
				trap_oid_symbol: "testTrap"
				uptime:          123456
				varbinds: [
					{oid: "1.3.6.1.2.1.1.3.0", oid_name: "SNMPv2-MIB::sysUpTime.0", oid_module: "SNMPv2-MIB", oid_symbol: "sysUpTime", oid_instance: "0", type: "timeticks", value: "123456"},
					{oid: "1.3.6.1.6.3.1.1.4.1.0", oid_name: "SNMPv2-MIB::snmpTrapOID.0", oid_module: "SNMPv2-MIB", oid_symbol: "snmpTrapOID", oid_instance: "0", type: "object_identifier", value: "1.3.6.1.4.1.8072.2.3.0.1", value_oid_name: "TEST-MIB::testTrap", value_oid_module: "TEST-MIB", value_oid_symbol: "testTrap"},
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
				and SNMPv2c SNMPv2-Trap-PDUs and InformRequest-PDUs as defined by
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

		inform_requests: {
			title: "InformRequest Acknowledgements"
			body:  """
				SNMPv2c InformRequest-PDUs are confirmed notifications. After parsing an inform
				and accepting the event for forwarding, Vector sends an [RFC 3416](\(urls.rfc_3416))
				Response-PDU to the sender with the same request ID and variable bindings,
				`noError` as the error status, and zero as the error index.

				If the full response would exceed Vector's local SNMP message size limit, Vector
				sends the [RFC 3416](\(urls.rfc_3416)) `tooBig` alternate response with an empty
				variable-binding list. If Vector cannot forward the inform event, no Response-PDU
				is sent so the manager can retry according to its own InformRequest timeout policy.
				"""
		}

		community_strings: {
			title: "Community Strings"
			body: """
				Use `communities` to accept only messages carrying one of the listed community
				strings. Messages with other communities are dropped before any event is created,
				informs from them are not acknowledged, and each rejection increments
				`component_errors_total` with `error_type` set to `authentication_failed`.
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

				For SNMPv2c traps and informs, [RFC 3416](\(urls.rfc_3416)) requires the first
				two varbinds to be `sysUpTime.0` and `snmpTrapOID.0`, in that order. Vector
				rejects SNMPv2c notifications that do not follow that ordering or use the wrong
				value types.
				Vector preserves numeric OIDs as received. When MIBs are configured, Vector adds
				resolved names in separate fields for varbind OIDs and ObjectIdentifier values.
				"""
		}

		mib_resolution: {
			title: "MIB Resolution"
			body:  """
				Use `mib_paths` to load MIB files or directories. Directories are scanned
				recursively at source startup with bounded depth, file count, and file size.
				Symlinked directories are skipped, symlinked files are allowed, and directory
				scans include files with `.mib`, `.my`, `.smi`, `.txt`, or no extension. Vector
				resolves [RFC 2578](\(urls.rfc_2578)) SMIv2 object identifier assignments such as
				`OBJECT IDENTIFIER`, `OBJECT-TYPE`, `OBJECT-IDENTITY`, `MODULE-IDENTITY`, and
				`NOTIFICATION-TYPE`, conformance definitions, and SMIv1 `TRAP-TYPE` definitions.

				Resolved names are emitted in fields such as `trap_oid_name`, `enterprise_oid_name`,
				`varbinds[].oid_name`, and `varbinds[].value_oid_name`. Numeric OIDs remain in
				`trap_oid`, `enterprise_oid`, `varbinds[].oid`, and `varbinds[].value`.

				Names follow Net-SNMP's `snmptrapd` conventions: an OID is named after the longest
				known definition that prefixes it, and any remaining arcs are appended, for example
				`IF-MIB::ifDescr.3` or `SNMPv2-SMI::enterprises.8072.1`. A small set of standard
				SMI and SNMPv2 definitions is always known, so most OIDs get a name even without
				`mib_paths`. Table index values are appended as numeric arcs rather than decoded
				from the table's `INDEX` clause.

				References are resolved within each module's own definitions and `IMPORTS` first.
				When several modules define the same OID, SMIv2 modules take precedence over SMIv1
				modules, a module never overrides a definition from a module it imports, and
				otherwise the first loaded definition is used. MIB resolution is best-effort and
				does not evaluate every ASN.1/SMI construct.
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
