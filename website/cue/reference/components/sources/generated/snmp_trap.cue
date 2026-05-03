package metadata

generated: components: sources: snmp_trap: configuration: {
	address: {
		description: """
			The address to listen for SNMP traps on.

			SNMP traps are typically sent to UDP port 162.
			"""
		required: true
		type: string: examples: ["0.0.0.0:9000", "systemd", "systemd#3", "0.0.0.0:162", "127.0.0.1:1162"]
	}
	host_key: {
		description: """
			Overrides the name of the log field used to add the peer host to each event.

			The value is the peer host's IP address. For example, `192.168.1.1`.

			By default, the [global `log_schema.host_key` option][global_host_key] is used.

			[global_host_key]: https://vector.dev/docs/reference/configuration/global-options/#log_schema.host_key
			"""
		required: false
		type: string: {}
	}
	mib_paths: {
		description: """
			MIB files or directories to load for OID name resolution.

			Directories are scanned recursively with bounded depth and file count, without following
			symlinked directories. Directory scans load files with common MIB extensions or no
			extension, and each MIB file must be at most 8 MiB. Numeric OIDs are always preserved, and
			resolved names are added in separate metadata fields.
			"""
		required: false
		type: array: {
			default: []
			items: type: string: {}
		}
	}
	receive_buffer_bytes: {
		description: """
			The size of the receive buffer used for the listening socket.

			This should not typically need to be changed.
			"""
		required: false
		type: uint: unit: "bytes"
	}
}
