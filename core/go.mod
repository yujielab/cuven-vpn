module github.com/yujielab/cuven-vpn/core

go 1.26.11

require (
	github.com/apernet/hysteria/extras/v2 v2.14.0
	github.com/quic-go/quic-go v0.66.0
	gvisor.dev/gvisor v0.0.0-20260928232755-bd02d2bfb3df
)

require golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect

require (
	github.com/google/btree v1.1.2 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	golang.org/x/crypto v0.59.0
	golang.org/x/exp v0.0.0-20250711185948-6ae5c78190dc // indirect
	golang.org/x/mobile v0.0.0-20261117202452-47699113848a // indirect
	golang.org/x/mod v0.43.0 // indirect
	golang.org/x/net v0.63.0 // indirect
	golang.org/x/sync v0.25.0 // indirect
	golang.org/x/sys v0.50.0 // indirect
	golang.org/x/text v0.44.0 // indirect
	golang.org/x/time v0.16.0 // indirect
	golang.org/x/tools v0.53.0 // indirect
	golang.zx2c4.com/wireguard v0.0.0-20261024220952-b3bc704ef0ee
)

tool (
	golang.org/x/mobile/cmd/gobind
	golang.org/x/mobile/cmd/gomobile
)

// Hysteria extras uses a placeholder for its local core module. Gomobile resolves the full module graph.
replace github.com/apernet/hysteria/core/v2 v2.0.0-00010101000000-000000000000 => github.com/apernet/hysteria/core/v2 v2.14.0
