module vanora-relay

go 1.26.0

toolchain go1.27.4

require (
	github.com/coder/websocket v1.8.14
	github.com/gofrs/flock v0.12.1
	github.com/jackc/pgx/v5 v5.13.0
	github.com/pion/logging v0.2.4
	github.com/pion/stun/v4 v4.0.1
	github.com/pion/turn/v4 v4.1.4
	github.com/pion/webrtc/v4 v4.2.27
	github.com/skip2/go-qrcode v0.0.0-20200617195104-da1b6568686e
	github.com/zalando/go-keyring v0.2.7
	golang.org/x/sync v0.25.0
	golang.org/x/sys v0.50.0
	golang.org/x/time v0.14.0
	modernc.org/sqlite v1.63.0
)

require (
	github.com/danieljoos/wincred v1.2.3 // indirect
	github.com/dustin/go-humanize v1.1.0 // indirect
	github.com/godbus/dbus/v5 v5.2.2 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.3 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/ncruces/go-strftime v1.1.0 // indirect
	github.com/pion/datachannel v1.6.4 // indirect
	github.com/pion/dtls/v3 v3.1.16 // indirect
	github.com/pion/ice/v4 v4.4.9 // indirect
	github.com/pion/interceptor v0.1.51 // indirect
	github.com/pion/mdns/v2 v2.2.2 // indirect
	github.com/pion/randutil v0.1.0 // indirect
	github.com/pion/rtcp v1.2.20 // indirect
	github.com/pion/rtp v1.10.6 // indirect
	github.com/pion/sctp v1.12.1 // indirect
	github.com/pion/sdp/v3 v3.0.20 // indirect
	github.com/pion/srtp/v3 v3.1.3 // indirect
	github.com/pion/stun/v3 v3.1.5 // indirect
	github.com/pion/transport/v4 v4.0.2 // indirect
	github.com/pion/transport/v5 v5.1.5 // indirect
	github.com/pion/turn/v5 v5.1.3 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/wlynxg/anet v0.0.5 // indirect
	golang.org/x/crypto v0.59.0 // indirect
	golang.org/x/mobile v0.0.0-20260217195705-b56b3793a9c4 // indirect
	golang.org/x/mod v0.42.0 // indirect
	golang.org/x/net v0.63.0 // indirect
	golang.org/x/text v0.44.0 // indirect
	golang.org/x/tools v0.52.0 // indirect
	modernc.org/libc v1.80.1 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.12.1 // indirect
)

tool (
	golang.org/x/mobile/cmd/gobind
	golang.org/x/mobile/cmd/gomobile
)
