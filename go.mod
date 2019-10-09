module github.com/status-im/status-go

go 1.12

replace github.com/ethereum/go-ethereum v1.9.5 => github.com/status-im/go-ethereum v1.9.5-status.4

replace github.com/NaySoftware/go-fcm => github.com/status-im/go-fcm v1.0.0-status

require (
	github.com/NaySoftware/go-fcm v0.0.0-00010101000000-000000000000
	github.com/beevik/ntp v0.2.0
	github.com/btcsuite/btcd v0.0.0-20190824003749-130ea5bddde3
	github.com/btcsuite/btcutil v0.0.0-20190425235716-9e5f4b9a998d
	github.com/ethereum/go-ethereum v1.9.5
	github.com/gballet/go-libpcsclite v0.0.0-20190607065134-2772fd86a8ff // indirect
	github.com/go-playground/locales v0.12.1 // indirect
	github.com/go-playground/universal-translator v0.16.0 // indirect
	github.com/golang/mock v1.3.1
	github.com/karalabe/usb v0.0.0-20190919080040-51dc0efba356 // indirect
	github.com/leodido/go-urn v1.1.0 // indirect
	github.com/lib/pq v1.2.0
	github.com/libp2p/go-libp2p v0.4.0 // indirect
	github.com/libp2p/go-libp2p-core v0.2.3
	github.com/multiformats/go-multiaddr v0.1.1
	github.com/mutecomm/go-sqlcipher v0.0.0-20190227152316-55dbde17881f
	github.com/pborman/uuid v1.2.0
	github.com/prometheus/tsdb v0.10.0 // indirect
	github.com/russolsen/transit v0.0.0-20180705123435-0794b4c4505a
	github.com/status-im/doubleratchet v2.0.0+incompatible
	github.com/status-im/keycard-go v0.0.0-20190424133014-d95853db0f48 // indirect
	github.com/status-im/migrate/v4 v4.3.1-status.0.20190822050738-a9d340ec8fb7
	github.com/status-im/rendezvous v1.3.0
	github.com/status-im/status-protocol-go v0.2.3-0.20191009073015-e7ecec99a52b
	github.com/status-im/whisper v1.5.1
	github.com/stretchr/testify v1.4.0
	github.com/syndtr/goleveldb v1.0.0
	github.com/tyler-smith/go-bip39 v1.0.2 // indirect
	github.com/wsddn/go-ecdh v0.0.0-20161211032359-48726bab9208 // indirect
	go.uber.org/zap v1.10.0
	golang.org/x/crypto v0.0.0-20191001141032-4663e185863a
	golang.org/x/net v0.0.0-20190930134127-c5a3c61f89f3 // indirect
	golang.org/x/sync v0.0.0-20190911185100-cd5d95a43a6e // indirect
	golang.org/x/sys v0.0.0-20190927073244-c990c680b611 // indirect
	golang.org/x/text v0.3.2
	gopkg.in/go-playground/assert.v1 v1.2.1 // indirect
	gopkg.in/go-playground/validator.v9 v9.29.1
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
)
