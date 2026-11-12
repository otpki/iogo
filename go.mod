module github.com/otpki/iogo

go 1.27.0

require (
	filippo.io/bigmod v0.1.0
	github.com/cloudflare/circl v0.0.0-00010101000000-000000000000
	github.com/stretchr/testify v1.12.1
	golang.org/x/crypto v0.58.0
)

require (
	go.yaml.in/yaml/v3 v3.0.6 // indirect
	golang.org/x/sys v0.50.0 // indirect
)

replace github.com/cloudflare/circl => github.com/otpki/circl v0.0.0-20261112151406-a03bc4371af7
