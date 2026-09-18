module github.com/otpki/iogo

go 1.27.0

replace github.com/cloudflare/circl => github.com/otpki/circl v0.0.0-20260310190244-baa88566ae46

require (
	filippo.io/bigmod v0.1.0
	github.com/cloudflare/circl v1.6.3
	github.com/stretchr/testify v1.12.1
	golang.org/x/crypto v0.54.0
)

require (
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/sys v0.48.0 // indirect
)
