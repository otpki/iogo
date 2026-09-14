module github.com/otpki/iogo

go 1.27.0

replace github.com/cloudflare/circl => github.com/otpki/circl v0.0.0-20260310190244-baa88566ae46

require (
	github.com/cloudflare/circl v1.6.3
	golang.org/x/crypto v0.54.0
)

require golang.org/x/sys v0.47.0 // indirect
