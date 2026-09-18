package x509

import "crypto/x509"

// IOGO<->stdx509 Certificate converters

// Convert this Certificate to a stdlib crypto/x509.Certificate for interoperability
// Note: assumes raw content is populated consistent with the parsed fields
func (c *Certificate) ToStdX509() (*x509.Certificate, error) {
	return x509.ParseCertificate(c.Raw)
}

// Convert this Certificate to a iogo/crypto/x509.Certificate for interoperability
// Note: assumes raw content is populated consistent with the parsed fields
func CertificateFromStdX509(cert *x509.Certificate) (*Certificate, error) {
	return ParseCertificate(cert.Raw)
}

func ConvertChainToStdX509(chain []*Certificate) ([]*x509.Certificate, error) {
	chainOut := []*x509.Certificate{}
	for _, cert := range chain {
		converted, err := cert.ToStdX509()
		if err != nil {
			return nil, err
		}
		chainOut = append(chainOut, converted)
	}
	return chainOut, nil
}

func ConvertChainFromStdX509(chain []*x509.Certificate) ([]*Certificate, error) {
	chainOut := []*Certificate{}
	for _, cert := range chain {
		converted, err := CertificateFromStdX509(cert)
		if err != nil {
			return nil, err
		}
		chainOut = append(chainOut, converted)
	}
	return chainOut, nil
}

// Convert this CSR to a stdlib crypto/x509.CertificateRequest for interoperability
// Note: assumes raw content is populated consistent with the parsed fields
func (c *CertificateRequest) ToStdX509() (*x509.CertificateRequest, error) {
	return x509.ParseCertificateRequest(c.Raw)
}

// Convert this CSR to a iogo/crypto/x509.CertificateRequest for interoperability
// Note: assumes raw content is populated consistent with the parsed fields
func CertificateRequestFromStdX509(csr *x509.CertificateRequest) (*CertificateRequest, error) {
	return ParseCertificateRequest(csr.Raw)
}
