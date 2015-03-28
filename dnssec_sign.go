//+build go1.4

package dns

import (
	"crypto"
	"crypto/rand"
	"encoding/asn1"
	"math/big"
	"strings"
)

// Sign signs an RRSet. The signature needs to be filled in with
// the values: Inception, Expiration, KeyTag, SignerName and Algorithm.
// The rest is copied from the RRset. Sign returns true when the signing went OK,
// otherwise false.
// There is no check if RRSet is a proper (RFC 2181) RRSet.
// If OrigTTL is non zero, it is used as-is, otherwise the TTL of the RRset
// is used as the OrigTTL.
func (rr *RRSIG) Sign(k crypto.Signer, rrset []RR) error {
	if k == nil {
		return ErrPrivKey
	}
	// s.Inception and s.Expiration may be 0 (rollover etc.), the rest must be set
	if rr.KeyTag == 0 || len(rr.SignerName) == 0 || rr.Algorithm == 0 {
		return ErrKey
	}

	rr.Hdr.Rrtype = TypeRRSIG
	rr.Hdr.Name = rrset[0].Header().Name
	rr.Hdr.Class = rrset[0].Header().Class
	if rr.OrigTtl == 0 { // If set don't override
		rr.OrigTtl = rrset[0].Header().Ttl
	}
	rr.TypeCovered = rrset[0].Header().Rrtype
	rr.Labels = uint8(CountLabel(rrset[0].Header().Name))

	if strings.HasPrefix(rrset[0].Header().Name, "*") {
		rr.Labels-- // wildcard, remove from label count
	}

	sigwire := new(rrsigWireFmt)
	sigwire.TypeCovered = rr.TypeCovered
	sigwire.Algorithm = rr.Algorithm
	sigwire.Labels = rr.Labels
	sigwire.OrigTtl = rr.OrigTtl
	sigwire.Expiration = rr.Expiration
	sigwire.Inception = rr.Inception
	sigwire.KeyTag = rr.KeyTag
	// For signing, lowercase this name
	sigwire.SignerName = strings.ToLower(rr.SignerName)

	// Create the desired binary blob
	signdata := make([]byte, DefaultMsgSize)
	n, err := PackStruct(sigwire, signdata, 0)
	if err != nil {
		return err
	}
	signdata = signdata[:n]
	wire, err := rawSignatureData(rrset, rr)
	if err != nil {
		return err
	}
	signdata = append(signdata, wire...)

	hash, ok := AlgorithmToHash[rr.Algorithm]
	if !ok {
		return ErrAlg
	}

	h := hash.New()
	h.Write(signdata)

	signature, err := sign(k, h.Sum(nil), hash, rr.Algorithm)
	if err != nil {
		return err
	}

	rr.Signature = toBase64(signature)

	return nil
}

func sign(k crypto.Signer, hashed []byte, hash crypto.Hash, alg uint8) ([]byte, error) {
	signature, err := k.Sign(rand.Reader, hashed, hash)
	if err != nil {
		return nil, err
	}

	switch alg {
	case RSASHA1, RSASHA1NSEC3SHA1, RSASHA256, RSASHA512:
		return signature, nil

	case ECDSAP256SHA256, ECDSAP384SHA384:
		ecdsaSignature := &struct {
			R, S *big.Int
		}{}
		if _, err := asn1.Unmarshal(signature, ecdsaSignature); err != nil {
			return nil, err
		}

		var intlen int
		switch alg {
		case ECDSAP256SHA256:
			intlen = 32
		case ECDSAP384SHA384:
			intlen = 48
		}

		signature := intToBytes(ecdsaSignature.R, intlen)
		signature = append(signature, intToBytes(ecdsaSignature.S, intlen)...)
		return signature, nil

	// There is no defined interface for what a DSA backed crypto.Signer returns
	case DSA, DSANSEC3SHA1:
		//  t := divRoundUp(divRoundUp(p.PublicKey.Y.BitLen(), 8)-64, 8)
		//  signature := []byte{byte(t)}
		//  signature = append(signature, intToBytes(r1, 20)...)
		//  signature = append(signature, intToBytes(s1, 20)...)
		//  rr.Signature = signature
	}

	return nil, ErrAlg
}
