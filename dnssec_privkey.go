package dns

import (
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"math/big"
	"strconv"
	"strings"
)

// Generate generates a DNSKEY of the given bit size.
// The public part is put inside the DNSKEY record.
// The Algorithm in the key must be set as this will define
// what kind of DNSKEY will be generated.
// The ECDSA algorithms imply a fixed keysize, in that case
// bits should be set to the size of the algorithm.
func (k *DNSKEY) Generate(bits int) (crypto.PrivateKey, error) {
	switch k.Algorithm {
	case DSA, DSANSEC3SHA1:
		if bits != 1024 {
			return nil, ErrKeySize
		}
	case RSAMD5, RSASHA1, RSASHA256, RSASHA1NSEC3SHA1:
		if bits < 512 || bits > 4096 {
			return nil, ErrKeySize
		}
	case RSASHA512:
		if bits < 1024 || bits > 4096 {
			return nil, ErrKeySize
		}
	case ECDSAP256SHA256:
		if bits != 256 {
			return nil, ErrKeySize
		}
	case ECDSAP384SHA384:
		if bits != 384 {
			return nil, ErrKeySize
		}
	}

	switch k.Algorithm {
	case DSA, DSANSEC3SHA1:
		params := new(dsa.Parameters)
		if err := dsa.GenerateParameters(params, rand.Reader, dsa.L1024N160); err != nil {
			return nil, err
		}
		priv := new(dsa.PrivateKey)
		priv.PublicKey.Parameters = *params
		err := dsa.GenerateKey(priv, rand.Reader)
		if err != nil {
			return nil, err
		}
		k.setPublicKeyDSA(params.Q, params.P, params.G, priv.PublicKey.Y)
		return priv, nil
	case RSAMD5, RSASHA1, RSASHA256, RSASHA512, RSASHA1NSEC3SHA1:
		priv, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return nil, err
		}
		k.setPublicKeyRSA(priv.PublicKey.E, priv.PublicKey.N)
		return priv, nil
	case ECDSAP256SHA256, ECDSAP384SHA384:
		var c elliptic.Curve
		switch k.Algorithm {
		case ECDSAP256SHA256:
			c = elliptic.P256()
		case ECDSAP384SHA384:
			c = elliptic.P384()
		}
		priv, err := ecdsa.GenerateKey(c, rand.Reader)
		if err != nil {
			return nil, err
		}
		k.setPublicKeyECDSA(priv.PublicKey.X, priv.PublicKey.Y)
		return priv, nil
	default:
		return nil, ErrAlg
	}
}

// Set the public key (the value E and N)
func (k *DNSKEY) setPublicKeyRSA(_E int, _N *big.Int) bool {
	if _E == 0 || _N == nil {
		return false
	}
	buf := exponentToBuf(_E)
	buf = append(buf, _N.Bytes()...)
	k.PublicKey = toBase64(buf)
	return true
}

// Set the public key for Elliptic Curves
func (k *DNSKEY) setPublicKeyECDSA(_X, _Y *big.Int) bool {
	if _X == nil || _Y == nil {
		return false
	}
	var intlen int
	switch k.Algorithm {
	case ECDSAP256SHA256:
		intlen = 32
	case ECDSAP384SHA384:
		intlen = 48
	}
	k.PublicKey = toBase64(curveToBuf(_X, _Y, intlen))
	return true
}

// Set the public key for DSA
func (k *DNSKEY) setPublicKeyDSA(_Q, _P, _G, _Y *big.Int) bool {
	if _Q == nil || _P == nil || _G == nil || _Y == nil {
		return false
	}
	buf := dsaToBuf(_Q, _P, _G, _Y)
	k.PublicKey = toBase64(buf)
	return true
}

// Set the public key (the values E and N) for RSA
// RFC 3110: Section 2. RSA Public KEY Resource Records
func exponentToBuf(_E int) []byte {
	var buf []byte
	i := big.NewInt(int64(_E))
	if len(i.Bytes()) < 256 {
		buf = make([]byte, 1)
		buf[0] = uint8(len(i.Bytes()))
	} else {
		buf = make([]byte, 3)
		buf[0] = 0
		buf[1] = uint8(len(i.Bytes()) >> 8)
		buf[2] = uint8(len(i.Bytes()))
	}
	buf = append(buf, i.Bytes()...)
	return buf
}

// Set the public key for X and Y for Curve. The two
// values are just concatenated.
func curveToBuf(_X, _Y *big.Int, intlen int) []byte {
	buf := intToBytes(_X, intlen)
	buf = append(buf, intToBytes(_Y, intlen)...)
	return buf
}

// Set the public key for X and Y for Curve. The two
// values are just concatenated.
func dsaToBuf(_Q, _P, _G, _Y *big.Int) []byte {
	t := divRoundUp(divRoundUp(_G.BitLen(), 8)-64, 8)
	buf := []byte{byte(t)}
	buf = append(buf, intToBytes(_Q, 20)...)
	buf = append(buf, intToBytes(_P, 64+t*8)...)
	buf = append(buf, intToBytes(_G, 64+t*8)...)
	buf = append(buf, intToBytes(_Y, 64+t*8)...)
	return buf
}

const format = "Private-key-format: v1.3\n"

// PrivateKeyString converts a PrivateKey to a string. This string has the same
// format as the private-key-file of BIND9 (Private-key-format: v1.3).
// It needs some info from the key (the algorithm), so its a method of the DNSKEY
// It supports rsa.PrivateKey, ecdsa.PrivateKey and dsa.PrivateKey
func (r *DNSKEY) PrivateKeyString(p crypto.PrivateKey) string {
	algorithm := strconv.Itoa(int(r.Algorithm))
	algorithm += " (" + AlgorithmToString[r.Algorithm] + ")"

	switch p := p.(type) {
	case *rsa.PrivateKey:
		modulus := toBase64(p.PublicKey.N.Bytes())
		e := big.NewInt(int64(p.PublicKey.E))
		publicExponent := toBase64(e.Bytes())
		privateExponent := toBase64(p.D.Bytes())
		prime1 := toBase64(p.Primes[0].Bytes())
		prime2 := toBase64(p.Primes[1].Bytes())
		// Calculate Exponent1/2 and Coefficient as per: http://en.wikipedia.org/wiki/RSA#Using_the_Chinese_remainder_algorithm
		// and from: http://code.google.com/p/go/issues/detail?id=987
		one := big.NewInt(1)
		p1 := big.NewInt(0).Sub(p.Primes[0], one)
		q1 := big.NewInt(0).Sub(p.Primes[1], one)
		exp1 := big.NewInt(0).Mod(p.D, p1)
		exp2 := big.NewInt(0).Mod(p.D, q1)
		coeff := big.NewInt(0).ModInverse(p.Primes[1], p.Primes[0])

		exponent1 := toBase64(exp1.Bytes())
		exponent2 := toBase64(exp2.Bytes())
		coefficient := toBase64(coeff.Bytes())

		return format +
			"Algorithm: " + algorithm + "\n" +
			"Modulus: " + modulus + "\n" +
			"PublicExponent: " + publicExponent + "\n" +
			"PrivateExponent: " + privateExponent + "\n" +
			"Prime1: " + prime1 + "\n" +
			"Prime2: " + prime2 + "\n" +
			"Exponent1: " + exponent1 + "\n" +
			"Exponent2: " + exponent2 + "\n" +
			"Coefficient: " + coefficient + "\n"

	case *ecdsa.PrivateKey:
		var intlen int
		switch r.Algorithm {
		case ECDSAP256SHA256:
			intlen = 32
		case ECDSAP384SHA384:
			intlen = 48
		}
		private := toBase64(intToBytes(p.D, intlen))
		return format +
			"Algorithm: " + algorithm + "\n" +
			"PrivateKey: " + private + "\n"

	case *dsa.PrivateKey:
		T := divRoundUp(divRoundUp(p.PublicKey.Parameters.G.BitLen(), 8)-64, 8)
		prime := toBase64(intToBytes(p.PublicKey.Parameters.P, 64+T*8))
		subprime := toBase64(intToBytes(p.PublicKey.Parameters.Q, 20))
		base := toBase64(intToBytes(p.PublicKey.Parameters.G, 64+T*8))
		priv := toBase64(intToBytes(p.X, 20))
		pub := toBase64(intToBytes(p.PublicKey.Y, 64+T*8))
		return format +
			"Algorithm: " + algorithm + "\n" +
			"Prime(p): " + prime + "\n" +
			"Subprime(q): " + subprime + "\n" +
			"Base(g): " + base + "\n" +
			"Private_value(x): " + priv + "\n" +
			"Public_value(y): " + pub + "\n"

	default:
		return ""
	}
}

// NewPrivateKey returns a PrivateKey by parsing the string s.
// s should be in the same form of the BIND private key files.
func (k *DNSKEY) NewPrivateKey(s string) (crypto.PrivateKey, error) {
	if s[len(s)-1] != '\n' { // We need a closing newline
		return k.ReadPrivateKey(strings.NewReader(s+"\n"), "")
	}
	return k.ReadPrivateKey(strings.NewReader(s), "")
}

// ReadPrivateKey reads a private key from the io.Reader q. The string file is
// only used in error reporting.
// The public key must be known, because some cryptographic algorithms embed
// the public inside the privatekey.
func (k *DNSKEY) ReadPrivateKey(q io.Reader, file string) (crypto.PrivateKey, error) {
	m, e := parseKey(q, file)
	if m == nil {
		return nil, e
	}
	if _, ok := m["private-key-format"]; !ok {
		return nil, ErrPrivKey
	}
	if m["private-key-format"] != "v1.2" && m["private-key-format"] != "v1.3" {
		return nil, ErrPrivKey
	}
	// TODO(mg): check if the pubkey matches the private key
	switch m["algorithm"] {
	case "3 (DSA)":
		priv, e := readPrivateKeyDSA(m)
		if e != nil {
			return nil, e
		}
		pub := k.publicKeyDSA()
		if pub == nil {
			return nil, ErrKey
		}
		priv.PublicKey = *pub
		return priv, e
	case "1 (RSAMD5)":
		fallthrough
	case "5 (RSASHA1)":
		fallthrough
	case "7 (RSASHA1NSEC3SHA1)":
		fallthrough
	case "8 (RSASHA256)":
		fallthrough
	case "10 (RSASHA512)":
		priv, e := readPrivateKeyRSA(m)
		if e != nil {
			return nil, e
		}
		pub := k.publicKeyRSA()
		if pub == nil {
			return nil, ErrKey
		}
		priv.PublicKey = *pub
		return priv, e
	case "12 (ECC-GOST)":
		return nil, ErrPrivKey
	case "13 (ECDSAP256SHA256)":
		fallthrough
	case "14 (ECDSAP384SHA384)":
		priv, e := readPrivateKeyECDSA(m)
		if e != nil {
			return nil, e
		}
		pub := k.publicKeyECDSA()
		if pub == nil {
			return nil, ErrKey
		}
		priv.PublicKey = *pub
		return priv, e
	default:
		return nil, ErrPrivKey
	}
}

// Read a private key (file) string and create a public key. Return the private key.
func readPrivateKeyRSA(m map[string]string) (*rsa.PrivateKey, error) {
	p := new(rsa.PrivateKey)
	p.Primes = []*big.Int{nil, nil}
	for k, v := range m {
		switch k {
		case "modulus", "publicexponent", "privateexponent", "prime1", "prime2":
			v1, err := fromBase64([]byte(v))
			if err != nil {
				return nil, err
			}
			switch k {
			case "modulus":
				p.PublicKey.N = big.NewInt(0)
				p.PublicKey.N.SetBytes(v1)
			case "publicexponent":
				i := big.NewInt(0)
				i.SetBytes(v1)
				p.PublicKey.E = int(i.Int64()) // int64 should be large enough
			case "privateexponent":
				p.D = big.NewInt(0)
				p.D.SetBytes(v1)
			case "prime1":
				p.Primes[0] = big.NewInt(0)
				p.Primes[0].SetBytes(v1)
			case "prime2":
				p.Primes[1] = big.NewInt(0)
				p.Primes[1].SetBytes(v1)
			}
		case "exponent1", "exponent2", "coefficient":
			// not used in Go (yet)
		case "created", "publish", "activate":
			// not used in Go (yet)
		}
	}
	return p, nil
}

func readPrivateKeyDSA(m map[string]string) (*dsa.PrivateKey, error) {
	p := new(dsa.PrivateKey)
	p.X = big.NewInt(0)
	for k, v := range m {
		switch k {
		case "private_value(x)":
			v1, err := fromBase64([]byte(v))
			if err != nil {
				return nil, err
			}
			p.X.SetBytes(v1)
		case "created", "publish", "activate":
			/* not used in Go (yet) */
		}
	}
	return p, nil
}

func readPrivateKeyECDSA(m map[string]string) (*ecdsa.PrivateKey, error) {
	p := new(ecdsa.PrivateKey)
	p.D = big.NewInt(0)
	// TODO: validate that the required flags are present
	for k, v := range m {
		switch k {
		case "privatekey":
			v1, err := fromBase64([]byte(v))
			if err != nil {
				return nil, err
			}
			p.D.SetBytes(v1)
		case "created", "publish", "activate":
			/* not used in Go (yet) */
		}
	}
	return p, nil
}

// parseKey reads a private key from r. It returns a map[string]string,
// with the key-value pairs, or an error when the file is not correct.
func parseKey(r io.Reader, file string) (map[string]string, error) {
	s := scanInit(r)
	m := make(map[string]string)
	c := make(chan lex)
	k := ""
	// Start the lexer
	go klexer(s, c)
	for l := range c {
		// It should alternate
		switch l.value {
		case zKey:
			k = l.token
		case zValue:
			if k == "" {
				return nil, &ParseError{file, "no private key seen", l}
			}
			//println("Setting", strings.ToLower(k), "to", l.token, "b")
			m[strings.ToLower(k)] = l.token
			k = ""
		}
	}
	return m, nil
}

// klexer scans the sourcefile and returns tokens on the channel c.
func klexer(s *scan, c chan lex) {
	var l lex
	str := "" // Hold the current read text
	commt := false
	key := true
	x, err := s.tokenText()
	defer close(c)
	for err == nil {
		l.column = s.position.Column
		l.line = s.position.Line
		switch x {
		case ':':
			if commt {
				break
			}
			l.token = str
			if key {
				l.value = zKey
				c <- l
				// Next token is a space, eat it
				s.tokenText()
				key = false
				str = ""
			} else {
				l.value = zValue
			}
		case ';':
			commt = true
		case '\n':
			if commt {
				// Reset a comment
				commt = false
			}
			l.value = zValue
			l.token = str
			c <- l
			str = ""
			commt = false
			key = true
		default:
			if commt {
				break
			}
			str += string(x)
		}
		x, err = s.tokenText()
	}
	if len(str) > 0 {
		// Send remainder
		l.token = str
		l.value = zValue
		c <- l
	}
}
