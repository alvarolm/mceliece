package mceliece

// Code to generate the NIST "PQCsignKAT" test vectors.
// See PQCsignKAT_sign.c and randombytes.c in the reference implementation.

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/alvarolm/mceliece/internal/nist"
	"github.com/alvarolm/mceliece/internal/test"
	"github.com/alvarolm/mceliece/kem"
	"github.com/alvarolm/mceliece/mceliece348864"
	"github.com/alvarolm/mceliece/mceliece348864f"
	"github.com/alvarolm/mceliece/mceliece460896"
	"github.com/alvarolm/mceliece/mceliece460896f"
	"github.com/alvarolm/mceliece/mceliece6688128"
	"github.com/alvarolm/mceliece/mceliece6688128f"
	"github.com/alvarolm/mceliece/mceliece6960119"
	"github.com/alvarolm/mceliece/mceliece6960119f"
	"github.com/alvarolm/mceliece/mceliece8192128"
	"github.com/alvarolm/mceliece/mceliece8192128f"
)

type kemTest struct {
	name   string
	want   string
	scheme kem.Scheme
}

func TestPQCgenKATKem(t *testing.T) {
	kats := []kemTest{
		// Computed from reference implementation
		{name: "mceliece348864f", want: "d0d5ea348a181740862dcc8476ff7d00ce44d1c6e36b2145289d97f580f2cd7d", scheme: mceliece348864f.Scheme()},
		{name: "mceliece348864", want: "76351ed2e95a616ca76230bac579cead21012d89181c7398381d0bbe904ab92c", scheme: mceliece348864.Scheme()},
		{name: "mceliece460896f", want: "552da50baff2666db7b64486c88da4e2b65b25c3d5424be682ca08ffce15a356", scheme: mceliece460896f.Scheme()},
		{name: "mceliece460896", want: "fd785edfe1b721fb24fe159cb9f30cc17daec3d188d59a4bf47a83388880192e", scheme: mceliece460896.Scheme()},
		{name: "mceliece6688128f", want: "7b64c9882a00bc984e0ca9d3748d0b1bd9215d1bcf921643ee88d28d539303d8", scheme: mceliece6688128f.Scheme()},
		{name: "mceliece6688128", want: "3f926328959729c61a11b11ab6326246a42d9b3e76943bba2625342ea33723e2", scheme: mceliece6688128.Scheme()},
		{name: "mceliece6960119f", want: "d6d3e929ff505108fd545d14df5f5bac234cd6d882f0eed3fd628f122e3093c6", scheme: mceliece6960119f.Scheme()},
		{name: "mceliece6960119", want: "e4d608fa9795c1a1704709ab9df3940ae1dbf0f708cc0dbdf76c8f3173088e46", scheme: mceliece6960119.Scheme()},
		{name: "mceliece8192128f", want: "3fdb40d47705829c16de4fb5a81f7c095eb4dadc306cfc2c89eff2f483c42402", scheme: mceliece8192128f.Scheme()},
		{name: "mceliece8192128", want: "beb28fc0d1555a0028afeb6ebc72b8337f424a826be3d49b47759b8bda50db90", scheme: mceliece8192128.Scheme()},
	}

	for _, kat := range kats {
		kat := kat
		t.Run(kat.name, func(t *testing.T) {
			testPQCgenKATKem(t, kat.name, kat.want, kat.scheme)
		})
	}
}

func testPQCgenKATKem(t *testing.T, name, expected string, scheme kem.Scheme) {

	if scheme == nil {
		t.Fatal()
	}

	var seed [48]byte
	kseed := make([]byte, scheme.SeedSize())
	for i := 0; i < 48; i++ {
		seed[i] = byte(i)
	}
	f := sha256.New()
	g := nist.NewDRBG(&seed)
	fmt.Fprintf(f, "# kem/%s\n\n", name)
	for i := 0; i < 10; i++ {
		g.Fill(seed[:])
		fmt.Fprintf(f, "count = %d\n", i)
		fmt.Fprintf(f, "seed = %X\n", seed)

		g2 := nist.NewDRBG(&seed)

		g2.Fill(kseed)

		pk, sk := scheme.DeriveKeyPair(kseed)
		ppk, _ := pk.MarshalBinary()
		psk, _ := sk.MarshalBinary()

		scheme := scheme.(interface {
			kem.Scheme
			EncapsulateDeterministically(pk kem.PublicKey, seed []byte) (ct, ss []byte, err error)
		})

		ct, ss, err := scheme.EncapsulateDeterministically(pk, seed[:])
		if err != nil {
			t.Fatal(err)
		}
		ss2, err := scheme.Decapsulate(sk, ct)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(ss, ss2) {
			test.ReportError(t, fmt.Sprintf("%X", ss2), fmt.Sprintf("%X", ss))
		}
		fmt.Fprintf(f, "pk = %X\n", ppk)
		fmt.Fprintf(f, "sk = %X\n", psk)
		fmt.Fprintf(f, "ct = %X\n", ct)
		fmt.Fprintf(f, "ss = %X\n\n", ss)
	}
	if fmt.Sprintf("%x", f.Sum(nil)) != expected {
		t.Fatal()
	}
}
