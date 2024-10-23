package util

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"fmt"
	"math/big"
)

var b = 256
var d = bi(0).Mul(bi(-121665), inv(bi(121666)))
var d1 = biMod(biMul(bi(-121665), inv(bi(121666))), q)
var I = expmod(bi(2), biDiv(biSub(q, bi(1)), bi(4)), q)
var q = biSub(biExp(bi(2), bi(255)), bi(19))
var by = biMul(bi(4), inv(bi(5)))
var bx = xrecover(by)
var bB = []*big.Int{biMod(bx, q), biMod(by, q)}
var bB1 = []*big.Int{biMod(bx, q), biMod(by, q), bi(1), biMod(biMul(bx, by), q)}
var l = biAdd(biExp(bi(2), bi(252)), biFromStr("27742317777372353535851937790883648493"))

func biFromStr(v string) (out *big.Int) {
	out = new(big.Int)
	_, _ = fmt.Sscan(v, out)
	return
}

// BlindedSignWithTorKey this is identical to stem's hidden_service.py:_blinded_sign() but takes an
// extended private key (i.e. in tor format) as its argument, instead of the
// standard format that hazmat does. It basically omits the "extended the key"
// step and does everything else the same.
func BlindedSignWithTorKey(msg []byte, identityKey ed25519.PrivateKey, blindedKey, blindingNonce []byte) []byte {
	esk := identityKey.Seed()
	return blindedSignP2(esk, msg, blindedKey, blindingNonce)
}

func BlindedSign(msg, identityKey, blindedKey, blindingNonce []byte) []byte {
	identityKeyBytes := identityKey

	// pad private identity key into an ESK (encrypted secret key)

	tmp := sha512.Sum512(identityKeyBytes)
	h := tmp[:]
	sum := bi(0)
	for i := int64(3); i < int64(b)-2; i++ {
		sum = biAdd(sum, biMul(biExp(bi(2), bi(i)), bi(int64(Bit(h, i)))))
	}
	a := biAdd(biExp(bi(2), bi(int64(b-2))), sum)
	tmpS := make([][]byte, 0)
	for i := b / 8; i < b/4; i++ {
		tmpS = append(tmpS, h[i:i+1])
	}
	k := bytes.Join(tmpS, []byte(""))
	esk := append(encodeint(a), k...)

	return blindedSignP2(esk, msg, blindedKey, blindingNonce)
}

func blindedSignP2(esk, msg, blindedKey, blindingNonce []byte) []byte {
	// blind the ESK with this nonce
	sum := bi(0)
	for i := int64(3); i < int64(b-2); i++ {
		bitRes := bi(int64(Bit(blindingNonce, i)))
		sum = biAdd(sum, biMul(biExp(bi(2), bi(i)), bitRes))
	}
	mult := biAdd(biExp(bi(2), bi(int64(b-2))), sum)
	s := decodeInt(esk[:32])
	sPrime := biMod(biMul(s, mult), l)
	k := esk[32:]
	tmp := sha512.Sum512([]byte("Derive temporary signing key hash input" + string(k)))
	kPrime := tmp[:32]
	blindedEsk := append(encodeint(sPrime), kPrime...)

	// finally, sign the message

	a := decodeInt(blindedEsk[:32])
	lines := make([][]byte, 0)
	for i := b / 8; i < b/4; i++ {
		lines = append(lines, blindedEsk[i:i+1])
	}
	toHint := append(bytes.Join(lines, []byte("")), msg...)
	r := hint(toHint)
	R := Scalarmult1(bB1, r)
	S := biMod(biAdd(r, biMul(hint([]byte(string(Encodepoint(R))+string(blindedKey)+string(msg))), a)), l)

	return append(Encodepoint(R), encodeint(S)...)
}

func hint(m []byte) *big.Int {
	tmp := sha512.Sum512(m)
	h := tmp[:]
	sum := bi(0)
	for i := 0; i < 2*b; i++ {
		sum = biAdd(sum, biMul(biExp(bi(2), bi(int64(i))), bi(int64(Bit(h, int64(i))))))
	}
	return sum
}

//def Hint(m):
//h = H(m)
//return sum(2 ** i * bit(h, i) for i in range(2 * b))

func BlindedPubkey(identityKey ed25519.PublicKey, blindingNonce []byte) ed25519.PublicKey {
	ed25519b := int64(256)
	sum := bi(0)
	for i := int64(3); i < ed25519b-2; i++ {
		sum = biAdd(sum, biMul(biExp(bi(2), bi(i)), bi(int64(Bit(blindingNonce, i)))))
	}
	mult := biAdd(biExp(bi(2), bi(ed25519b-2)), sum)
	P := Decodepoint(identityKey)
	return Encodepoint(Scalarmult1(P, mult))
}

func Decodepoint(s []byte) []*big.Int {
	sum := bi(0)
	for i := 0; i < b-1; i++ {
		sum = biAdd(sum, biMul(biExp(bi(2), bi(int64(i))), bi(int64(Bit(s, int64(i))))))
	}
	y := sum
	x := xrecover(y)
	if biAnd(x, bi(1)).Cmp(bi(int64(Bit(s, int64(b-1))))) != 0 {
		x = biSub(q, x)
	}
	P := []*big.Int{x, y, bi(1), biMod(biMul(x, y), q)}
	if !isoncurve(P) {
		panic("decoding point that is not on curve")
	}
	return P
}

func decodeInt(s []uint8) *big.Int {
	sum := bi(0)
	for i := 0; i < 256; i++ {
		tmpI := bi(int64(i))
		base := bi(2)
		e := bi(0).Exp(base, tmpI, nil)
		m := bi(int64(Bit(s, int64(i))))
		tmp := bi(0).Mul(e, m)
		sum = sum.Add(sum, tmp)
	}
	return sum
}

func encodeint(y *big.Int) []byte {
	bits := make([]*big.Int, 0)
	for i := 0; i < b; i++ {
		bits = append(bits, biAnd(biRsh(y, uint(i)), bi(1)))
	}
	final := make([]byte, 0)
	for i := 0; i < b/8; i++ {
		sum := bi(0)
		for j := 0; j < 8; j++ {
			sum = biAdd(sum, biLsh(bits[i*8+j], uint(j)))
		}
		final = append(final, byte(sum.Uint64()))
	}
	return final
}

func xrecover(y *big.Int) *big.Int {
	xx := biMul(biSub(biMul(y, y), bi(1)), inv(biAdd(biMul(biMul(d, y), y), bi(1))))
	x := expmod(xx, biDiv(biAdd(q, bi(3)), bi(8)), q)
	if biMod(biSub(biMul(x, x), xx), q).Int64() != 0 {
		x = biMod(biMul(x, I), q)
	}
	if biMod(x, bi(2)).Int64() != 0 {
		x = biSub(q, x)
	}
	return x
}

func expmod(b, e, m *big.Int) *big.Int {
	if e.Cmp(bi(0)) == 0 {
		return bi(1)
	}
	t := biMod(biExp(expmod(b, biDiv(e, bi(2)), m), bi(2)), m)
	if biAnd(e, bi(1)).Int64() == 1 {
		t = biMod(biMul(t, b), m)
	}
	return t
}

func Bit(h []uint8, i int64) uint8 {
	return (h[i/8] >> (i % 8)) & 1
}

func inv(x *big.Int) *big.Int {
	return expmod(x, biSub(q, bi(2)), q)
}

func isoncurve(P []*big.Int) bool {
	var d = biMod(biMul(bi(-121665), inv(bi(121666))), q)
	var q = biSub(biExp(bi(2), bi(255)), bi(19))
	x := P[0]
	y := P[1]
	z := P[2]
	t := P[3]
	return biMod(z, q).Cmp(bi(0)) != 0 &&
		biMod(biMul(x, y), q).Cmp(biMod(biMul(z, t), q)) == 0 &&
		biMod(biSub(biSub(biSub(biMul(y, y), biMul(x, x)), biMul(z, z)), biMul(biMul(d, t), t)), q).Int64() == 0
}

func edwardsAdd(P, Q []*big.Int) []*big.Int {
	// This is formula sequence 'addition-add-2008-hwcd-3' from
	// http://www.hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html
	x1 := P[0]
	y1 := P[1]
	z1 := P[2]
	t1 := P[3]
	x2 := Q[0]
	y2 := Q[1]
	z2 := Q[2]
	t2 := Q[3]
	a := biMod(biMul(biSub(y1, x1), biSub(y2, x2)), q)
	b := biMod(biMul(biAdd(y1, x1), biAdd(y2, x2)), q)
	c := biMod(biMul(biMul(biMul(t1, bi(2)), d1), t2), q)
	dd := biMod(biMul(biMul(z1, bi(2)), z2), q)
	e := biSub(b, a)
	f := biSub(dd, c)
	g := biAdd(dd, c)
	h := biAdd(b, a)
	x3 := biMul(e, f)
	y3 := biMul(g, h)
	t3 := biMul(e, h)
	z3 := biMul(f, g)
	return []*big.Int{biMod(x3, q), biMod(y3, q), biMod(z3, q), biMod(t3, q)}
}

func edwardsDouble(P []*big.Int) []*big.Int {
	// This is formula sequence 'dbl-2008-hwcd' from
	// http://www.hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html
	x1 := P[0]
	y1 := P[1]
	z1 := P[2]
	a := biMod(biMul(x1, x1), q)
	b := biMod(biMul(y1, y1), q)
	c := biMod(biMul(biMul(bi(2), z1), z1), q)
	e := biMod(biSub(biSub(biMul(biAdd(x1, y1), biAdd(x1, y1)), a), b), q)
	g := biAdd(biMul(a, bi(-1)), b)
	f := biSub(g, c)
	h := biSub(biMul(a, bi(-1)), b)
	x3 := biMul(e, f)
	y3 := biMul(g, h)
	t3 := biMul(e, h)
	z3 := biMul(f, g)
	return []*big.Int{biMod(x3, q), biMod(y3, q), biMod(z3, q), biMod(t3, q)}
}

func Scalarmult1(P []*big.Int, e *big.Int) []*big.Int {
	if e.Cmp(bi(0)) == 0 {
		return []*big.Int{bi(0), bi(1), bi(1), bi(0)}
	}
	Q := Scalarmult1(P, biDiv(e, bi(2)))
	Q = edwardsDouble(Q)
	if biAnd(e, bi(1)).Int64() == 1 {
		//if e.And(e, bi(1)).Int64() == 1 {
		Q = edwardsAdd(Q, P)
	}
	return Q
}

func Encodepoint(P []*big.Int) []byte {
	x := P[0]
	y := P[1]
	z := P[2]
	//t := P[3]
	zi := inv(z)
	x = biMod(biMul(x, zi), q)
	y = biMod(biMul(y, zi), q)
	bits := make([]uint8, 0)
	for i := 0; i < b-1; i++ {
		bits = append(bits, uint8(biAnd(biRsh(y, uint(i)), bi(1)).Int64()))
	}
	bits = append(bits, uint8(biAnd(x, bi(1)).Int64()))
	by := make([]uint8, 0)
	for i := 0; i < b/8; i++ {
		sum := uint8(0)
		for j := 0; j < 8; j++ {
			sum += bits[i*8+j] << j
		}
		by = append(by, sum)
	}
	return by
}

//func Encodepoint(P []*big.Int) []byte {
//	x := P[0]
//	y := P[1]
//	bits := make([]uint8, 0)
//	for i := 0; i < b; i++ {
//		bits = append(bits, uint8(biAnd(biRsh(y, uint(i)), bi(1)).Int64()))
//	}
//	by := make([]uint8, 0)
//	bits = append(bits, uint8(biAnd(x, bi(1)).Int64()))
//	for i := 0; i < b/8; i++ {
//		sum := uint8(0)
//		for j := 0; j < 8; j++ {
//			sum += bits[i*8+j] << j
//		}
//		by = append(by, sum)
//	}
//	return by
//}

func bi(v int64) *big.Int {
	return big.NewInt(v)
}

func biExp(a, b *big.Int) *big.Int {
	return bi(0).Exp(a, b, nil)
}

func biDiv(a, b *big.Int) *big.Int {
	return bi(0).Div(a, b)
}

func biSub(a, b *big.Int) *big.Int {
	return bi(0).Sub(a, b)
}

func biAdd(a, b *big.Int) *big.Int {
	return bi(0).Add(a, b)
}

func biAnd(a, b *big.Int) *big.Int {
	return bi(0).And(a, b)
}

func biRsh(a *big.Int, b uint) *big.Int {
	return bi(0).Rsh(a, b)
}

func biLsh(a *big.Int, b uint) *big.Int {
	return bi(0).Lsh(a, b)
}

func biMul(a, b *big.Int) *big.Int {
	return bi(0).Mul(a, b)
}

func biMod(a, b *big.Int) *big.Int {
	return bi(0).Mod(a, b)
}
