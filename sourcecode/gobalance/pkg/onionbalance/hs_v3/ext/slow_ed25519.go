package ext

import "math/big"

var b = 256
var by = biMul(bi(4), inv(bi(5)))
var bx = xrecover(by)
var q = biSub(biExp(bi(2), bi(255)), bi(19))
var bB = []*big.Int{biMod(bx, q), biMod(by, q)}
var I = expmod(bi(2), biDiv(biSub(q, bi(1)), bi(4)), q)
var d = bi(0).Mul(bi(-121665), inv(bi(121666)))

func encodepoint(P []*big.Int) []byte {
	x := P[0]
	y := P[1]
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

func decodeInt(s []uint8) *big.Int {
	sum := bi(0)
	for i := 0; i < 256; i++ {
		e := biExp(bi(2), bi(int64(i)))
		m := bi(int64(Bit(s, int64(i))))
		sum = sum.Add(sum, biMul(e, m))
	}
	return sum
}

func scalarmult(P []*big.Int, e *big.Int) []*big.Int {
	if e.Cmp(bi(0)) == 0 {
		return []*big.Int{bi(0), bi(1)}
	}
	Q := scalarmult(P, biDiv(e, bi(2)))
	Q = edwards(Q, Q)
	if e.And(e, bi(1)).Int64() == 1 {
		Q = edwards(Q, P)
	}
	return Q
}

func edwards(P, Q []*big.Int) []*big.Int {
	x1 := P[0]
	y1 := P[1]
	x2 := Q[0]
	y2 := Q[1]
	x3 := biMul(biAdd(biMul(x1, y2), biMul(x2, y1)), inv(biAdd(bi(1), biMul(biMul(biMul(biMul(d, x1), x2), y1), y2))))
	y3 := biMul(biAdd(biMul(y1, y2), biMul(x1, x2)), inv(biSub(bi(1), biMul(biMul(biMul(biMul(d, x1), x2), y1), y2))))
	return []*big.Int{biMod(x3, q), biMod(y3, q)}
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

func inv(x *big.Int) *big.Int {
	return expmod(x, biSub(q, bi(2)), q)
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
