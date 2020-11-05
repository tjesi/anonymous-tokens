package main

import (
	"crypto/rand"
	"crypto/sha256"
	"math/big"
)

// RandomBytes sample B random Bytes.
func RandomBytes() []byte {
	r := make([]byte, B)
	rand.Read(r)
	return r
}

// HashToCurve hash t to a curve point T.
// If T is not valid, then Ty = nil.
func HashToCurve(t []byte) (Tx *big.Int, Ty *big.Int) {
	hash := sha256.Sum256(t)
	Tx = new(big.Int).SetBytes(hash[:])

	// Verify that (Ty)^2 = (Tx)^3 - 3*Tx + B mod P
	// holds for T = (Tx,Ty). Otherwise set Ty = nil.
	Ty = new(big.Int).ModSqrt(polynomial(params.B, params.P, Tx), params.P)
	return
}

// CreateChallenge hash all informaion into B Bytes.
// Reference: https://golang.org/pkg/crypto/sha256.
// There is probably a more elegant way to do this.
func CreateChallenge(Px, Py, Qx, Qy, Kx, Ky, Ax, Ay, Bx, By *big.Int) (c [B]byte) {
	bytes := append(params.Gx.Bytes(), params.Gx.Bytes()...)
	list := []big.Int{*Px, *Py, *Qx, *Qy, *Kx, *Ky, *Ax, *Ay, *Bx, *By}
	for _, element := range list {
		bytes = append(bytes, element.Bytes()...)
	}
	c = sha256.Sum256(bytes)
	return
}

// CreateProof creates a proof (c,z) proving
// that Q = *P and K = k*G without revealing k.
func CreateProof(Px, Py, Qx, Qy, Kx, Ky *big.Int, k []byte) (c [B]byte, z []byte) {

	// Generate random mask r, and
	// then compute A = rP and B = rG
	r := RandomBytes()
	Ax, Ay := curve.ScalarMult(Px, Py, r)
	Bx, By := curve.ScalarBaseMult(r)

	// Hash everything
	c = CreateChallenge(Px, Py, Qx, Qy, Kx, Ky, Ax, Ay, Bx, By)

	// Compute z = r - ck mod N
	temp := new(big.Int).SetBytes(c[:])
	temp.Mul(temp, new(big.Int).SetBytes(k[:]))
	temp.Sub(new(big.Int).SetBytes(r[:]), temp)
	temp.Mod(temp, params.N)
	z = temp.Bytes()

	return
}

// VerifyProof verifies the proof (c,z).
func VerifyProof(Px, Py, Qx, Qy, Kx, Ky *big.Int, c [B]byte, z []byte) bool {
	var x1, x2, y1, y2 *big.Int

	// Compute zP+cQ = rP = A
	x1, y1 = curve.ScalarMult(Px, Py, z)
	x2, y2 = curve.ScalarMult(Qx, Qy, c[:])
	Ax, Ay := curve.Add(x1, y1, x2, y2)

	// Compute zG+cK = rG = B
	x1, y1 = curve.ScalarBaseMult(z)
	x2, y2 = curve.ScalarMult(Kx, Ky, c[:])
	Bx, By := curve.Add(x1, y1, x2, y2)

	hash := CreateChallenge(Px, Py, Qx, Qy, Kx, Ky, Ax, Ay, Bx, By)

	// Verify that c = H(G,P,Q,K,zP+cQ,zG+cK)
	return c == hash
}

// Computes x^3 - 3x + B mod P. Copied from:
// https://golang.org/src/crypto/elliptic/elliptic.go
func polynomial(B, P, x *big.Int) *big.Int {
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)

	threeX := new(big.Int).Lsh(x, 1)
	threeX.Add(threeX, x)

	x3.Sub(x3, threeX)
	x3.Add(x3, B)
	x3.Mod(x3, P)

	return x3
}
