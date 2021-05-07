package main

import (
	"fmt"
	"math/big"
)

// KeyGen creates a private key k,
// and a public key K = (Kx,Ky)
func KeyGen() (k []byte, Kx, Ky *big.Int) {
	k = RandomBytes()
	Kx, Ky = curve.ScalarBaseMult(k[:])
	return
}

// Initiate sample random t,r of B Bytes,
// hash t to curve as T, and compute
// P = [r]*T. Returns (t,r,Px,Py).
func Initiate() (t, r []byte, Px, Py *big.Int) {

	r = RandomBytes()
	t = RandomBytes()
	Tx, Ty := HashToCurve(t)

	// Check that T is valdid, otherwise try again.
	for Ty == nil || !curve.IsOnCurve(Tx, Ty) {
		t = RandomBytes()
		Tx, Ty = HashToCurve(t)
	}

	// Compute P = [r]*T.
	Px, Py = curve.ScalarMult(Tx, Ty, r)
	return
}

// GenerateToken use the private key to compute
// Q = [k]*P, and creates a proof (c,z) that k is
// used to compute Q and K from P and G, respectively.
func GenerateToken(Px, Py, Kx, Ky *big.Int, k []byte) (Qx, Qy *big.Int, c [B]byte, z []byte) {
	Qx, Qy = curve.ScalarMult(Px, Py, k[:])
	c, z = CreateProof(Px, Py, Qx, Qy, Kx, Ky, k)
	return
}

// RandomiseToken remove the mask r of Q, and
// returns W = [(1/r)]*Q = k*P. First, it checks
// that the proof (c,z) is correct.
func RandomiseToken(Px, Py, Qx, Qy, Kx, Ky *big.Int, c [B]byte, z, r []byte) (Wx, Wy *big.Int) {

	// Verify the proof (c,z).
	if VerifyProof(Px, Py, Qx, Qy, Kx, Ky, c, z) {
		fmt.Println("Proof is valid.")
	} else {
		fmt.Println("Proof is not valid.")
	}

	// Compute inverse rInv of r mod N.
	rInv := new(big.Int).SetBytes(r[:])
	rInv.ModInverse(rInv, params.N)

	// Remove the mask r from the token.
	Wx, Wy = curve.ScalarMult(Qx, Qy, rInv.Bytes())

	return
}

// VerifyToken checks that the token is correct,
// by computing T = Hash(t) and compare W and k*T.
func VerifyToken(t []byte, Wx, Wy *big.Int, k []byte) bool {

	Tx, Ty := HashToCurve(t)
	X, Y := curve.ScalarMult(Tx, Ty, k[:])

	if curve.IsOnCurve(Tx, Ty) && X.Cmp(Wx) == 0 && Y.Cmp(Wy) == 0 {
		return true
	}
	return false
}
