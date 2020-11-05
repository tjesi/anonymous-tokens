package main

import (
	"crypto/elliptic"
	"fmt"
)

// Ellipcic curve P256
var curve = elliptic.P256()

/*
	Public parameters:
	P       *big.Int // the order of the underlying field
	N       *big.Int // the order of the base point
	B       *big.Int // the constant of the curve equation
	Gx, Gy  *big.Int // (x,y) of the base point
*/
var params = curve.Params()

// B public constant setting
// randomness to 32 Bytes
const B = 32

func main() {

	// Generate private key k,
	// and publik key K.
	k, Kx, Ky := KeyGen()

	// Initiate communication.
	// Generate random numbers t and r,
	// and compute P = r*T, T = Hash(t).
	t, r, Px, Py := Initiate()

	// Generate token Q = k*P, and create
	// proof (c,z) of correctness, given K.
	Qx, Qy, c, z := GenerateToken(Px, Py, Kx, Ky, k)

	// Randomise the token Q, by removing
	// the mask r: W = (1/r)*Q = k*P.
	// Also checks that proof (c,z) is correct.
	Wx, Wy := RandomiseToken(Px, Py, Qx, Qy, Kx, Ky, c, z, r)

	// Verify that the token (t,W) is correct.
	if VerifyToken(t, Wx, Wy, k) {
		fmt.Println("Token is valid.")
	} else {
		fmt.Println("Token is not valid.")
	}

}
