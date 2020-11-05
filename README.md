# anonymous-tokens

This is joint work by [Tjerand Silde](https://tjerandsilde.no) and [Martin Strand](https://twitter.com/martinstrand).

We present a simple protocol for anonymous tokens. The real world situation in mind is the Norwegian contract tracing app Smittestopp 2.0. We have three parties in our protocol: Smittestopp Backend, Smittestopp App and Smittestopp Verification. More information about the setting can be found in the [Fhi.Smittestopp.Documentation](https://github.com/folkehelseinstituttet/Fhi.Smittestopp.Documentation) repository.

The situation is the following:
- Smittestopp App (SA) initiate contact with Smittestopp Verification (SV) to report on a positive test.
- The user authenticates himself, SV verifies that the user has tested positive, and issues a token to SA.
- SA sends the token to Smittestopp Backend (SB) together with his diagnosis keys.
- SB verifies the token, and conditionally accept the keys and sends them to all users in the system.

We give a [brief analysis (in Norwegian)](/documents/Ytterligere.forsterket.personvern.i.Smittestopp.2.0.pdf) of the security of this protocol, and point out that a it is possible to correlate a user with his diagnosis keys, for example if SV and SB share their list of tokens. In our updated protocol we give a solution for randomised tokens that make it infeasible to make this connection, and hence, increase the privacy of the user. It goes as following:

- SA samples a seed and sends a masked nonce computed from the seed to SV when initiating contact.
- SV signs the masked nonce as a token, and proves that it used the correct signing key.
- SA verifies the proof, and conditionally unmask the token before it sends it to SB together with the seed.
- SB verifies that the randomised token was correctly computed with respect to the seed.

We note that the process of masking the seed make it impossible to correlate the token with the randomised token. See our [attachment (in Norwegian)](/documents/Smittestopp_2_0__Vedlegg.pdf) for the cryptographic details. Our solution is based on a Oblivious Pseudo-random Function (OPRF), and the protocol is inspired by [Privacy Pass](https://privacypass.github.io.). See also the Privacy Pass [paper](https://www.petsymposium.org/2018/files/papers/issue3/popets-2018-0026.pdf) and [code](https://github.com/privacypass/challenge-bypass-extension#cryptography).

Everything in implemented in [Go](https://golang.org), and we refer to the [crypto/elliptic](https://golang.org/pkg/crypto/elliptic) package for more details about the cryptography used in our code.
