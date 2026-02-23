use secp256k1::Secp256k1;
use secp256k1::PublicKey;
use secp256k1::XOnlyPublicKey;
use secp256k1::schnorr::Signature as SchnorrSignature;
use secp256k1::ecdsa::Signature as EcdsaSignature;
use secp256k1::rand::thread_rng;
use zeroize::Zeroize;

/// Participant identifier type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ParticipantId(pub u64);

impl ParticipantId {
    /// Creates a new participant identifier.
    pub fn new(id: u64) -> Self {
        Self(id)
    }
}

/// A Schnorr signature for Bitcoin.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Signature {
    inner: SchnorrSignature,
}

impl Signature {
    /// Creates a new signature from raw bytes.
    pub fn from_bytes(bytes: &[u8; 64]) -> Result<Self, crate::errors::FrostError> {
        Ok(Self {
            inner: SchnorrSignature::from_slice(bytes)
                .map_err(crate::errors::FrostError::from)?,
        })
    }

    /// Returns the signature as bytes.
    pub fn to_bytes(&self) -> [u8; 64] {
        self.inner.as_ref().try_into().expect("Signature should always be 64 bytes")
    }

    /// Returns a reference to the inner secp256k1 signature.
    pub fn as_inner(&self) -> &SchnorrSignature {
        &self.inner
    }

    /// Verifies a Schnorr signature.
    pub fn verify(
        &self,
        public_key: &XOnlyPublicKey,
        message: &[u8],
    ) -> Result<bool, crate::errors::FrostError> {
        let secp = Secp256k1::verification_only();
        let msg_hash = secp256k1::Message::from_slice(message)
            .map_err(crate::errors::FrostError::from)?;
        
        Ok(secp.verify_schnorr(&self.inner, &msg_hash, public_key) == Ok(()))
    }
}

/// A wrapper type for secret scalars with zeroization support.
#[derive(Debug)]
pub struct SecretScalar(secp256k1::SecretKey);

impl SecretScalar {
    /// Generates a new random secret scalar.
    pub fn random() -> Self {
        let mut rng = thread_rng();
        let sk = secp256k1::SecretKey::new(&mut rng);
        Self(sk)
    }

    /// Creates a new secret scalar from bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, crate::errors::FrostError> {
        Ok(Self(
            secp256k1::SecretKey::from_slice(bytes)
                .map_err(crate::errors::FrostError::from)?,
        ))
    }

    /// Returns the secret scalar as bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.secret_bytes()
    }

    /// Returns a reference to the inner secp256k1 secret key.
    pub fn as_inner(&self) -> &secp256k1::SecretKey {
        &self.0
    }

    /// Returns the corresponding public key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey::from_secret_key(&Secp256k1::new(), &self.0)
    }
}

impl Zeroize for SecretScalar {
    fn zeroize(&mut self) {
        self.0.zeroize()
    }
}

impl Drop for SecretScalar {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Computes the SHA256 hash of the given message.
pub fn sha256(message: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(message);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_scalar_random() {
        let sk = SecretScalar::random();
        let pk = sk.public_key();
        assert_ne!(pk, PublicKey::from_secret_key(&Secp256k1::new(), &secp256k1::SecretKey::from_slice(&[0u8; 32]).unwrap()));
    }

    #[test]
    fn test_signature_verify() {
        let secp = Secp256k1::new();
        let mut rng = thread_rng();
        let sk = secp256k1::SecretKey::new(&mut rng);
        let (pk, _) = XOnlyPublicKey::from_keypair(&secp, &secp256k1::Keypair::from(sk));
        
        let msg = b"test message";
        let msg_hash = secp256k1::Message::from_slice(msg).unwrap();
        let sig = secp.sign_schnorr(&msg_hash, &sk);
        
        let signature = Signature::from_bytes(&sig.as_ref().try_into().unwrap()).unwrap();
        assert!(signature.verify(&pk, msg).unwrap());
    }
}
