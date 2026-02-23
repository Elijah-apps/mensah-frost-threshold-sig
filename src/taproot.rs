use crate::crypto::Signature;
use crate::errors::FrostError;
use crate::errors::Result;
use secp256k1::XOnlyPublicKey;
use secp256k1::PublicKey;
use secp256k1::Secp256k1;
use crate::crypto::sha256;

/// A Taproot-ready public key with optional script tree.
#[derive(Debug, Clone)]
pub struct TaprootKey {
    pub internal_key: XOnlyPublicKey,
    pub merkle_root: Option<[u8; 32]>,
    pub output_key: XOnlyPublicKey,
}

impl TaprootKey {
    /// Creates a new Taproot key from an internal public key.
    pub fn new(
        internal_key: XOnlyPublicKey,
        merkle_root: Option<[u8; 32]>,
    ) -> Result<Self> {
        let output_key = compute_taproot_output_key(internal_key, merkle_root)?;
        
        Ok(Self {
            internal_key,
            merkle_root,
            output_key,
        })
    }

    /// Returns the taproot output key (tweaked internal key).
    pub fn output_key(&self) -> XOnlyPublicKey {
        self.output_key
    }

    /// Returns the internal key (untweaked).
    pub fn internal_key(&self) -> XOnlyPublicKey {
        self.internal_key
    }

    /// Returns the merkle root of the script tree (if any).
    pub fn merkle_root(&self) -> Option<&[u8; 32]> {
        self.merkle_root.as_ref()
    }

    /// Creates a Taproot spend signature from a FROST signature.
    pub fn sign_taproot(
        &self,
        signature: &Signature,
        annex: Option<&[u8]>,
    ) -> Result<TaprootSignature> {
        Ok(TaprootSignature {
            signature: signature.clone(),
            annex: annex.map(|x| x.to_vec()),
            sighash_type: TaprootSighashType::Default,
        })
    }

    /// Verifies a Taproot spend signature.
    pub fn verify_taproot_spend(
        &self,
        message: &[u8],
        signature: &TaprootSignature,
    ) -> Result<bool> {
        Ok(signature.signature.verify(&self.output_key, message)?)
    }
}

/// A Taproot signature with SIGHASH type and optional annex.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TaprootSignature {
    pub signature: Signature,
    pub annex: Option<Vec<u8>>,
    pub sighash_type: TaprootSighashType,
}

impl TaprootSignature {
    /// Returns the signature as bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.signature.to_bytes().to_vec();
        
        match self.sighash_type {
            TaprootSighashType::Default => bytes.push(0x00),
            TaprootSighashType::All => bytes.push(0x01),
            TaprootSighashType::None => bytes.push(0x02),
            TaprootSighashType::Single => bytes.push(0x03),
        }
        
        if let Some(annex) = &self.annex {
            bytes.extend_from_slice(annex);
        }
        
        bytes
    }

    /// Parses a Taproot signature from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 65 {
            return Err(FrostError::InvalidSignature);
        }
        
        let sig_bytes = &bytes[0..64];
        let sighash_byte = bytes[64];
        
        let signature = Signature::from_bytes(sig_bytes.try_into().map_err(|_| FrostError::InvalidSignature)?)?;
        
        let annex = if bytes.len() > 65 {
            Some(bytes[65..].to_vec())
        } else {
            None
        };
        
        let sighash_type = match sighash_byte {
            0x00 => TaprootSighashType::Default,
            0x01 => TaprootSighashType::All,
            0x02 => TaprootSighashType::None,
            0x03 => TaprootSighashType::Single,
            _ => return Err(FrostError::InvalidSignature),
        };
        
        Ok(Self {
            signature,
            annex,
            sighash_type,
        })
    }
}

/// SIGHASH types for Taproot.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TaprootSighashType {
    /// Default SIGHASH type for Taproot.
    Default = 0x00,
    /// All inputs and outputs are included.
    All = 0x01,
    /// No outputs are included.
    None = 0x02,
    /// Only the first output is included.
    Single = 0x03,
}

/// Computes the Taproot output key.
fn compute_taproot_output_key(
    internal_key: XOnlyPublicKey,
    merkle_root: Option<[u8; 32]>,
) -> Result<XOnlyPublicKey> {
    let secp = Secp256k1::new();
    
    // Compute tweak
    let mut tweak_data = Vec::with_capacity(32 + 1);
    tweak_data.extend_from_slice(&internal_key.serialize());
    
    if let Some(merkle) = merkle_root {
        tweak_data.extend_from_slice(&[0x01]);
        tweak_data.extend_from_slice(&merkle);
    }
    
    let tweak_hash = sha256(&tweak_data);
    
    // Compute tweaked public key
    let internal_pk = PublicKey::from_secret_key(&secp, &secp256k1::SecretKey::from_slice(&[0u8; 32]).unwrap());
    let tweaked_pk = internal_pk.tweak_add_check(&tweak_hash)?;
    
    let (xonly, _) = XOnlyPublicKey::from_keypair(&secp, &secp256k1::Keypair::from(
        secp256k1::SecretKey::from_slice(&[0u8; 32]).unwrap()
    ));
    
    Ok(xonly)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::Participant;
    use crate::crypto::ParticipantId;
    use crate::signing::Coordinator;
    use crate::signing::ParticipantSigning;

    #[test]
    fn test_taproot_key_creation() {
        // Initialize a simple Taproot key without merkle root
        let secp = Secp256k1::new();
        let (internal_key, _) = XOnlyPublicKey::from_keypair(&secp, &secp256k1::Keypair::from(
            secp256k1::SecretKey::from_slice(&[0u8; 32]).unwrap()
        ));
        
        let taproot_key = TaprootKey::new(internal_key, None).unwrap();
        
        assert_eq!(taproot_key.internal_key(), internal_key);
        assert!(taproot_key.merkle_root().is_none());
    }

    #[test]
    fn test_taproot_signing_and_verification() {
        // Initialize participants and complete DKG
        let mut participants = Vec::new();
        for i in 0..5 {
            participants.push(Participant::new(ParticipantId(i), 3, 5).unwrap());
        }

        let round1_outputs: Vec<_> = participants.iter_mut()
            .map(|p| p.dkg_round1().unwrap())
            .collect();

        let round2_outputs: Vec<_> = participants.iter_mut()
            .map(|p| p.dkg_round2(&round1_outputs).unwrap())
            .collect();

        let distributed_keys: Vec<_> = participants.iter_mut()
            .map(|p| p.complete_dkg(&round2_outputs).unwrap())
            .collect();

        let coordinator = Coordinator::new(3, 5).unwrap();

        let mut signing_round1_outputs = Vec::new();
        let mut nonces_store = Vec::new();

        for participant in &participants[0..3] {
            let (nonces, commitments) = participant.signing_round1().unwrap();
            signing_round1_outputs.push(commitments);
            nonces_store.push(nonces);
        }

        let message = b"Taproot transaction data";
        let session = coordinator.start_signing_session(message, &signing_round1_outputs).unwrap();

        let mut signature_shares = Vec::new();
        for (i, participant) in participants[0..3].iter().enumerate() {
            let share = participant.signing_round2(
                &session,
                &nonces_store[i],
                &distributed_keys[i],
            ).unwrap();
            signature_shares.push((participant.id(), share));
        }

        let final_signature = coordinator.aggregate_signatures(&session, signature_shares).unwrap();

        // Create Taproot key
        let taproot_key = TaprootKey::new(
            distributed_keys[0].public_key(),
            None,
        ).unwrap();

        // Create Taproot signature
        let taproot_signature = taproot_key.sign_taproot(&final_signature, None).unwrap();

        // Verify Taproot signature
        assert!(taproot_key.verify_taproot_spend(message, &taproot_signature).unwrap());
    }
}
