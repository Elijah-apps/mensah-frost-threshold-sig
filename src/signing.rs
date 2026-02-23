use crate::crypto::ParticipantId;
use crate::crypto::Signature;
use crate::crypto::SecretScalar;
use crate::dkg::DistributedKey;
use crate::errors::FrostError;
use crate::errors::Result;
use secp256k1::XOnlyPublicKey;
use secp256k1::Secp256k1;
use secp256k1::rand::thread_rng;
use zeroize::Zeroizing;
use std::collections::HashMap;

/// A coordinator manages the signing session.
#[derive(Debug, Clone)]
pub struct Coordinator {
    threshold: usize,
    n: usize,
}

impl Coordinator {
    /// Creates a new coordinator.
    pub fn new(threshold: usize, n: usize) -> Result<Self> {
        if n < 2 {
            return Err(FrostError::InvalidParticipantCount);
        }
        if threshold < 1 || threshold >= n {
            return Err(FrostError::InvalidThreshold);
        }

        Ok(Self { threshold, n })
    }

    /// Starts a new signing session.
    pub fn start_signing_session(
        &self,
        message: &[u8],
        commitments: &[SigningRound1Output],
    ) -> Result<SigningSession> {
        // Verify commitments
        if commitments.len() < self.threshold {
            return Err(FrostError::NotEnoughShares {
                expected: self.threshold,
                got: commitments.len(),
            });
        }

        // Check for duplicate participants
        let mut seen = HashMap::new();
        for commit in commitments {
            if seen.contains_key(&commit.participant_id) {
                return Err(FrostError::DuplicateParticipant(commit.participant_id.0));
            }
            seen.insert(commit.participant_id, ());
        }

        Ok(SigningSession {
            message: message.to_vec(),
            participants: commitments
                .iter()
                .map(|c| c.participant_id)
                .collect(),
            commitments: commitments.to_vec(),
            threshold: self.threshold,
        })
    }

    /// Aggregates signature shares into a final signature.
    pub fn aggregate_signatures(
        &self,
        session: &SigningSession,
        shares: Vec<(ParticipantId, SigningRound2Output)>,
    ) -> Result<Signature> {
        if shares.len() < self.threshold {
            return Err(FrostError::NotEnoughShares {
                expected: self.threshold,
                got: shares.len(),
            });
        }

        // Verify all shares are from valid participants
        for (id, _) in &shares {
            if !session.participants.contains(id) {
                return Err(FrostError::ParticipantNotFound(id.0));
            }
        }

        // Simplified aggregation
        let secp = Secp256k1::new();
        let mut aggregated = [0u8; 64];
        
        for (i, (_, share)) in shares.iter().enumerate() {
            let share_bytes = share.to_bytes();
            
            for (j, byte) in share_bytes.iter().enumerate() {
                aggregated[j] = (aggregated[j] + byte) % 256;
            }
        }

        Ok(Signature::from_bytes(&aggregated)?)
    }
}

/// A signing session managed by the coordinator.
#[derive(Debug, Clone)]
pub struct SigningSession {
    message: Vec<u8>,
    participants: Vec<ParticipantId>,
    commitments: Vec<SigningRound1Output>,
    threshold: usize,
}

impl SigningSession {
    /// Returns the message to sign.
    pub fn message(&self) -> &[u8] {
        &self.message
    }

    /// Returns the list of participants in this session.
    pub fn participants(&self) -> &[ParticipantId] {
        &self.participants
    }

    /// Returns the commitments from round 1.
    pub fn commitments(&self) -> &[SigningRound1Output] {
        &self.commitments
    }
}

/// Round 1 output of the signing phase.
#[derive(Debug, Clone)]
pub struct SigningRound1Output {
    pub participant_id: ParticipantId,
    pub nonce_commitment: Vec<u8>,
}

/// Round 2 output of the signing phase.
#[derive(Debug, Clone)]
pub struct SigningRound2Output {
    pub participant_id: ParticipantId,
    pub signature_share: Vec<u8>,
}

impl SigningRound2Output {
    /// Returns the signature share as bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.signature_share.clone()
    }
}

/// Extension methods for participants during signing phase.
pub trait ParticipantSigning {
    /// Performs round 1 of signing phase.
    fn signing_round1(&self) -> Result<(Zeroizing<SecretScalar>, SigningRound1Output)>;

    /// Performs round 2 of signing phase.
    fn signing_round2(
        &self,
        session: &SigningSession,
        nonce: &Zeroizing<SecretScalar>,
        distributed_key: &DistributedKey,
    ) -> Result<SigningRound2Output>;
}

impl ParticipantSigning for crate::dkg::Participant {
    fn signing_round1(&self) -> Result<(Zeroizing<SecretScalar>, SigningRound1Output)> {
        let nonce = Zeroizing::new(SecretScalar::random());
        let commitment = nonce.to_bytes().to_vec();

        Ok((
            nonce,
            SigningRound1Output {
                participant_id: self.id(),
                nonce_commitment: commitment,
            },
        ))
    }

    fn signing_round2(
        &self,
        session: &SigningSession,
        nonce: &Zeroizing<SecretScalar>,
        distributed_key: &DistributedKey,
    ) -> Result<SigningRound2Output> {
        // Check if this participant is in the session
        if !session.participants().contains(&self.id()) {
            return Err(FrostError::ParticipantNotFound(self.id().0));
        }

        // Generate signature share
        let msg_hash = crate::crypto::sha256(session.message());
        let share = self.generate_signature_share(&msg_hash, nonce, distributed_key);

        Ok(SigningRound2Output {
            participant_id: self.id(),
            signature_share: share.to_bytes().to_vec(),
        })
    }
}

impl crate::dkg::Participant {
    /// Generates a signature share.
    fn generate_signature_share(
        &self,
        msg_hash: &[u8; 32],
        nonce: &Zeroizing<SecretScalar>,
        distributed_key: &DistributedKey,
    ) -> SecretScalar {
        // Simplified share generation
        let mut share_bytes = [0u8; 32];
        
        for i in 0..32 {
            share_bytes[i] = (msg_hash[i] + nonce.to_bytes()[i] + distributed_key.secret_share()[i]) % 256;
        }
        
        SecretScalar::from_bytes(&share_bytes).unwrap()
    }
}

/// Verifies a threshold signature.
pub fn verify_threshold_signature(
    public_key: &XOnlyPublicKey,
    message: &[u8],
    signature: &Signature,
) -> bool {
    signature.verify(public_key, message).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::Participant;
    use crate::crypto::ParticipantId;

    #[test]
    fn test_signing_basic_flow() {
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

        // Create coordinator
        let coordinator = Coordinator::new(3, 5).unwrap();

        // Signing round 1
        let mut signing_round1_outputs = Vec::new();
        let mut nonces_store = Vec::new();

        for participant in &participants[0..3] {
            let (nonces, commitments) = participant.signing_round1().unwrap();
            signing_round1_outputs.push(commitments);
            nonces_store.push(nonces);
        }

        let message = b"Taproot transaction data";
        let session = coordinator.start_signing_session(message, &signing_round1_outputs).unwrap();

        // Signing round 2
        let mut signature_shares = Vec::new();
        for (i, participant) in participants[0..3].iter().enumerate() {
            let share = participant.signing_round2(
                &session,
                &nonces_store[i],
                &distributed_keys[i],
            ).unwrap();
            signature_shares.push((participant.id(), share));
        }

        // Aggregate signatures
        let final_signature = coordinator.aggregate_signatures(&session, signature_shares).unwrap();

        // Verify signature
        assert!(verify_threshold_signature(
            &distributed_keys[0].public_key(),
            message,
            &final_signature
        ));
    }
}
