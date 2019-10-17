// Copyright Cryptape Technologies LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::collections::HashMap;
use std::fs::File;
use std::io::prelude::*;
use std::usize::MAX;

use bincode::{deserialize, serialize, Infinite};

use cita_directories::DataPath;
use crypto::{pubkey_to_address, Sign, Signature};
use hashable::Hashable;
use libproto::blockchain::{Proof, ProofType};
use rlp::{Decodable, DecoderError, Encodable, RlpStream, UntrustedRlp};
use types::{Address, H256};

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum Step {
    Propose = 0,
    ProposeWait = 1,
    Prevote = 2,
    PrevoteWait = 3,
    PrecommitAuth = 4,
    Precommit = 5,
    PrecommitWait = 6,
    Commit = 7,
    CommitWait = 8,
}

impl From<u8> for Step {
    fn from(s: u8) -> Step {
        match s {
            0 => Step::Propose,
            1 => Step::ProposeWait,
            2 => Step::Prevote,
            3 => Step::PrevoteWait,
            4 => Step::PrecommitAuth,
            5 => Step::Precommit,
            6 => Step::PrecommitWait,
            7 => Step::Commit,
            8 => Step::CommitWait,
            _ => panic!("Invalid step."),
        }
    }
}

impl Step {
    pub fn into_u8(&self) -> u8 {
        *self as u8
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub struct BftProposalMsg {
    pub height: usize,
    pub round: usize,
    pub step: Step,
    pub author: Address,
    pub proposal: Option<H256>,
}

impl BftProposalMsg {
    pub fn new(
        height: usize,
        round: usize,
        step: Step,
        author: Address,
        proposal: Option<H256>,
    ) -> Self {
        BftProposalMsg {
            height,
            round,
            step,
            author,
            proposal,
        }
    }

    pub fn values(&self) -> (usize, usize, Step, Address, Option<H256>) {
        (
            self.height,
            self.round,
            self.step,
            self.author,
            self.proposal,
        )
    }
}

impl Encodable for BftProposalMsg {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(5);
        s.append(&self.height);
        s.append(&self.round);
        s.append(&self.step.into_u8());
        s.append(&self.author);
        s.append(&self.proposal.unwrap_or(H256::from(0)));
    }
}

impl Decodable for BftProposalMsg {
    fn decode(rlp: &UntrustedRlp) -> Result<Self, DecoderError> {
        let value: H256 = rlp.val_at(4)?;
        let proposal = if value.is_zero() { None } else { Some(value) };
        let msg = BftProposalMsg {
            height: rlp.val_at(0)?,
            round: rlp.val_at(1)?,
            step: rlp.val_at::<u8>(2)?.into(),
            author: rlp.val_at(3)?,
            proposal,
        };
        Ok(msg)
    }
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct BftProof {
    pub proposal: H256,
    // Prev height
    pub height: usize,
    pub round: usize,
    pub commits: HashMap<Address, Signature>,
}

impl BftProof {
    pub fn new(
        height: usize,
        round: usize,
        proposal: H256,
        commits: HashMap<Address, Signature>,
    ) -> BftProof {
        BftProof {
            height,
            round,
            proposal,
            commits,
        }
    }

    pub fn default() -> Self {
        BftProof {
            height: MAX,
            round: MAX,
            proposal: H256::default(),
            commits: HashMap::new(),
        }
    }

    pub fn store(&self) {
        let proof_path = DataPath::proof_bin_path();
        let mut file = File::create(&proof_path).unwrap();
        let encoded_proof: Vec<u8> = serialize(&self, Infinite).unwrap();
        file.write_all(&encoded_proof).unwrap();
        let _ = file.sync_all();
    }

    pub fn load(&mut self) {
        let proof_path = DataPath::proof_bin_path();
        if let Ok(mut file) = File::open(&proof_path) {
            let mut content = Vec::new();
            if file.read_to_end(&mut content).is_ok() {
                if let Ok(decoded) = deserialize(&content[..]) {
                    //self.round = decoded.round;
                    //self.proposal = decoded.proposal;
                    //self.commits = decoded.commits;
                    *self = decoded;
                }
            }
        }
    }

    pub fn is_default(&self) -> bool {
        if self.round == MAX {
            return true;
        }
        false
    }

    // Check proof commits
    pub fn check(&self, h: usize, authorities: &[Address]) -> bool {
        if h == 0 {
            return true;
        }
        if h != self.height {
            return false;
        }
        if 2 * authorities.len() >= 3 * self.commits.len() {
            return false;
        }
        self.commits.iter().all(|(sender, sig)| {
            if authorities.contains(sender) {
                let msg = BftProposalMsg {
                    height: h,
                    round: self.round,
                    step: Step::Precommit,
                    author: *sender,
                    proposal: Some(self.proposal),
                };
                let msg: Vec<u8> = rlp::encode(&msg).to_vec();
                let signature = Signature(sig.0);
                if let Ok(pubkey) = signature.recover(&msg.crypt_hash()) {
                    return pubkey_to_address(&pubkey) == *sender;
                }
            }
            false
        })
    }
}

pub struct Commit(Address, Signature);

impl Encodable for Commit {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(2);
        s.append(&self.0);
        s.append(&self.1);
    }
}

impl Decodable for Commit {
    fn decode(rlp: &UntrustedRlp) -> Result<Self, DecoderError> {
        let commit = Commit(rlp.val_at(0)?, rlp.val_at(1)?);
        Ok(commit)
    }
}

pub struct Commits(Vec<Commit>);

impl Commits {
    fn len(&self) -> usize {
        self.0.len()
    }

    fn from_hash_map(hash_map: HashMap<Address, Signature>) -> Self {
        let mut commits = Vec::new();
        hash_map.iter().for_each(|(key, value)| {
            commits.push(Commit(*key, value.clone()));
        });
        Commits(commits)
    }

    fn to_hash_map(&self) -> HashMap<Address, Signature> {
        let mut hash_map = HashMap::new();
        self.0.iter().for_each(|commit| {
            hash_map.insert(commit.0, commit.1.clone());
        });
        hash_map
    }
}

impl Encodable for Commits {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(self.len() + 1);
        s.append(&self.len());

        self.0.iter().for_each(|e| {
            s.append(e);
        });
    }
}

impl Decodable for Commits {
    fn decode(rlp: &UntrustedRlp) -> Result<Self, DecoderError> {
        let len = rlp.val_at(0)?;
        let mut commits = Vec::new();
        for i in 1..=len {
            let element = rlp.val_at(i)?;
            commits.push(element)
        }

        Ok(Commits(commits))
    }
}

impl Decodable for BftProof {
    fn decode(rlp: &UntrustedRlp) -> Result<Self, DecoderError> {
        let commits: Commits = rlp.val_at(3)?;
        let proof = BftProof {
            proposal: rlp.val_at(0)?,
            height: rlp.val_at(1)?,
            round: rlp.val_at(2)?,
            commits: commits.to_hash_map(),
        };
        Ok(proof)
    }
}

impl Encodable for BftProof {
    fn rlp_append(&self, s: &mut RlpStream) {
        let commits = Commits::from_hash_map(self.commits.clone());
        s.begin_list(4);
        s.append(&self.proposal);
        s.append(&self.height);
        s.append(&self.round);
        s.append(&commits);
    }
}

impl From<Proof> for BftProof {
    fn from(p: Proof) -> Self {
        let decoded: BftProof = rlp::decode(p.get_content());
        decoded
    }
}

impl Into<Proof> for BftProof {
    fn into(self) -> Proof {
        let mut proof = Proof::new();
        let encoded_proof: Vec<u8> = rlp::encode(&self).to_vec();
        proof.set_content(encoded_proof);
        proof.set_field_type(ProofType::Bft);
        proof
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use libproto::blockchain::Proof;

    use super::{BftProof, H256};
    use crate::BftProposalMsg;
    use crate::Step;
    use types::Address;

    #[test]
    pub fn proof_convert() {
        let proof = BftProof::new(0, 1, H256::default(), HashMap::new());
        let proto_proof: Proof = proof.clone().into();
        let de_proof: BftProof = proto_proof.into();
        assert_eq!(proof, de_proof);
    }

    #[test]
    pub fn bft_proof_msg_encode_decode() {
        let msg = BftProposalMsg::new(1, 1, Step::Precommit, Address::from(1), Some(H256::from(2)));
        let en_msg: Vec<u8> = rlp::encode(&msg).into_vec();
        let de_msg: BftProposalMsg = rlp::decode(&en_msg);
        println!("{:?}", de_msg);
        assert_eq!(msg, de_msg);

        let msg = BftProposalMsg::new(0, 0, Step::Precommit, Address::from(0), None);
        let en_msg: Vec<u8> = rlp::encode(&msg).into_vec();
        let de_msg: BftProposalMsg = rlp::decode(&en_msg);
        println!("{:?}", de_msg);
        assert_eq!(msg, de_msg);
    }
}
