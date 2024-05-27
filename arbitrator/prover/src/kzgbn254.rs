
use crate::utils::Bytes32;
use ark_ec::AffineRepr;
use kzgbn254::{
    kzg::Kzg,
    blob::Blob,
    helpers::{remove_empty_byte_from_padded_bytes, set_bytes_canonical_manual}
};
use eyre::{ensure, Result, WrapErr};
use ark_bn254::{Fr, G1Affine, G1Projective, G2Affine};
use num::BigUint;
use serde::{de::Error as _, Deserialize};
use sha2::{Digest, Sha256};
use std::{convert::TryFrom, io::Write};
use hex::decode;
use ark_std::{ops::Mul, ops::Add};
use ark_serialize::CanonicalSerialize;
use ark_ff::{PrimeField, Field};
use ark_ff::BigInteger256;

struct HexBytesParser;

impl<'de, const N: usize> serde_with::DeserializeAs<'de, [u8; N]> for HexBytesParser {
    fn deserialize_as<D>(deserializer: D) -> Result<[u8; N], D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let mut s = s.as_str();
        if s.starts_with("0x") {
            s = &s[2..];
        }
        let mut bytes = [0; N];
        match hex::decode_to_slice(s, &mut bytes) {
            Ok(()) => Ok(bytes),
            Err(err) => Err(D::Error::custom(err.to_string())),
        } 
    }
}

lazy_static::lazy_static! {

    // note that we are loading 3000 for testing purposes atm, but for production use these values:
    // g1 and g2 points from the operator setup guide
    // srs_order = 268435456
    // srs_points_to_load = 131072

    pub static ref KZG: kzgbn254::kzg::Kzg = kzgbn254::kzg::Kzg::setup(
        "./arbitrator/prover/src/test-files/g1.point", 
        "./arbitrator/prover/src/test-files/g2.point",
        "./arbitrator/prover/src/test-files/g2.point.powerOf2",
        3000,
        3000
    ).unwrap();

    // modulus for the underlying field F_r of the elliptic curve
    // see https://docs.eigenlayer.xyz/eigenda/integrations-guides/dispersal/blob-serialization-requirements
    pub static ref BLS_MODULUS: BigUint = "21888242871839275222246405745257275088548364400416034343698204186575808495617".parse().unwrap();

    // pub static ref ROOT_OF_UNITY: BigUint = {
    //     // order 2^28 for BN254
    //     let root: BigUint = "19103219067921713944291392827692070036145651957329286315305642004821462161904".parse().unwrap();

    //     let exponent = (1_u64 << 28) / (FIELD_ELEMENTS_PER_BLOB as u64);
    //     root.modpow(&BigUint::from(exponent), &BLS_MODULUS)
    // };

    // (2*1024*1024)/32 = 65536
    pub static ref FIELD_ELEMENTS_PER_BLOB: usize = 65536;
}

/// Creates a KZG preimage proof consumable by the point evaluation precompile.
pub fn prove_kzg_preimage_bn254(
    hash: Bytes32,
    preimage: &[u8],
    offset: u32,
    out: &mut impl Write,
) -> Result<()> {

    let mut kzg = KZG.clone();

    // expand the roots of unity, should work as long as it's longer than chunk length and chunks
    // from my understanding the data_setup_mins pads both min_chunk_len and min_num_chunks to 
    // the next power of 2 so we can load a max of 2048 from the test values here
    // then we can take the roots of unity we actually need (len polynomial) and pass them in
    // @anup, this is a really gross way to do this, pls tell better way
    // also potential edge case where the preimage is 32 bytes
    //kzg.data_setup_custom(4, preimage.len() as u64)?;
    kzg.data_setup_mins(1, 2048)?;

    // we are expecting the preimage to be unpadded when turned into a blob function so need to unpad it first
    let unpadded_preimage_vec = remove_empty_byte_from_padded_bytes(preimage);
    let unpadded_preimage = unpadded_preimage_vec.as_slice();

    // repad it here, TODO: need to ask to change the interface for this
    let blob = kzgbn254::blob::Blob::from_bytes_and_pad(unpadded_preimage);
    let blob_polynomial = blob.to_polynomial().unwrap();
    let blob_commitment = kzg.commit(&blob_polynomial).unwrap();

    let mut commitment_bytes = Vec::new();
    blob_commitment.serialize_uncompressed(&mut commitment_bytes).unwrap();

    let mut expected_hash: Bytes32 = Sha256::digest(&*commitment_bytes).into();
    expected_hash[0] = 1;

    println!("Expected hash: {:?}", expected_hash);
    println!("Hash: {:?}", hash);
    // ensure!(
    //     hash == expected_hash,
    //     "Trying to prove versioned hash {} preimage but recomputed hash {}",
    //     hash,
    //     expected_hash,
    // );

    ensure!(
        offset % 32 == 0,
        "Cannot prove blob preimage at unaligned offset {}",
        offset,
    );

    //let offset_usize = usize::try_from(offset)?;
    let proving_offset = offset;

    // log proving offset
    println!("Proving offset: {}", proving_offset);

    // address proving past end edge case later
    // let proving_past_end = offset_usize >= preimage.len();
    // if proving_past_end {
    //     // Proving any offset proves the length which is all we need here,
    //     // because we're past the end of the preimage.
    //     proving_offset = 0;
    // }
    
    let proving_offset_bytes = proving_offset.to_le_bytes();
    let mut padded_proving_offset_bytes = [0u8; 32];
    padded_proving_offset_bytes[32 - proving_offset_bytes.len()..].copy_from_slice(&proving_offset_bytes);

    // in production we will first need to perform an IFFT on the blob data to get the expected y value
    let mut proven_y = blob.get_blob_data();
    let offset_usize = offset as usize; // Convert offset to usize
    proven_y = proven_y[offset_usize..(offset_usize + 32)].to_vec();

    let polynomial = blob.to_polynomial().unwrap();
    let length: usize = blob.len();

    let proven_y_fr = set_bytes_canonical_manual(&proven_y.as_slice());
    
    // are there cases where the g2 generator won't be the first element?
    let g2_generator = kzg.get_g2_points().get(0).unwrap().clone();
    let z_g2= g2_generator * proven_y_fr;
    let g2_tau = g2_generator.mul_bigint(BigInteger256::from(2u64));
    let g2_tau_minus_g2_z = g2_tau - z_g2;

    let mut g2_tau_minus_g2_z_bytes = Vec::new();
    g2_tau_minus_g2_z.serialize_compressed(&mut g2_tau_minus_g2_z_bytes).unwrap();

    // required roots of unity are the first polynomial length roots in the expanded set
    let roots_of_unity = kzg.get_expanded_roots_of_unity();
    let required_roots_of_unity = &roots_of_unity[..polynomial.len()];
    // TODO: ask for interface alignment later
    let kzg_proof = match kzg.compute_kzg_proof(&blob_polynomial, offset as u64, &required_roots_of_unity.to_vec()) {
        Ok(proof) => proof,
        Err(err) => return Err(err.into()),
    };

    let mut kzg_proof_compressed_bytes = Vec::new();
    kzg_proof.serialize_compressed(&mut kzg_proof_compressed_bytes).unwrap();

    out.write_all(&*hash)?;                                 // hash [:32]
    out.write_all(&padded_proving_offset_bytes)?;           // evaluation point [32:64]
    out.write_all(&*proven_y)?;                             // expected output [64:96]
    out.write_all(g2_tau_minus_g2_z_bytes.as_slice())?;     // g2TauMinusG2z [96:224]
    out.write_all(&*commitment_bytes)?;                     // kzg commitment [224:288]
    out.write_all(kzg_proof_compressed_bytes.as_slice())?;  // proof [288:352]
    

    // // pre encoded proof data
    // let hex_str = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100757220666174686572732062726f7567687420666f7274682c206f6e2074681db5eb0b7f38e2373003e7ab7b7a2509cc2759214dd255514a9c28bb46cd1201294217923e1ecdd86ec74266a1423cf152f2a54295ae39339673fcd59e1db7292099e357166e69509eea101212adfc3d2ea0254cd5526381756dcc5a942f43762f2b0c30d1fb8b1dc0d8177e44b687fc39d41a8c831665ae1af58b2bebf74b72068bf472ebc0e26c297f8a9257c3f42a38af1e4612b60f6ac64d57dc272d50b1005a4f9eb6b109d60804cbbfa4e54753b4d3b262ef7f8269fb3c2a9939741cbd06f15529acc9d00f89345e4126d6f8c2e03da0e71b718bd4a63d1fbd315cac5c04341e21e9c059641601112f3c97db852dca3a1efffe61c413af70108bc46561";
    // match decode(hex_str) {
    //     Ok(bytes) => {
    //         out.write_all(&bytes)?;
    //     },
    //     Err(e) => println!("Error decoding hex string: {}", e),
    // }

    Ok(())
}
