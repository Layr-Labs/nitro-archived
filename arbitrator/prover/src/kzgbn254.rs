
use crate::utils::Bytes32;
use kzgbn254::{
    kzg::Kzg, blob::Blob, consts::FIELD_ELEMENTS_PER_BLOB,
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
use ark_ec::{Group, VariableBaseMSM};
use ark_ff::{PrimeField, Field};

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
    pub static ref KZG: kzgbn254::kzg::Kzg = kzgbn254::kzg::Kzg::setup(
        "src/test-files/g1.point", 
        "src/test-files/g2.point",
        3000
    ).unwrap();

    // modulus for the underlying field F_r of the elliptic curve
    pub static ref BLS_MODULUS: BigUint = "21888242871839275222246405745257275088548364400416034343698204186575808495617".parse().unwrap();

    pub static ref ROOT_OF_UNITY: BigUint = {
        // order 2^28 for BN254
        let root: BigUint = "19103219067921713944291392827692070036145651957329286315305642004821462161904".parse().unwrap();

        let exponent = (1_u64 << 28) / (FIELD_ELEMENTS_PER_BLOB as u64);
        root.modpow(&BigUint::from(exponent), &BLS_MODULUS)
    };
}

/// Creates a KZG preimage proof consumable by the point evaluation precompile.
pub fn prove_kzg_preimage_bn254(
    hash: Bytes32,
    preimage: &[u8],
    offset: u32,
    out: &mut impl Write,
) -> Result<()> {

    // // we probably want to unpad this huh
    let blob = kzgbn254::blob::Blob::from_bytes_and_pad(preimage);

    let commitment = KZG.blob_to_kzg_commitment(&blob)?;

    let mut commitment_bytes = Vec::new();
    commitment.serialize_uncompressed(&mut commitment_bytes).unwrap();

    let mut expected_hash: Bytes32 = Sha256::digest(&*commitment_bytes).into();
    expected_hash[0] = 1;
    ensure!(
        hash == expected_hash,
        "Trying to prove versioned hash {} preimage but recomputed hash {}",
        hash,
        expected_hash,
    );

    // we can't enture that offset is 32-byte aligned, because we don't know the size of the preimage, we will need to encode preimage length into this later
    // ensure!(
    //     offset % 32 == 0,
    //     "Cannot prove blob preimage at unaligned offset {}",
    //     offset,
    // );

    //let offset_usize = usize::try_from(offset)?;
    let proving_offset = offset;
    // // let proving_past_end = offset_usize >= preimage.len();
    // // if proving_past_end {
    // //     // Proving any offset proves the length which is all we need here,
    // //     // because we're past the end of the preimage.
    // //     proving_offset = 0;
    // // }

    // should this maybe be field elements in our blob instead of in the max size???
    // blob.lengthAfterPadding / 32
    let exp = (proving_offset / 32).reverse_bits()
        >> (u32::BITS - FIELD_ELEMENTS_PER_BLOB.trailing_zeros());
    
    // make sure on finite field
    let z = ROOT_OF_UNITY.modpow(&BigUint::from(exp), &BLS_MODULUS);
    let z_bytes = z.to_bytes_be();

    // pad to 32
    let mut padded_z_bytes = [0u8; 32];
    padded_z_bytes[32 - z_bytes.len()..].copy_from_slice(&z_bytes);

    
    // ask anup to just give it to me in the proof function later
    let mut proven_y = blob.get_blob_data();
    let offset_usize = offset as usize; // Convert offset to usize
    proven_y = proven_y[offset_usize..(offset_usize + 32)].to_vec();

    let polynomial = blob.to_polynomial().unwrap();
    let length: usize = blob.len();



    // polynomial, index, roots_of_unity, padded_input_length
    let (kzg_proof, error) = kzg.compute_kzg_proof(&polynomial, &z_bytes,,length)



    // // let's return this value too???? not sure why not working so get it to align
    // // var zG2 bn254.G2Affine
	// // zG2.ScalarMultiplication(&G2Gen, zFr.BigInt(&valueBig))

    let g2_generator = G2Affine::prime_subgroup_generator();
    let z_g2 = g2_generator * proven_y.BigInt(); // anup says this works?

    // // var xMinusZ bn254.G2Affine
	// // xMinusZ.Sub(&G2tau, &zG2)

    let g2_tau = g2_generator * 2;
    let x_minus_z = g2_tau - z_g2;

    out.write_all(&*hash)?; // hash
    out.write_all(&*z_bytes)?;
    out.write_all(&*proven_y)?;
    out.write_all(&*x_minus_z)?;
    out.write_all(&*commitment)?;
    out.write_all(kzg_proof.to_bytes().as_slice())?;
    
    

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
