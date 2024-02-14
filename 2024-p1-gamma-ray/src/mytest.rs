use std::ops::Mul;

use ark_bls12_381::Fq2 as F;
use ark_bls12_381::Fq as Fq;
use ark_ec::pairing::Pairing;
use ark_ec::CurveGroup;
use ark_ff::BigInteger;
use ark_std::{One, UniformRand};
use ark_ff::{Field, PrimeField};
use num_bigint::BigUint;
use ark_bls12_381::{Bls12_381, G1Projective as G1, G2Projective as G2, G1Affine, G2Affine, Fr as ScalarField};


fn main() {
  let mut rng = rand::thread_rng();
  // Let's sample uniformly random field elements:
  let a = F::rand(&mut rng);
  let b = F::rand(&mut rng);
  println!("a = {:?}", a);

  // We can add...
  let c = a + b;
  // ... subtract ...
  let d = a - b;
  // ... double elements ...
  assert_eq!(c + d, a.double());

  // ... multiply ...
  let e = c * d;
  // ... square elements ...
  assert_eq!(e, a.square() - b.square());

  // ... and compute inverses ...
  let xd = a.inverse();
  println!("xd = {:?}", xd);
  xd.unwrap_or_default();
  println!("one inverse = {:?}", F::one().inverse().unwrap());
  assert_eq!(a.inverse().unwrap() * a, F::one());
  let two = F::from(2u64);
  println!("two inverse = {:?}", two.inverse().unwrap());
  let mut two2 = F::from(2u64);
  println!("two2 = {:?}", two2);
  // two2.c0 = Fq::from(0u64);
  two2.c1 = Fq::from(2u64);
  println!("two2 = {:?}", two2);
  println!("two2 inverse = {:?}", two2.inverse().unwrap());

  let one = Fq::from(BigUint::from(1u64));
  let two = Fq::from(BigUint::from(2u64));
  let three = Fq::from(BigUint::from(3u64));
  let four = Fq::from(BigUint::from(4u64));
  let a = F::new(two, one);
  let b = F::new(three, four);
  println!("my a = {:?}", a);
  println!("my b = {:?}", b);
  println!("my a + b = {:?}", a + b);
  println!("my a * b = {:?}", a * b);

  let mut a2 = F::rand(&mut rng);
  if a2.legendre().is_qnr() {
    a2 = a2.square();
  }
  let b2 = a2.sqrt().unwrap();
  assert_eq!(b2.square(), a2);

  let mut a2 = F::rand(&mut rng);
  while a2.legendre().is_qr() {
    a2 = F::rand(&mut rng);
  }
  let b2 = a2.sqrt();
  assert!(b2.is_none());

  let a3 = Fq::rand(&mut rng);
  let modulus = <Fq as PrimeField>::MODULUS;
  println!("a3 = {:?}", a3);
  println!("modulus = {:?}", modulus);
  assert_eq!(a3.pow(&modulus), a3.pow(&[1u64]));

  let one: BigUint = Fq::one().into();
  assert_eq!(one, BigUint::one());
  
  let bts = modulus.to_bytes_le();
  // bts[0] = bts[0] - 1;
  let n = Fq::from_le_bytes_mod_order(&bts);
  assert_eq!(n, Fq::one() - Fq::one());
  let bts_found = [4].to_vec();
  let m = Fq::from_le_bytes_mod_order(&bts_found);
  let one = Fq::one();
  assert_eq!(m, (one + one).pow(&[2]));
  println!("m = {:?}", m);
  println!("one = {:?}", one);
  let mm = m.pow(&[80, 0]);
  println!("mm = {:?}", mm);
  // assert_eq!(m, one.pow(&[4]));


  let mut rng = ark_std::rand::thread_rng();
  let a = G1::rand(&mut rng);
  let b = G1::rand(&mut rng);
  let c = a + b;
  // ...and multiply group elements by elements of the corresponding scalar field
  let scalar = ScalarField::rand(&mut rng);
  let e = c.mul(&scalar);
  let f = e.mul(&scalar.inverse().unwrap());
  assert_eq!(f, c);

  let e_affine = e.into_affine();
  let e_x = e_affine.x;
  let e_y = e_affine.y;
  let new_e = G1Affine::new(e_x, e_y);
  assert_eq!(e_affine, new_e);
  // Users should check that the new point is on the curve and is in the prime-order group:
  assert!(new_e.is_on_curve());
  assert!(new_e.is_in_correct_subgroup_assuming_on_curve());


  // Let's sample uniformly random field elements:
  let a: G1Affine = G1::rand(&mut rng).into();
  let b: G2Affine = G2::rand(&mut rng).into();
  println!("a = {:?}", a);
  println!("b = {:?}", b);
  // We can compute the pairing of `a` and `b`:
  let c = Bls12_381::pairing(a, b);
  println!("c = {:?}", c);

  // We can also compute the pairing partwise:
  // First, we compute the Miller loop:
  let c_ml = Bls12_381::miller_loop(a, b);
  let c_fe = Bls12_381::final_exponentiation(c_ml).unwrap();
  assert_eq!(c, c_fe);
}