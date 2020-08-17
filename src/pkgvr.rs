// Public Key Generation with verifiable randomness

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use rand_os::OsRng;

use sha3::{Digest, Sha3_512};

// generating a base point, and another point for Pedersen
pub fn crs_gen()
        -> ((RistrettoPoint, RistrettoPoint),Scalar){
    println!("Generating a pair of group elements");
    let mut rng = OsRng::new().unwrap();
    let g = RistrettoPoint::random(&mut rng);
    let h = RistrettoPoint::random(&mut rng);
    println!("Generating a hash key");
    let hk = Scalar::random(&mut rng);


    ((g,h),hk)

}


// Hash

pub fn hash_3_scal(hk: Scalar, bit: Scalar, ru: Scalar, st: String) -> Scalar {
    let mut has = Sha3_512::new();
    has.input(hk.to_bytes());
    has.input(bit.to_bytes());
    has.input(ru.to_bytes());
    has.input(st.as_bytes());


    Scalar::from_hash(has)
}

pub fn hash2_3_scal(hk: Scalar, cc: RistrettoPoint, rmr: RistrettoPoint, st: String) -> Scalar {
    let mut has = Sha3_512::new();
    has.input(hk.to_bytes());
    has.input(cc.compress().to_bytes());
    has.input(rmr.compress().to_bytes());
    has.input(st.as_bytes());


    Scalar::from_hash(has)
}

// Prove that a pedersen commitment pedu opens to rpu / rhou using randomness krh/krm
pub fn ped_proof(hk: Scalar, crs:(RistrettoPoint,RistrettoPoint), pedu: RistrettoPoint, rpu:Scalar, rhou:Scalar, krh:Scalar, krm:Scalar) -> (RistrettoPoint, Scalar, Scalar)
{

    let rm = krm*crs.0;
    let rr = krh*crs.1;

    let e = hash2_3_scal(hk, pedu, rm+ rr,"ped".to_string());

    (rm + rr, krm+e*rpu,krh+e*rhou)

}

// Verify a pedersen proof
pub fn verif_schnorr(hk: Scalar, crs:(RistrettoPoint,RistrettoPoint),pedu:RistrettoPoint, d:(RistrettoPoint, Scalar, Scalar)) -> bool
{

    let e = hash2_3_scal(hk, pedu, d.0,"ped".to_string());

    d.1*crs.0 + d.2*crs.1 == d.0 + e *pedu

}

// User U generates a pedersen commitment to his random part, and prove that he knows an opening
pub fn first_flow(crs:(RistrettoPoint,RistrettoPoint), hk: Scalar) -> (Scalar, Scalar, RistrettoPoint, (RistrettoPoint,Scalar,Scalar))
{
    let mut rng = OsRng::new().unwrap();
    let ru = Scalar::random(&mut rng);

    let rpu = hash_3_scal(hk, Scalar::zero(), ru,"ru".to_string());
    let rhou = hash_3_scal(hk, Scalar::one(), ru,"rhou".to_string());

    // Randomness for schnorr
    let krh = hash_3_scal(hk, Scalar::one()+Scalar::one(), ru,"krh".to_string());
    let krm = hash_3_scal(hk, Scalar::one()+Scalar::one(), ru,"krm".to_string());


    let pedu = rpu*crs.0 + rhou * crs.1;
    let d = ped_proof(hk, crs, pedu, rpu, rhou, krh, krm);

    (rpu, rhou, pedu, d)

}

// Server sends its randomness
pub fn second_flow() -> Scalar {
    let mut rng = OsRng::new().unwrap();
    let rca = Scalar::random(&mut rng);

    rca
}


// User generates the secret key with it's randomness and an extraction from the server ones, and proves then that pk does use the server randomness and the randomness commited initially
pub fn third_flow(hk:Scalar, crs:(RistrettoPoint,RistrettoPoint),rpu: Scalar, rhou: Scalar, rca:Scalar, cc: RistrettoPoint) -> (Scalar,RistrettoPoint,(RistrettoPoint,Scalar,Scalar)) {
    let sk = rpu + hash_3_scal(hk,Scalar::zero(),rca,"ext".to_string());
    let pk = sk*crs.0;

// Generate the proof randomness
    let spu = hash_3_scal(hk, Scalar::one()+Scalar::one(), sk,"srca".to_string());
    let spu2 = hash_3_scal(hk, Scalar::one()+Scalar::one()+Scalar::one(), sk,"srhou".to_string());

    let pedfake = pk - cc;
    let d = ped_proof(hk, crs, pedfake, hash_3_scal(hk,Scalar::zero(),rca,"ext".to_string()), -rhou, spu2, spu);


    (sk,pk, d)
}


#[cfg(test)]
mod test {
    use super::*;

    fn do_key_init_test(should_succeed: bool) -> bool{
        // Generate a key pair
        let ((g,h),hk) = crs_gen();

        let (_,_,pedu,d)=first_flow((g,h),hk);

        if should_succeed
        {
            verif_schnorr(hk,(g,h),pedu, d)
        }
        else
        {
            verif_schnorr(hk,(h,g), pedu, d)
        }
    }

    #[test]
    fn ki_success() {
        assert_eq!(do_key_init_test(true), true);
    }

    #[test]
    fn ki_fail() {
        assert_eq!(do_key_init_test(false), false);
    }

    fn do_prot_test(should_succeed: bool) -> bool{
        // Generate a key pair
        let ((g,h),hk) = crs_gen();

        let (rpu,rhou,pedu,_)=first_flow((g,h),hk);

        let rca = second_flow();

        let (sk,pk,pru) = third_flow(hk, (g,h), rpu, rhou, rca,pedu);

        if should_succeed {
            verif_schnorr(hk,(g,h),pk-pedu, pru) && pk == sk*g
        }
        else
        {
            verif_schnorr(hk,(g,h), pk-pedu, pru) && pk == sk*h
        }
    }

    #[test]
    fn prot_success() {
        assert_eq!(do_prot_test(true), true);
    }

    #[test]
    fn prot_fail() {
        assert_eq!(do_prot_test(false), false);
    }

}
