// import prelude from current directory (src)
// use crate::prelude::*;

// Import from the standard library
use serde::{Deserialize, Deserializer, Serialize, Serializer};

// use concrete_core::prelude::{LweDimension,



// /// The number of scalar in an LWE mask, or the length of an LWE secret key.
// #[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize)]
// #[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
// pub struct LweDimension(pub usize);

// impl LweDimension {
//     /// Returns the associated [`LweSize`].
//     pub fn to_lwe_size(&self) -> LweSize {
//         LweSize(self.0 + 1)
//     }
// }

// #[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Copy, Clone)]
// #[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
// pub struct LweSize(pub usize);

// impl LweSize {
//     /// Returns the associated [`LweDimension`].
//     pub fn to_lwe_dimension(&self) -> LweDimension {
//         LweDimension(self.0 - 1)
//     }
// }


use concrete_core::prelude::{
                             LweDimension,
                             GlweDimension,
                             PolynomialSize,
                             StandardDev,
                             DecompositionBaseLog,
                             DecompositionLevelCount,
                             LweCiphertext32,
                             DefaultSerializationEngine,
                             LweSecretKey32,
                             GlweSecretKey32
                             
                            };
pub use concrete_core::specification::engines::*;


// pub use super::specification::engines::*;




// pub use crate::specification::engines::*;
// pub use crate::specification::entities::*;

// pub use crate::specification::engines::*;
// pub use specification::entities::*;


// use concrete_core::prelude::*;

use std::fmt::{Debug, Formatter};

/// A set of cryptographic parameters for homomorphic Boolean circuit evaluation.
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BooleanParameters {
    // pub lwe_dimension: LweDimension,
    // import LweDimension from the function above
    pub lwe_dimension: LweDimension,
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
    pub lwe_modular_std_dev: StandardDev,
    pub glwe_modular_std_dev: StandardDev,
    pub pbs_base_log: DecompositionBaseLog,
    pub pbs_level: DecompositionLevelCount,
    pub ks_base_log: DecompositionBaseLog,
    pub ks_level: DecompositionLevelCount,
}

impl BooleanParameters {
    /// Constructs a new set of parameters for boolean circuit evaluation.
    ///
    /// # Safety
    ///
    /// This function is unsafe, as failing to fix the parameters properly would yield incorrect
    /// and insecure computation. Unless you are a cryptographer who really knows the impact of each
    /// of those parameters, you __must__ stick with the provided parameters [`DEFAULT_PARAMETERS`]
    /// and [`TFHE_LIB_PARAMETERS`], which both offer correct results with 128 bits of security.
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn new_insecure(
        lwe_dimension: LweDimension,
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
        lwe_modular_std_dev: StandardDev,
        glwe_modular_std_dev: StandardDev,
        pbs_base_log: DecompositionBaseLog,
        pbs_level: DecompositionLevelCount,
        ks_base_log: DecompositionBaseLog,
        ks_level: DecompositionLevelCount,
    ) -> BooleanParameters {
        BooleanParameters {
            lwe_dimension,
            glwe_dimension,
            polynomial_size,
            lwe_modular_std_dev,
            glwe_modular_std_dev,
            pbs_base_log,
            pbs_level,
            ks_level,
            ks_base_log,
        }
    }
}


#[derive(Clone, Debug)]
pub enum Ciphertext {
    Encrypted(LweCiphertext32),
    Trivial(bool),
}

#[derive(Serialize, Deserialize)]
enum SerializableCiphertext {
    Encrypted(Vec<u8>),
    Trivial(bool),
}

impl Serialize for Ciphertext {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut ser_eng = DefaultSerializationEngine::new(()).map_err(serde::ser::Error::custom)?;

        match self {
            Ciphertext::Encrypted(lwe) => {
                let ciphertext = ser_eng.serialize(lwe).map_err(serde::ser::Error::custom)?;
                SerializableCiphertext::Encrypted(ciphertext)
            }
            Ciphertext::Trivial(b) => SerializableCiphertext::Trivial(*b),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Ciphertext {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let thing = SerializableCiphertext::deserialize(deserializer)?;

        let mut de_eng = DefaultSerializationEngine::new(()).map_err(serde::de::Error::custom)?;

        Ok(match thing {
            SerializableCiphertext::Encrypted(data) => {
                let lwe = de_eng
                    .deserialize(data.as_slice())
                    .map_err(serde::de::Error::custom)?;
                Self::Encrypted(lwe)
            }
            SerializableCiphertext::Trivial(b) => Self::Trivial(b),
        })
    }
}




/// A set of cryptographic parameters for homomorphic Boolean circuit evaluation.


/// Default parameter set.
///
/// This parameter set ensures 128-bits of security, and a probability of error is upper-bounded by
/// $2^{-25}$. The secret keys generated with this parameter set are uniform binary.
/// This parameter set allows to evaluate faster Boolean circuits than the `TFHE_LIB_PARAMETERS`
/// one.
pub const DEFAULT_PARAMETERS: BooleanParameters = BooleanParameters {
   lwe_dimension: LweDimension(586),
   glwe_dimension: GlweDimension(2),
   polynomial_size: PolynomialSize(512),
   lwe_modular_std_dev: StandardDev(0.000_092_511_997_467_675_6), // 2^{-13.4}
   glwe_modular_std_dev: StandardDev(0.000_000_034_233_878_701_836_9), // 2^{-24.8}
   pbs_base_log: DecompositionBaseLog(8),
   pbs_level: DecompositionLevelCount(2),
   ks_base_log: DecompositionBaseLog(2),
   ks_level: DecompositionLevelCount(5),
};

/// Parameter set used in [TFHE library](https://tfhe.github.io/tfhe/) for 128-bits of security.
///
/// Details about this set are provided
/// [here](https://github.com/tfhe/tfhe/blob/master/src/libtfhe/tfhe_gate_bootstrapping.cpp).
/// The secret keys generated with this parameter set are uniform binary.
/// This parameter set ensures a probability of error is upper-bounded by $2^{-165}$.
pub const TFHE_LIB_PARAMETERS: BooleanParameters = BooleanParameters {
   lwe_dimension: LweDimension(630),
   glwe_dimension: GlweDimension(1),
   polynomial_size: PolynomialSize(1024),
   lwe_modular_std_dev: StandardDev(0.000_043_158_372_875_155_5), // 2^{-14.5}
   glwe_modular_std_dev: StandardDev(0.000_000_034_233_878_701_836_9), // 2^{-24.8}
   pbs_base_log: DecompositionBaseLog(7),
   pbs_level: DecompositionLevelCount(3),
   ks_base_log: DecompositionBaseLog(2),
   ks_level: DecompositionLevelCount(8),
};


#[derive(Clone)]
pub struct ClientKey {
    pub(crate) lwe_secret_key: LweSecretKey32,
    pub(crate) glwe_secret_key: GlweSecretKey32,
    pub(crate) parameters: BooleanParameters,
}

#[derive(Clone)]
pub struct ServerKey {
    cpu_key: CpuBootstrapKey,
}



use crate::engine::CpuBootstrapKey;
use crate::engine::{BinaryGatesEngine, CpuBooleanEngine, WithThreadLocalEngine};


pub trait BinaryBooleanGates<L, R> {
    fn and(&self, ct_left: L, ct_right: R) -> Ciphertext;
    fn nand(&self, ct_left: L, ct_right: R) -> Ciphertext;
    fn nor(&self, ct_left: L, ct_right: R) -> Ciphertext;
    fn or(&self, ct_left: L, ct_right: R) -> Ciphertext;
    fn xor(&self, ct_left: L, ct_right: R) -> Ciphertext;
    fn xnor(&self, ct_left: L, ct_right: R) -> Ciphertext;
}

trait RefFromServerKey {
    fn get_ref(server_key: &ServerKey) -> &Self;
}

trait DefaultImplementation {
    type Engine: WithThreadLocalEngine;
    type BootsrapKey: RefFromServerKey;
}


mod implementation {
    use super::*;

    impl RefFromServerKey for CpuBootstrapKey {
        fn get_ref(server_key: &ServerKey) -> &Self {
            &server_key.cpu_key
        }
    }

    impl DefaultImplementation for ServerKey {
        type Engine = CpuBooleanEngine;
        type BootsrapKey = CpuBootstrapKey;
    }
}



impl<Lhs, Rhs> BinaryBooleanGates<Lhs, Rhs> for ServerKey
where
    <ServerKey as DefaultImplementation>::Engine:
        BinaryGatesEngine<Lhs, Rhs, <ServerKey as DefaultImplementation>::BootsrapKey>,
{
    fn and(&self, ct_left: Lhs, ct_right: Rhs) -> Ciphertext {
        let bootstrap_key = <ServerKey as DefaultImplementation>::BootsrapKey::get_ref(self);
        <ServerKey as DefaultImplementation>::Engine::with_thread_local_mut(|engine| {
            engine.and(ct_left, ct_right, bootstrap_key)
        })
    }

    fn nand(&self, ct_left: Lhs, ct_right: Rhs) -> Ciphertext {
        let bootstrap_key = <ServerKey as DefaultImplementation>::BootsrapKey::get_ref(self);
        <ServerKey as DefaultImplementation>::Engine::with_thread_local_mut(|engine| {
            engine.nand(ct_left, ct_right, bootstrap_key)
        })
    }

    fn nor(&self, ct_left: Lhs, ct_right: Rhs) -> Ciphertext {
        let bootstrap_key = <ServerKey as DefaultImplementation>::BootsrapKey::get_ref(self);
        <ServerKey as DefaultImplementation>::Engine::with_thread_local_mut(|engine| {
            engine.nor(ct_left, ct_right, bootstrap_key)
        })
    }

    fn or(&self, ct_left: Lhs, ct_right: Rhs) -> Ciphertext {
        let bootstrap_key = <ServerKey as DefaultImplementation>::BootsrapKey::get_ref(self);
        <ServerKey as DefaultImplementation>::Engine::with_thread_local_mut(|engine| {
            engine.or(ct_left, ct_right, bootstrap_key)
        })
    }

    fn xor(&self, ct_left: Lhs, ct_right: Rhs) -> Ciphertext {
        let bootstrap_key = <ServerKey as DefaultImplementation>::BootsrapKey::get_ref(self);
        <ServerKey as DefaultImplementation>::Engine::with_thread_local_mut(|engine| {
            engine.xor(ct_left, ct_right, bootstrap_key)
        })
    }

    fn xnor(&self, ct_left: Lhs, ct_right: Rhs) -> Ciphertext {
        let bootstrap_key = <ServerKey as DefaultImplementation>::BootsrapKey::get_ref(self);
        <ServerKey as DefaultImplementation>::Engine::with_thread_local_mut(|engine| {
            engine.xnor(ct_left, ct_right, bootstrap_key)
        })
    }

}

impl ServerKey {
    pub fn new(cks: &ClientKey) -> Self {
        let cpu_key =
            CpuBooleanEngine::with_thread_local_mut(|engine| engine.create_server_key(cks));

        Self::from(cpu_key)
    }

    pub fn trivial_encrypt(&self, message: bool) -> Ciphertext {
        Ciphertext::Trivial(message)
    }

    pub fn not(&self, ct: &Ciphertext) -> Ciphertext {
        CpuBooleanEngine::with_thread_local_mut(|engine| engine.not(ct))
    }

    pub fn mux(
        &self,
        ct_condition: &Ciphertext,
        ct_then: &Ciphertext,
        ct_else: &Ciphertext,
    ) -> Ciphertext {
        {
            CpuBooleanEngine::with_thread_local_mut(|engine| {
                engine.mux(ct_condition, ct_then, ct_else, &self.cpu_key)
            })
        }
    }
}

impl From<CpuBootstrapKey> for ServerKey {
    fn from(cpu_key: CpuBootstrapKey) -> Self {
        {
            Self { cpu_key }
        }
    }
}


/////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////




/////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////



/// A structure containing the client key, which must be kept secret.
///
/// In more details, it contains:
/// * `lwe_secret_key` - an LWE secret key, used to encrypt the inputs and decrypt the outputs.
/// This secret key is also used in the generation of bootstrapping and key switching keys.
/// * `glwe_secret_key` - a GLWE secret key, used to generate the bootstrapping keys and key
/// switching keys.
/// * `parameters` - the cryptographic parameter set.



impl PartialEq for ClientKey {
    fn eq(&self, other: &Self) -> bool {
        self.parameters == other.parameters
            && self.lwe_secret_key == other.lwe_secret_key
            && self.glwe_secret_key == other.glwe_secret_key
    }
}

impl Debug for ClientKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "ClientKey {{ ")?;
        write!(f, "lwe_secret_key: {:?}, ", self.lwe_secret_key)?;
        write!(f, "glwe_secret_key: {:?}, ", self.glwe_secret_key)?;
        write!(f, "parameters: {:?}, ", self.parameters)?;
        write!(f, "engine: CoreEngine, ")?;
        write!(f, "}}")?;
        Ok(())
    }
}

impl ClientKey {
    /// Encrypts a Boolean message using the client key.
    ///
    /// # Example
    ///
    /// ```rust
    /// # #[cfg(not(feature = "cuda"))]
    /// # fn main() {
    /// use concrete_boolean::prelude::*;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, mut sks) = gen_keys();
    ///
    /// // Encryption of one message:
    /// let ct = cks.encrypt(true);
    ///
    /// // Decryption:
    /// let dec = cks.decrypt(&ct);
    /// assert_eq!(true, dec);
    /// # }
    /// # #[cfg(feature = "cuda")]
    /// # fn main() {}
    /// ```
    pub fn encrypt(&self, message: bool) -> Ciphertext {
        CpuBooleanEngine::with_thread_local_mut(|engine| engine.encrypt(message, self))
    }

    /// Decrypts a ciphertext encrypting a Boolean message using the client key.
    ///
    /// # Example
    ///
    /// ```rust
    /// # #[cfg(not(feature = "cuda"))]
    /// # fn main() {
    /// use concrete_boolean::prelude::*;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, mut sks) = gen_keys();
    ///
    /// // Encryption of one message:
    /// let ct = cks.encrypt(true);
    ///
    /// // Decryption:
    /// let dec = cks.decrypt(&ct);
    /// assert_eq!(true, dec);
    /// # }
    /// # #[cfg(feature = "cuda")]
    /// # fn main() {}
    /// ```
    pub fn decrypt(&self, ct: &Ciphertext) -> bool {
        CpuBooleanEngine::with_thread_local_mut(|engine| engine.decrypt(ct, self))
    }

    /// Allocates and generates a client key.
    ///
    /// # Panic
    ///
    /// This will panic when the "cuda" feature is enabled and the parameters
    /// uses a GlweDimension > 1 (as it is not yet supported by the cuda backend).
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_boolean::client_key::ClientKey;
    /// use concrete_boolean::parameters::TFHE_LIB_PARAMETERS;
    /// use concrete_boolean::prelude::*;
    ///
    /// // Generate the client key:
    /// let cks = ClientKey::new(&TFHE_LIB_PARAMETERS);
    /// ```
    pub fn new(parameter_set: &BooleanParameters) -> ClientKey {

        CpuBooleanEngine::with_thread_local_mut(|engine| engine.create_client_key(*parameter_set))
    }
}

#[derive(Serialize, Deserialize)]
struct SerializableClientKey {
    lwe_secret_key: Vec<u8>,
    glwe_secret_key: Vec<u8>,
    parameters: BooleanParameters,
}


impl Serialize for ClientKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut ser_eng = DefaultSerializationEngine::new(()).map_err(serde::ser::Error::custom)?;

        let lwe_secret_key = ser_eng
            .serialize(&self.lwe_secret_key)
            .map_err(serde::ser::Error::custom)?;
        let glwe_secret_key = ser_eng
            .serialize(&self.glwe_secret_key)
            .map_err(serde::ser::Error::custom)?;

        SerializableClientKey {
            lwe_secret_key,
            glwe_secret_key,
            parameters: self.parameters,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ClientKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let thing =
            SerializableClientKey::deserialize(deserializer).map_err(serde::de::Error::custom)?;
        let mut de_eng = DefaultSerializationEngine::new(()).map_err(serde::de::Error::custom)?;

        Ok(Self {
            lwe_secret_key: de_eng
                .deserialize(thing.lwe_secret_key.as_slice())
                .map_err(serde::de::Error::custom)?,
            glwe_secret_key: de_eng
                .deserialize(thing.glwe_secret_key.as_slice())
                .map_err(serde::de::Error::custom)?,
            parameters: thing.parameters,
        })
    }
}

/////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////




/////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////

pub mod engine;


/// The scaling factor used for the plaintext
pub(crate) const PLAINTEXT_LOG_SCALING_FACTOR: usize = 3;

/// The plaintext associated with true: 1/8
pub(crate) const PLAINTEXT_TRUE: u32 = 1 << (32 - PLAINTEXT_LOG_SCALING_FACTOR);

/// The plaintext associated with false: -1/8
pub(crate) const PLAINTEXT_FALSE: u32 = 7 << (32 - PLAINTEXT_LOG_SCALING_FACTOR);

/// tool to generate random booleans
// #[cfg(test)]
// pub(crate) fn random_boolean() -> bool {
//     // create a random generator
//     let mut rng = rand::thread_rng();

//     // generate a random bit
//     let n: u32 = (rng.gen::<u32>()) % 2;

//     // convert it to boolean and return
//     n != 0
// }

// /// tool to generate random integers
// #[cfg(test)]
// pub(crate) fn random_integer() -> u32 {
//     // create a random generator
//     let mut rng = rand::thread_rng();

//     // generate a random u32
//     rng.gen::<u32>()
// }

pub fn gen_keys() -> (ClientKey, ServerKey) {
    // generate the client key
    let cks = ClientKey::new(&DEFAULT_PARAMETERS);

    // generate the server key
    let sks = ServerKey::new(&cks);

    // return
    (cks, sks)
}

/////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////




fn main() {
   // We generate a set of client/server keys, using the default parameters:
   println!("Generating keys...");

   let (client_key, server_key) = gen_keys();

   // We use the client secret key to encrypt two messages:
   println!("Encrypting messages...");
   let ct_1 = client_key.encrypt(true);
   let ct_2 = client_key.encrypt(false);

   // We use the server public key to execute a boolean circuit:
   // if ((NOT ct_2) NAND (ct_1 AND ct_2)) then (NOT ct_2) else (ct_1 AND ct_2)
   println!("Executing circuit...");
   let ct_3 = server_key.not(&ct_2);
   let ct_4 = server_key.and(&ct_1, &ct_2);
   let ct_5 = server_key.nand(&ct_3, &ct_4);
   let ct_6 = server_key.mux(&ct_5, &ct_3, &ct_4);

   // We use the client key to decrypt the output of the circuit:
   println!("Decrypting output...");
   let output = client_key.decrypt(&ct_6);
   
   assert_eq!(output, true)
}
