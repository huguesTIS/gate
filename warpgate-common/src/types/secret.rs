use std::borrow::Cow;
use std::fmt::Debug;

use bytes::Bytes;
use data_encoding::HEXLOWER;
use delegate::delegate;
use poem_openapi::registry::{MetaSchemaRef, Registry};
use poem_openapi::types::{ParseError, ParseFromJSON, ToJSON};
use rand::RngExt;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::helpers::rng::get_crypto_rng;

/// `T: Zeroize` is a bound on the struct itself, not just on `Drop` below —
/// Rust requires a `Drop` impl's generic parameters and bounds to match the
/// struct's exactly (E0366/E0367: neither a narrower concrete type nor an extra
/// bound on just the `Drop` impl is allowed). The two concrete instantiations
/// actually used in this codebase (`Secret<String>`, `Secret<Vec<u8>>` via
/// `OtpSecretKey`) both satisfy it; a new `Secret<SomeType>` would need
/// `SomeType: Zeroize` too.
#[derive(PartialEq, Eq, Clone)]
pub struct Secret<T: Zeroize>(T);

/// Zeroes the plaintext on drop. Narrows, but does not close, the window in which
/// a process with live memory access (core dump, ptrace) could recover a secret
/// after use — it cannot protect a secret being actively used at the moment of
/// capture, which is a limit of any proxy that must hold plaintext to authenticate
/// with a target, not something fixable at this layer.
impl<T: Zeroize> Drop for Secret<T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Secret<String> {
    pub fn random() -> Self {
        Self::new(HEXLOWER.encode(&Bytes::from_iter(get_crypto_rng().random::<[u8; 32]>())))
    }
}

impl<T: Zeroize> Secret<T> {
    pub const fn new(v: T) -> Self {
        Self(v)
    }

    pub const fn expose_secret(&self) -> &T {
        &self.0
    }
}

impl<T: Zeroize> From<T> for Secret<T> {
    fn from(v: T) -> Self {
        Self::new(v)
    }
}

impl<'de, T: Zeroize> Deserialize<'de> for Secret<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let v = Deserialize::deserialize::<D>(deserializer)?;
        Ok(Self::new(v))
    }
}

impl<T: Zeroize> Serialize for Secret<T>
where
    T: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<T: Zeroize> Debug for Secret<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<secret>")
    }
}

impl<T: Zeroize + poem_openapi::types::Type> poem_openapi::types::Type for Secret<T> {
    const IS_REQUIRED: bool = T::IS_REQUIRED;
    type RawValueType = T::RawValueType;
    type RawElementValueType = T::RawElementValueType;

    fn name() -> Cow<'static, str> {
        T::name()
    }
    fn schema_ref() -> MetaSchemaRef {
        T::schema_ref()
    }
    fn register(registry: &mut Registry) {
        T::register(registry);
    }

    delegate! {
        to self.0 {
            fn as_raw_value(&self) -> Option<&Self::RawValueType>;
            fn raw_element_iter(
                &'_ self,
            ) -> Box<dyn Iterator<Item = &'_ Self::RawElementValueType> + '_>;
            fn is_empty(&self) -> bool;
            fn is_none(&self) -> bool;
        }
    }
}

impl<T: Zeroize + ParseFromJSON> ParseFromJSON for Secret<T> {
    fn parse_from_json(value: Option<serde_json::Value>) -> poem_openapi::types::ParseResult<Self> {
        T::parse_from_json(value)
            .map(Self::new)
            .map_err(|e| ParseError::custom(e.into_message()))
    }
}

impl<T: Zeroize + ToJSON> ToJSON for Secret<T> {
    fn to_json(&self) -> Option<serde_json::Value> {
        self.0.to_json()
    }
}
