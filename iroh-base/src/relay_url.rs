use std::{fmt, ops::Deref, str::FromStr, sync::Arc};

use n0_error::{e, stack_error};
use serde::{Deserialize, Serialize};
use url::Url;

/// A URL identifying a relay server.
///
/// It is cheaply clonable, as the underlying type is wrapped into an `Arc`.  The main type
/// under the hood though is [`Url`].
///
/// To create a [`RelayUrl`] use the `From<Url>` implementation.
///
/// It is encouraged to use a fully-qualified DNS domain name in the URL.  Meaning a DNS
/// name which ends in a `.`, e.g, in `relay.example.com.`.  Otherwise the DNS resolution of
/// your local host or network could interpret the DNS name as relative and in some
/// configurations might cause additional delays or even connection problems.
///
/// # Length limit (Xross fork)
///
/// Every string ingress ([`FromStr`] and [`Deserialize`]) rejects relay URLs longer than
/// [`MAX_RELAY_URL_LEN`] bytes, both before parsing and after normalization. The infallible
/// [`From<Url>`] conversion is kept for API compatibility and is meant for locally trusted
/// values; the endpoint checks such values with [`RelayUrl::check_len`] where they enter it.
#[derive(Clone, derive_more::Display, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct RelayUrl(Arc<Url>);

/// Maximum length, in bytes, of a relay URL (Xross fork).
///
/// The limit applies to the raw input before parsing and to the normalized serialization
/// ([`Url::as_str`]) after parsing, since normalization can expand the input (percent
/// encoding, IDNA). 2,048 bytes:
/// - equals the relay-hint admission bound Xross already enforces on application and pairing
///   hints, so no value accepted there is refused here;
/// - is the de-facto URL limit of common HTTP clients and servers, and is far above any real
///   relay URL (a DNS name is at most 253 bytes; the longest relay URL in this repository's
///   tests and defaults is under 64 bytes);
/// - keeps per-path memory small and fixed for every relay URL that reaches the endpoint.
pub const MAX_RELAY_URL_LEN: usize = 2048;

impl From<Url> for RelayUrl {
    fn from(url: Url) -> Self {
        Self(Arc::new(url))
    }
}

/// Can occur when parsing a string into a [`RelayUrl`].
#[stack_error(derive, add_meta)]
#[non_exhaustive]
pub enum RelayUrlParseError {
    /// The input is not a valid URL.
    #[error("Failed to parse relay URL")]
    Parse {
        /// The URL parser error.
        #[error(std_err)]
        source: url::ParseError,
    },
    /// The relay URL is longer than [`MAX_RELAY_URL_LEN`] bytes.
    #[error("Relay URL is {len} bytes, more than the limit of {max} bytes")]
    TooLong {
        /// Length of the refused input or normalized URL, in bytes.
        len: usize,
        /// The limit, [`MAX_RELAY_URL_LEN`].
        max: usize,
    },
}

impl RelayUrl {
    /// Checks that this URL's normalized serialization is at most [`MAX_RELAY_URL_LEN`] bytes.
    ///
    /// [`FromStr`] and [`Deserialize`] already enforce this; use it for values built with the
    /// infallible [`From<Url>`] conversion before they are stored or dialed.
    pub fn check_len(&self) -> Result<(), RelayUrlParseError> {
        check_len(self.0.as_str().len())
    }
}

fn check_len(len: usize) -> Result<(), RelayUrlParseError> {
    if len > MAX_RELAY_URL_LEN {
        return Err(e!(RelayUrlParseError::TooLong {
            len,
            max: MAX_RELAY_URL_LEN
        }));
    }
    Ok(())
}

/// Support for parsing strings directly.
///
/// If you need more control over the error first create a [`Url`] and use [`RelayUrl::from`]
/// instead.
impl FromStr for RelayUrl {
    type Err = RelayUrlParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Refuse overlong input before the parser allocates anything for it.
        check_len(s.len())?;
        let inner = Url::from_str(s).map_err(|source| e!(RelayUrlParseError::Parse { source }))?;
        // Normalization can expand the input (percent encoding, IDNA): check the result too.
        check_len(inner.as_str().len())?;
        Ok(RelayUrl::from(inner))
    }
}

/// Deserializes from a string through [`FromStr`], so the length limit applies before the
/// URL parser runs. The wire format is unchanged: a newtype around the URL string.
impl<'de> Deserialize<'de> for RelayUrl {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct RelayUrlVisitor;

        impl<'de> serde::de::Visitor<'de> for RelayUrlVisitor {
            type Value = RelayUrl;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "a relay URL of at most {MAX_RELAY_URL_LEN} bytes")
            }

            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Self::Value, E> {
                RelayUrl::from_str(s).map_err(E::custom)
            }

            fn visit_newtype_struct<D: serde::Deserializer<'de>>(
                self,
                deserializer: D,
            ) -> Result<Self::Value, D::Error> {
                deserializer.deserialize_str(self)
            }
        }

        deserializer.deserialize_newtype_struct("RelayUrl", RelayUrlVisitor)
    }
}

impl From<RelayUrl> for Url {
    fn from(value: RelayUrl) -> Self {
        Arc::unwrap_or_clone(value.0)
    }
}

/// Dereferences to the wrapped [`Url`].
///
/// Note that [`DerefMut`] is not implemented on purpose, so this type has more flexibility
/// to change the inner later.
///
/// [`DerefMut`]: std::ops::DerefMut
impl Deref for RelayUrl {
    type Target = Url;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Debug for RelayUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("RelayUrl")
            .field(&DbgStr(self.0.as_str()))
            .finish()
    }
}

/// Helper struct to format a &str without allocating a String.
///
/// Maybe this is entirely unneeded and the compiler would be smart enough to never allocate
/// the String anyway.  Who knows.  Writing this was faster than checking the assembler
/// output.
struct DbgStr<'a>(&'a str);

impl fmt::Debug for DbgStr<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, r#""{}""#, self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `https://r.example/` followed by `a`s up to exactly `len` bytes.
    fn url_of_len(len: usize) -> String {
        let prefix = "https://r.example/";
        format!("{prefix}{}", "a".repeat(len - prefix.len()))
    }

    #[test]
    fn relay_url_from_str_enforces_length_limit() {
        let ok = url_of_len(MAX_RELAY_URL_LEN);
        let url: RelayUrl = ok.parse().expect("limit is inclusive");
        assert_eq!(url.as_str().len(), MAX_RELAY_URL_LEN);
        url.check_len().expect("in bound");

        let long = url_of_len(MAX_RELAY_URL_LEN + 1);
        let err = long
            .parse::<RelayUrl>()
            .expect_err("one byte over is refused");
        assert!(
            matches!(err, RelayUrlParseError::TooLong { len, max, .. }
                if len == MAX_RELAY_URL_LEN + 1 && max == MAX_RELAY_URL_LEN),
            "{err:?}"
        );
    }

    #[test]
    fn relay_url_from_str_refuses_raw_overlong_input_before_parsing() {
        // Not a valid URL at all: if the parser ran first, this would be `Parse`.
        let junk = " ".repeat(MAX_RELAY_URL_LEN + 1);
        let err = junk.parse::<RelayUrl>().expect_err("overlong");
        assert!(matches!(err, RelayUrlParseError::TooLong { .. }), "{err:?}");
    }

    #[test]
    fn relay_url_from_str_refuses_normalization_expansion() {
        // 'é' is 2 input bytes and 6 normalized bytes (`%C3%A9`).
        let prefix = "https://r.example/";
        let input = format!("{prefix}{}", "é".repeat(400));
        assert!(input.len() <= MAX_RELAY_URL_LEN);
        let err = input
            .parse::<RelayUrl>()
            .expect_err("normalized form is overlong");
        assert!(
            matches!(err, RelayUrlParseError::TooLong { len, .. } if len > MAX_RELAY_URL_LEN),
            "{err:?}"
        );
    }

    #[test]
    fn relay_url_deserialize_enforces_length_limit() {
        let ok: RelayUrl = url_of_len(MAX_RELAY_URL_LEN).parse().unwrap();
        // Wire format is unchanged (a plain string) in both a text and a binary format.
        let json = serde_json::to_string(&ok).unwrap();
        assert_eq!(serde_json::from_str::<RelayUrl>(&json).unwrap(), ok);
        let bytes = postcard::to_stdvec(&ok).unwrap();
        assert_eq!(postcard::from_bytes::<RelayUrl>(&bytes).unwrap(), ok);

        let long = url_of_len(MAX_RELAY_URL_LEN + 1);
        let json = serde_json::to_string(&long).unwrap();
        assert!(serde_json::from_str::<RelayUrl>(&json).is_err());
        let bytes = postcard::to_stdvec(&long).unwrap();
        assert!(postcard::from_bytes::<RelayUrl>(&bytes).is_err());
        // Nested, as in a ticket or a serialized endpoint address: variant 0 is `Relay`.
        #[cfg(feature = "key")]
        {
            let nested = postcard::to_stdvec(&(0u32, ok.as_str())).unwrap();
            assert!(postcard::from_bytes::<crate::TransportAddr>(&nested).is_ok());
            let nested = postcard::to_stdvec(&(0u32, long.as_str())).unwrap();
            assert!(postcard::from_bytes::<crate::TransportAddr>(&nested).is_err());
        }
    }

    #[test]
    fn relay_url_check_len_catches_from_url() {
        let url = RelayUrl::from(Url::parse(&url_of_len(MAX_RELAY_URL_LEN + 1)).unwrap());
        assert!(matches!(
            url.check_len(),
            Err(RelayUrlParseError::TooLong { .. })
        ));
    }

    #[test]
    fn test_relay_url_debug_display() {
        let url = RelayUrl::from(Url::parse("https://example.com").unwrap());

        assert_eq!(format!("{url:?}"), r#"RelayUrl("https://example.com/")"#);

        assert_eq!(format!("{url}"), "https://example.com/");
    }

    #[test]
    fn test_relay_url_absolute() {
        let url = RelayUrl::from(Url::parse("https://example.com").unwrap());

        assert_eq!(url.domain(), Some("example.com"));

        let url1 = RelayUrl::from(Url::parse("https://example.com.").unwrap());
        assert_eq!(url1.domain(), Some("example.com."));

        let url2 = RelayUrl::from(Url::parse("https://example.com./").unwrap());
        assert_eq!(url2.domain(), Some("example.com."));

        let url3 = RelayUrl::from(Url::parse("https://example.com/").unwrap());
        assert_eq!(url3.domain(), Some("example.com"));
    }
}
