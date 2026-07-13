// SPDX-License-Identifier: Apache-2.0

use std::{fmt, str::FromStr};

use serde::{de, Deserialize, Deserializer, Serialize};

use crate::ContractError;

const MAX_IDENTIFIER_BYTES: usize = 128;

fn validate_identifier(value: &str, field: &'static str) -> Result<(), ContractError> {
    if value.is_empty() {
        return Err(ContractError::InvalidIdentifier {
            field,
            reason: "must not be empty",
        });
    }
    if value.len() > MAX_IDENTIFIER_BYTES {
        return Err(ContractError::InvalidIdentifier {
            field,
            reason: "must be at most 128 bytes",
        });
    }
    if value == "." || value == ".." {
        return Err(ContractError::InvalidIdentifier {
            field,
            reason: "must not be a path segment",
        });
    }
    let Some(first) = value.chars().next() else {
        return Err(ContractError::InvalidIdentifier {
            field,
            reason: "must not be empty",
        });
    };
    let Some(last) = value.chars().next_back() else {
        return Err(ContractError::InvalidIdentifier {
            field,
            reason: "must not be empty",
        });
    };
    if !first.is_ascii_alphanumeric() || !last.is_ascii_alphanumeric() {
        return Err(ContractError::InvalidIdentifier {
            field,
            reason: "must begin and end with an ASCII letter or digit",
        });
    }
    if !value
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || "._:-".contains(character))
    {
        return Err(ContractError::InvalidIdentifier {
            field,
            reason: "contains characters outside [A-Za-z0-9._:-]",
        });
    }
    Ok(())
}

pub(crate) fn validate_reference(value: &str, field: &'static str) -> Result<(), ContractError> {
    if value.is_empty() {
        return Err(ContractError::InvalidField {
            field,
            reason: "must not be empty",
        });
    }
    if value.len() > 512 {
        return Err(ContractError::InvalidField {
            field,
            reason: "must be at most 512 bytes",
        });
    }
    if value.chars().any(char::is_control) {
        return Err(ContractError::InvalidField {
            field,
            reason: "must not contain control characters",
        });
    }
    Ok(())
}

macro_rules! identifier_type {
    ($name:ident, $field:literal, $docs:literal) => {
        #[doc = $docs]
        #[derive(
            schemars::JsonSchema, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
        )]
        #[serde(transparent)]
        pub struct $name(
            #[schemars(
                length(min = 1, max = 128),
                regex(pattern = r"^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$")
            )]
            String,
        );

        impl $name {
            /// Borrow the opaque identifier value.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<&str> for $name {
            type Error = ContractError;

            fn try_from(value: &str) -> Result<Self, Self::Error> {
                validate_identifier(value, $field)?;
                Ok(Self(value.to_string()))
            }
        }

        impl TryFrom<String> for $name {
            type Error = ContractError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                validate_identifier(&value, $field)?;
                Ok(Self(value))
            }
        }

        impl FromStr for $name {
            type Err = ContractError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::try_from(value)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::try_from(value).map_err(de::Error::custom)
            }
        }
    };
}

identifier_type!(
    OrganizationId,
    "organization_id",
    "An organization-scoped opaque identifier."
);
identifier_type!(
    RunId,
    "run_id",
    "An organization-scoped Agent Run identifier."
);
identifier_type!(
    SourceId,
    "source_id",
    "A registered Evidence Source identifier."
);

pub(crate) fn validate_contract_identifier(
    value: &str,
    field: &'static str,
) -> Result<(), ContractError> {
    validate_identifier(value, field)
}
