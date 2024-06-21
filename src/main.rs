use std::{fmt, str::FromStr};

use argon2::Argon2;
use derive_builder::Builder;
use derive_getters::Getters;

use derive_new::new;
use rand::{rngs::OsRng, Rng};
use strum::{EnumProperty, IntoEnumIterator};
use strum_macros::{Display, EnumIter, EnumProperty};
use thiserror::Error;

#[derive(Debug, Display, Clone, PartialEq, Eq, EnumIter, EnumProperty)]
pub enum Language {
    #[strum(props(lang = "en"))]
    English,
    #[strum(props(lang = "zh"))]
    Chinese,
    #[strum(props(lang = "es"))]
    Spanish,
    #[strum(props(lang = "fr"))]
    French,
    #[strum(props(lang = "de"))]
    German,
    #[strum(props(lang = "ja"))]
    Japanese,
    #[strum(props(lang = "pt"))]
    Portuguese,
    #[strum(props(lang = "ru"))]
    Russian,
    #[strum(props(lang = "ar"))]
    Arabic,
    #[strum(props(lang = "ko"))]
    Korean,
}

#[derive(Debug, Error)]
pub enum ApplicationError {
    #[error("Language Not Found")]
    LanguageNotFound,
    #[error("Password Hashing Failed: {0}")]
    PasswordHash(String),
}

impl FromStr for Language {
    type Err = ApplicationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::iter()
            .find(|l| l.get_str("lang") == Some(s))
            .ok_or(Self::Err::LanguageNotFound)
    }
}

#[derive(Clone)]
struct Password {
    salt: [u8; 16],
    hash: [u8; 32],
}

#[derive(Clone, Default, new)]
struct PasswordCypher<'a> {
    argon: Argon2<'a>,
}

impl<'a> PasswordCypher<'a> {
    pub fn encode(&self, raw_text: &str) -> Result<Password, ApplicationError> {
        let mut salt = [0; 16];
        let mut hash = [0; 32];
        OsRng::fill(&mut OsRng, &mut salt);
        self.argon
            .hash_password_into(raw_text.as_bytes(), &salt, &mut hash)
            .map_err(|e| ApplicationError::PasswordHash(e.to_string()))?;
        Ok(Password { salt, hash })
    }

    pub fn try_password(
        &self,
        password: &Password,
        raw_text: &str,
    ) -> Result<bool, ApplicationError> {
        let argon = Argon2::default();
        let mut hash = [0; 32];
        argon
            .hash_password_into(raw_text.as_bytes(), &password.salt, &mut hash)
            .map_err(|e| ApplicationError::PasswordHash(e.to_string()))?;
        Ok(password.hash == hash)
    }
}

impl fmt::Debug for Password {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Let's keep the password a secret
        f.debug_struct("Password").finish()
    }
}

#[derive(Debug, Clone, Getters, Builder)]
struct User {
    id: i64,
    username: String,
    email: String,
    // Lets keep the password a secret
    #[getter(skip)]
    password: Password,
    language: Language,
}

impl PartialEq for User {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl User {
    pub fn try_password_with(
        &self,
        cypher: &PasswordCypher,
        raw_password: &str,
    ) -> Result<bool, ApplicationError> {
        cypher.try_password(&self.password, raw_password)
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cypher = PasswordCypher::default();
    let user = UserBuilder::default()
        .id(1)
        .username("someuser100".into())
        .email("someuser100@protomail.com".into())
        .password(cypher.encode("123")?)
        .language("en".parse()?)
        .build()?;
    println!(
        "User id {}, username {}, email {}, language {}",
        user.id(),
        user.username(),
        user.email(),
        user.language(),
    );
    println!(
        "Does the password 1234 work? {}",
        if user.try_password_with(&cypher, "1234")? {
            "yes"
        } else {
            "no"
        }
    );
    println!(
        "Does the password 123 work? {}",
        if user.try_password_with(&cypher, "123")? {
            "yes"
        } else {
            "no"
        }
    );
    // Okay let's peak into the password-- for science!
    // We can do this since everything is in the same module
    // granting access to private properties
    // do not do this in production!
    let p = cypher.encode("123")?;
    println!("The salt is:\n{:#?}\nThe hash is:\n{:#?}", p.salt, p.hash);
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_password_cypher_encode() -> Result<(), ApplicationError> {
        let cypher = PasswordCypher::default();
        let password = cypher.encode("123")?;
        assert!(!password.salt.iter().all(|b| *b == 0u8));
        assert!(!password.hash.iter().all(|b| *b == 0u8));
        assert_ne!(password.hash, "123".as_bytes());
        Ok(())
    }

    #[test]
    fn test_password_cypher_try_password() -> Result<(), ApplicationError> {
        let cypher = PasswordCypher::default();
        let password = cypher.encode("123")?;
        assert!(cypher.try_password(&password, "123")?);
        assert!(!cypher.try_password(&password, "1234")?);
        Ok(())
    }

    #[test]
    fn test_user_try_password_with() -> Result<(), Box<dyn std::error::Error>> {
        let cypher = PasswordCypher::default();
        let user = UserBuilder::default()
            .id(1)
            .username("someuser100".into())
            .email("someuser100@protomail.com".into())
            .password(cypher.encode("123")?)
            .language("en".parse()?)
            .build()?;
        assert!(user.try_password_with(&cypher, "123")?);
        assert!(!user.try_password_with(&cypher, "1234")?);
        Ok(())
    }
}
