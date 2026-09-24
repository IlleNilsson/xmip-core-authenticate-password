#![forbid(unsafe_code)]

//! Authenticate by password: a username and a password against the
//! capability's store of salted verifiers.
//!
//! The mechanism is `password` (ADR-0050 section 4): a username and password
//! over a protected channel — an FTPS `USER` and `PASS`, SASL PLAIN, a SQL
//! login. The first gate reads the name and calls it a `username` claim,
//! with the password riding on `Presented::proof` under the name `password`
//! and never on the record. This gate takes that claim, or one already named
//! `password`, and asks the store. The store is the capability's
//! `authenticate::store::CredentialStore`, so that `basic`, `digest` and
//! `scram` verify against the same enrolments without any of them depending
//! on this crate (ADR-0044).
//!
//! Proven, or refused with the reason: no proof, another mechanism's claim,
//! or a credential the store does not hold — the last without saying whether
//! it was the name or the password that was wrong.

use authenticate::store::CredentialStore;
use authenticate::{AuthenticateError, Authenticator};
use context::Verified;
use identify::Presented;
use identify::evidence::{self, PASSWORD};
use xcore::{Mechanism, mechanism};

/// Verifies a `username` claim with a `password` proof against a store.
pub struct PasswordAuthenticator {
    store: CredentialStore,
}

impl PasswordAuthenticator {
    #[must_use]
    pub fn new(store: CredentialStore) -> Self {
        Self { store }
    }

    /// The enrolments this verifies against.
    #[must_use]
    pub fn store(&self) -> &CredentialStore {
        &self.store
    }
}

/// Whether a claim is one this verifier reads: a bare `username`, or one
/// the first gate already filed under `password`.
fn reads(mechanism: &Mechanism) -> bool {
    let name = mechanism.name();
    name == "username" || name == "password"
}

impl Authenticator for PasswordAuthenticator {
    fn mechanism(&self) -> Mechanism {
        mechanism::password()
    }

    fn verify(&self, presented: &Presented) -> Result<Verified, AuthenticateError> {
        if !reads(&presented.mechanism) {
            return Err(AuthenticateError::new(format!(
                "'{}' is not a claim the password verifier reads: it takes a username",
                presented.mechanism.name()
            )));
        }
        let password = presented.proof(evidence::PASSWORD).ok_or_else(|| {
            AuthenticateError::new(format!(
                "no '{PASSWORD}' proof was presented with the username '{}'",
                presented.value
            ))
        })?;
        if presented.value.is_empty() {
            return Err(AuthenticateError::new("the username presented is empty"));
        }
        if self.store.verify(&presented.value, password) {
            Ok(Verified::Proven)
        } else {
            Ok(Verified::Refused)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use authenticate::{Acceptance, PartyRegistry, Refusal, authenticate};
    use xcore::{PartyId, Purpose};

    fn verifier() -> PasswordAuthenticator {
        PasswordAuthenticator::new(CredentialStore::from_entries(
            4096,
            [("alice", "pencil"), ("bob", "correct horse")],
        ))
    }

    fn claim(username: &str, password: &str) -> Presented {
        Presented::passed(mechanism::username(), username).with_proof(evidence::PASSWORD, password)
    }

    #[test]
    fn the_right_password_proves_the_username() {
        assert_eq!(
            verifier()
                .verify(&claim("alice", "pencil"))
                .expect("verified"),
            Verified::Proven
        );
        // A claim the first gate already filed under this mechanism reads too.
        let filed = Presented::passed(mechanism::password(), "bob")
            .with_proof(evidence::PASSWORD, "correct horse");
        assert_eq!(
            verifier().verify(&filed).expect("verified"),
            Verified::Proven
        );
    }

    #[test]
    fn a_wrong_password_and_an_unknown_name_are_refused_alike() {
        let verifier = verifier();
        assert_eq!(
            verifier.verify(&claim("alice", "pen")).expect("verified"),
            Verified::Refused
        );
        assert_eq!(
            verifier
                .verify(&claim("mallory", "pencil"))
                .expect("verified"),
            Verified::Refused
        );
    }

    #[test]
    fn a_username_without_a_password_proof_is_refused_by_name() {
        let bare = Presented::passed(mechanism::username(), "alice");
        let failure = verifier().verify(&bare).expect_err("refused");
        assert!(
            failure.message.contains("'password' proof"),
            "{}",
            failure.message
        );
    }

    #[test]
    fn another_mechanisms_claim_is_not_this_verifiers() {
        let key = Presented::passed(mechanism::api_key(), "k-1").with_proof("api-key", "secret");
        let failure = verifier().verify(&key).expect_err("refused");
        assert!(failure.message.contains("'api-key'"), "{}", failure.message);
    }

    #[test]
    fn the_password_never_reaches_the_record() {
        // Debug prints proof names only; the value on the record is the name.
        let presented = claim("alice", "pencil");
        let printed = format!("{presented:?}");
        assert!(printed.contains("password"));
        assert!(!printed.contains("pencil"));
        assert_eq!(presented.value, "alice");
    }

    struct Registry;

    impl PartyRegistry for Registry {
        fn resolve(&self, mechanism: &str, _purpose: Purpose, value: &str) -> Option<PartyId> {
            (mechanism == "password" && value == "alice").then(|| PartyId::new(7))
        }
    }

    #[test]
    fn through_the_gate_a_proven_password_resolves_to_its_party() {
        let verifier = verifier();
        let acceptance = Acceptance::closed().accepting(&mechanism::password());
        let filed = Presented::passed(mechanism::password(), "alice")
            .with_proof(evidence::PASSWORD, "pencil");
        let identity =
            authenticate(&acceptance, &[&verifier], &Registry, &filed).expect("accepted");
        assert_eq!(identity.party_id, Some(PartyId::new(7)));
        assert_eq!(identity.verified, Verified::Proven);
        assert!(identity.evidence.is_empty());

        let wrong =
            Presented::passed(mechanism::password(), "alice").with_proof(evidence::PASSWORD, "pen");
        assert_eq!(
            authenticate(&acceptance, &[&verifier], &Registry, &wrong).expect_err("refused"),
            Refusal::NotProven {
                mechanism: "password".to_string(),
                detail: "the claim did not hold".to_string()
            }
        );
    }
}
