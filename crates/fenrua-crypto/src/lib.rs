//! Signing-profile discovery for the R1 foundation and R2 local prototype.
//!
//! This crate contains no signing, verification, private-key, provider, or
//! network implementation. It makes profile names explicit so callers cannot
//! silently substitute an unknown or downgraded profile while the real profile
//! contracts remain unreleased.

use fenrua_protocol::{Problem, ProblemCode};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SigningProfile {
    LocalUnsignedDevelopment,
    Ed25519V1,
    P256V1,
    EnterpriseProviderV1,
}

impl SigningProfile {
    pub const fn id(self) -> &'static str {
        match self {
            Self::LocalUnsignedDevelopment => "local-unsigned-development",
            Self::Ed25519V1 => "ed25519-v1",
            Self::P256V1 => "p256-v1",
            Self::EnterpriseProviderV1 => "enterprise-provider-v1",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProfileStatus {
    ReservedUnreleased,
}

impl ProfileStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReservedUnreleased => "reserved-unreleased",
        }
    }

    pub const fn permits_cryptographic_operations(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProfileDescriptor {
    profile: SigningProfile,
    status: ProfileStatus,
}

impl ProfileDescriptor {
    pub const fn profile(self) -> SigningProfile {
        self.profile
    }

    pub const fn status(self) -> ProfileStatus {
        self.status
    }
}

const PROFILES: [ProfileDescriptor; 4] = [
    ProfileDescriptor {
        profile: SigningProfile::LocalUnsignedDevelopment,
        status: ProfileStatus::ReservedUnreleased,
    },
    ProfileDescriptor {
        profile: SigningProfile::Ed25519V1,
        status: ProfileStatus::ReservedUnreleased,
    },
    ProfileDescriptor {
        profile: SigningProfile::P256V1,
        status: ProfileStatus::ReservedUnreleased,
    },
    ProfileDescriptor {
        profile: SigningProfile::EnterpriseProviderV1,
        status: ProfileStatus::ReservedUnreleased,
    },
];

pub const fn profile_descriptors() -> &'static [ProfileDescriptor] {
    &PROFILES
}

/// Looks up a known bootstrap profile label. The successful lookup does not
/// grant a cryptographic capability; all profiles remain unreleased.
pub fn lookup_profile(id: &str) -> Result<ProfileDescriptor, Problem> {
    for descriptor in profile_descriptors() {
        if descriptor.profile().id() == id {
            return Ok(*descriptor);
        }
    }
    Err(Problem::new(ProblemCode::UnsupportedProfile))
}

/// Rejects profile use at the R1 boundary rather than pretending that a
/// registry lookup is signature verification.
pub fn require_released_profile(_profile: SigningProfile) -> Result<(), Problem> {
    Err(Problem::new(ProblemCode::FeatureUnavailable))
}

#[cfg(test)]
mod tests {
    use super::{ProfileStatus, SigningProfile, lookup_profile, require_released_profile};
    use fenrua_protocol::ProblemCode;

    #[test]
    fn known_profile_names_are_discoverable_but_not_usable() {
        let profile = match lookup_profile("ed25519-v1") {
            Ok(profile) => profile,
            Err(error) => panic!("known profile must be discoverable: {error}"),
        };
        assert_eq!(profile.status(), ProfileStatus::ReservedUnreleased);
        let error = match require_released_profile(profile.profile()) {
            Ok(()) => panic!("unreleased profile must not become usable"),
            Err(error) => error,
        };
        assert_eq!(error.code(), ProblemCode::FeatureUnavailable);
    }

    #[test]
    fn unknown_profile_cannot_downgrade_to_a_known_one() {
        let error = match lookup_profile("Ed25519") {
            Ok(_) => panic!("aliases must not be accepted"),
            Err(error) => error,
        };
        assert_eq!(error.code(), ProblemCode::UnsupportedProfile);
        assert_eq!(SigningProfile::Ed25519V1.id(), "ed25519-v1");
    }
}
