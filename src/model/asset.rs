// Copyright (c) 2026 Certlocker
// SPDX-License-Identifier: GPL-3.0-only

use serde::{Deserialize, Serialize};

/// Fields shared by Trust secrets, certificates, and tokens.
pub trait Asset {
    /// Asset id.
    fn id(&self) -> Option<&str>;
    /// Tenant account id.
    fn account_id(&self) -> Option<&str>;
    /// Display name.
    fn name(&self) -> Option<&str>;
    /// Lifecycle status.
    fn status(&self) -> Option<AssetStatus>;
    /// Who holds the edit lock.
    fn locked_by(&self) -> Option<&str>;

    /// Whether someone currently holds the edit lock.
    fn is_locked(&self) -> bool {
        self.locked_by().is_some_and(|value| !value.is_empty())
    }

    /// Whether the asset status is [`AssetStatus::Active`].
    fn is_active(&self) -> bool {
        self.status().is_some_and(AssetStatus::is_active)
    }
}

/// Lifecycle status of a Trust asset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AssetStatus {
    /// Asset is active and usable.
    Active,
    /// Asset is temporarily suspended.
    Suspended,
    /// Asset has expired.
    Expired,
    /// Asset has been revoked.
    Revoked,
}

impl AssetStatus {
    /// Whether the asset is active.
    pub fn is_active(self) -> bool {
        self == Self::Active
    }

    /// Whether the asset can be suspended.
    pub fn can_suspend(self) -> bool {
        self == Self::Active
    }

    /// Whether the asset can be revoked.
    pub fn can_revoke(self) -> bool {
        self != Self::Revoked
    }

    /// Whether a suspended asset can be resumed.
    pub fn can_resume(self) -> bool {
        self == Self::Suspended
    }

    /// Whether the asset can be renewed.
    pub fn can_renew(self) -> bool {
        self == Self::Active || self == Self::Expired
    }

    /// Whether the asset can be rotated.
    pub fn can_rotate(self) -> bool {
        self == Self::Active || self == Self::Expired
    }
}

/// Kind of asset stored in Trust.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AssetType {
    /// Host / machine asset.
    Host,
    /// Secret asset.
    Secret,
    /// Certificate asset.
    Certificate,
    /// API token asset.
    Token,
    /// Bastion asset.
    Bastion,
    /// Probe asset.
    Probe,
    /// Agent asset.
    Agent,
    /// ACME client asset.
    AcmeClient,
    /// DNS client asset.
    DnsClient,
    /// Automation asset.
    Automation,
    /// Notification / message channel asset.
    Channel,
}

macro_rules! impl_asset {
    ($ty:ty) => {
        impl $ty {
            /// Whether someone currently holds the edit lock.
            pub fn is_locked(&self) -> bool {
                self.locked_by
                    .as_ref()
                    .is_some_and(|value| !value.is_empty())
            }

            /// Whether the asset status is [`AssetStatus::Active`].
            pub fn is_active(&self) -> bool {
                self.status.is_some_and(AssetStatus::is_active)
            }
        }

        impl Asset for $ty {
            fn id(&self) -> Option<&str> {
                self.id.as_deref()
            }

            fn account_id(&self) -> Option<&str> {
                self.account_id.as_deref()
            }

            fn name(&self) -> Option<&str> {
                self.name.as_deref()
            }

            fn status(&self) -> Option<AssetStatus> {
                self.status
            }

            fn locked_by(&self) -> Option<&str> {
                self.locked_by.as_deref()
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_transitions_match_the_java_client() {
        assert!(AssetStatus::Active.is_active());
        assert!(AssetStatus::Active.can_suspend());
        assert!(!AssetStatus::Revoked.can_revoke());
        assert!(AssetStatus::Suspended.can_resume());
        assert!(AssetStatus::Expired.can_renew());
        assert!(AssetStatus::Active.can_rotate());
        assert_eq!(
            serde_json::to_string(&AssetStatus::Active).unwrap(),
            "\"ACTIVE\""
        );
    }
}
