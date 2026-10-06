use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use async_trait::async_trait;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NfsBindingPermission {
    ReadOnly,
    ReadWrite,
}

impl NfsBindingPermission {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "ro",
            Self::ReadWrite => "rw",
        }
    }
}

impl FromStr for NfsBindingPermission {
    type Err = NfsBindingParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "ro" => Ok(Self::ReadOnly),
            "rw" => Ok(Self::ReadWrite),
            _ => Err(NfsBindingParseError::Invalid),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NfsCidr {
    V4 { network: u32, prefix: u8 },
    V6 { network: u128, prefix: u8 },
}

impl NfsCidr {
    pub const fn prefix_len(self) -> u8 {
        match self {
            Self::V4 { prefix, .. } | Self::V6 { prefix, .. } => prefix,
        }
    }

    pub fn contains(self, address: IpAddr) -> bool {
        match (self, address) {
            (Self::V4 { network, prefix }, IpAddr::V4(address)) => {
                let mask = ipv4_mask(prefix);
                u32::from(address) & mask == network
            }
            (Self::V6 { network, prefix }, IpAddr::V6(address)) => {
                let mask = ipv6_mask(prefix);
                u128::from(address) & mask == network
            }
            _ => false,
        }
    }
}

impl FromStr for NfsCidr {
    type Err = NfsBindingParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (address, prefix) = value
            .split_once('/')
            .ok_or(NfsBindingParseError::Invalid)?;
        let address = address
            .parse::<IpAddr>()
            .map_err(|_| NfsBindingParseError::Invalid)?;
        let prefix = prefix
            .parse::<u8>()
            .map_err(|_| NfsBindingParseError::Invalid)?;

        match address {
            IpAddr::V4(address) if prefix <= 32 => {
                let mask = ipv4_mask(prefix);
                Ok(Self::V4 {
                    network: u32::from(address) & mask,
                    prefix,
                })
            }
            IpAddr::V6(address) if prefix <= 128 => {
                let mask = ipv6_mask(prefix);
                Ok(Self::V6 {
                    network: u128::from(address) & mask,
                    prefix,
                })
            }
            _ => Err(NfsBindingParseError::Invalid),
        }
    }
}

impl fmt::Display for NfsCidr {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::V4 { network, prefix } => {
                write!(formatter, "{}/{}", Ipv4Addr::from(network), prefix)
            }
            Self::V6 { network, prefix } => {
                write!(formatter, "{}/{}", Ipv6Addr::from(network), prefix)
            }
        }
    }
}

const fn ipv4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

const fn ipv6_mask(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum NfsBindingParseError {
    #[error("invalid NFS binding value")]
    Invalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum NfsBindingLevel {
    L1,
    L2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NfsBinding {
    pub id: String,
    pub share_id: String,
    pub cidr: NfsCidr,
    pub uid: Option<u32>,
    pub user_id: String,
    pub permission: NfsBindingPermission,
}

impl NfsBinding {
    pub const fn level(&self) -> NfsBindingLevel {
        if self.uid.is_some() {
            NfsBindingLevel::L2
        } else {
            NfsBindingLevel::L1
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedNfsIdentity {
    pub binding_id: String,
    pub user_id: String,
    pub permission: NfsBindingPermission,
    pub level: NfsBindingLevel,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum NfsIdentityError {
    #[error("multiple NFS bindings match at the same precedence: {binding_ids:?}")]
    Ambiguous { binding_ids: Vec<String> },
}

pub fn resolve_nfs_identity(
    bindings: &[NfsBinding],
    client_ip: IpAddr,
    uid: Option<u32>,
) -> Result<Option<ResolvedNfsIdentity>, NfsIdentityError> {
    let mut best_score = None;
    let mut best = Vec::new();

    for binding in bindings {
        if !binding.cidr.contains(client_ip) {
            continue;
        }
        if let Some(expected_uid) = binding.uid
            && uid != Some(expected_uid)
        {
            continue;
        }

        let score = (u8::from(binding.uid.is_some()), binding.cidr.prefix_len());
        match best_score {
            None => {
                best_score = Some(score);
                best.push(binding);
            }
            Some(current) if score > current => {
                best_score = Some(score);
                best.clear();
                best.push(binding);
            }
            Some(current) if score == current => best.push(binding),
            Some(_) => {}
        }
    }

    if best.len() > 1 {
        let mut binding_ids = best
            .iter()
            .map(|binding| binding.id.clone())
            .collect::<Vec<_>>();
        binding_ids.sort();
        return Err(NfsIdentityError::Ambiguous { binding_ids });
    }

    Ok(best.first().map(|binding| ResolvedNfsIdentity {
        binding_id: binding.id.clone(),
        user_id: binding.user_id.clone(),
        permission: binding.permission,
        level: binding.level(),
    }))
}

#[derive(Debug, Error)]
pub enum NfsRepositoryError {
    #[error("nfs repository is unavailable")]
    Unavailable,
}

#[async_trait]
pub trait NfsBindingRepository: Send + Sync {
    async fn list_nfs_bindings(
        &self,
        share_id: &str,
    ) -> Result<Vec<NfsBinding>, NfsRepositoryError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding(
        id: &str,
        cidr: &str,
        uid: Option<u32>,
        user_id: &str,
        permission: NfsBindingPermission,
    ) -> NfsBinding {
        NfsBinding {
            id: id.to_owned(),
            share_id: "shr_media".to_owned(),
            cidr: cidr.parse().unwrap(),
            uid,
            user_id: user_id.to_owned(),
            permission,
        }
    }

    #[test]
    fn cidr_normalizes_host_bits_and_matches_same_address_family() {
        let cidr = "192.168.10.42/24".parse::<NfsCidr>().unwrap();
        assert_eq!(cidr.to_string(), "192.168.10.0/24");
        assert!(cidr.contains("192.168.10.200".parse().unwrap()));
        assert!(!cidr.contains("192.168.11.1".parse().unwrap()));
        assert!(!cidr.contains("::1".parse().unwrap()));

        let v6 = "2001:db8::1234/64".parse::<NfsCidr>().unwrap();
        assert_eq!(v6.to_string(), "2001:db8::/64");
        assert!(v6.contains("2001:db8::beef".parse().unwrap()));
    }

    #[test]
    fn l2_uid_binding_wins_over_l1_network_binding() {
        let bindings = vec![
            binding(
                "l1",
                "192.168.1.0/24",
                None,
                "usr_guest",
                NfsBindingPermission::ReadOnly,
            ),
            binding(
                "l2",
                "192.168.0.0/16",
                Some(1000),
                "usr_alice",
                NfsBindingPermission::ReadWrite,
            ),
        ];

        let resolved = resolve_nfs_identity(
            &bindings,
            "192.168.1.20".parse().unwrap(),
            Some(1000),
        )
        .unwrap()
        .unwrap();

        assert_eq!(resolved.binding_id, "l2");
        assert_eq!(resolved.user_id, "usr_alice");
        assert_eq!(resolved.level, NfsBindingLevel::L2);
        assert_eq!(resolved.permission, NfsBindingPermission::ReadWrite);
    }

    #[test]
    fn most_specific_network_wins_within_same_level() {
        let bindings = vec![
            binding(
                "wide",
                "10.0.0.0/8",
                None,
                "usr_wide",
                NfsBindingPermission::ReadOnly,
            ),
            binding(
                "specific",
                "10.20.30.0/24",
                None,
                "usr_specific",
                NfsBindingPermission::ReadWrite,
            ),
        ];

        let resolved =
            resolve_nfs_identity(&bindings, "10.20.30.4".parse().unwrap(), Some(501))
                .unwrap()
                .unwrap();

        assert_eq!(resolved.binding_id, "specific");
        assert_eq!(resolved.user_id, "usr_specific");
    }

    #[test]
    fn l1_is_used_when_no_l2_uid_matches() {
        let bindings = vec![
            binding(
                "l1",
                "172.16.0.0/12",
                None,
                "usr_guest",
                NfsBindingPermission::ReadOnly,
            ),
            binding(
                "l2",
                "172.16.1.0/24",
                Some(1000),
                "usr_alice",
                NfsBindingPermission::ReadWrite,
            ),
        ];

        let resolved =
            resolve_nfs_identity(&bindings, "172.16.1.8".parse().unwrap(), Some(1001))
                .unwrap()
                .unwrap();

        assert_eq!(resolved.binding_id, "l1");
        assert_eq!(resolved.level, NfsBindingLevel::L1);
    }

    #[test]
    fn same_precedence_match_is_rejected_as_ambiguous() {
        let bindings = vec![
            binding(
                "first",
                "192.168.5.1/24",
                None,
                "usr_a",
                NfsBindingPermission::ReadOnly,
            ),
            binding(
                "second",
                "192.168.5.200/24",
                None,
                "usr_b",
                NfsBindingPermission::ReadWrite,
            ),
        ];

        assert_eq!(
            resolve_nfs_identity(&bindings, "192.168.5.50".parse().unwrap(), None),
            Err(NfsIdentityError::Ambiguous {
                binding_ids: vec!["first".to_owned(), "second".to_owned()]
            })
        );
    }

    #[test]
    fn unmatched_client_is_denied_by_default() {
        let bindings = vec![binding(
            "lan",
            "192.168.1.0/24",
            None,
            "usr_guest",
            NfsBindingPermission::ReadOnly,
        )];

        assert_eq!(
            resolve_nfs_identity(&bindings, "10.0.0.1".parse().unwrap(), Some(1000)).unwrap(),
            None
        );
    }
}
