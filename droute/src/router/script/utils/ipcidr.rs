use super::Result;
use cidr_utils::{
    cidr::{IpCidr as Cidr, IpCidrError},
    utils::IpCidrCombiner as CidrCombiner,
};
use std::{net::IpAddr, path::Path};

/// IP CIDR matcher.
#[derive(Clone)]
#[cfg_attr(feature = "rune-scripting", derive(rune::Any))]
pub struct IpCidr {
    matcher: CidrCombiner,
}

impl IpCidr {
    /// Create a new empty `IpCidr` matcher
    pub fn new() -> Self {
        Self {
            matcher: CidrCombiner::new(),
        }
    }

    /// Add IP CIDRs from a files where each IP CIDR is seperated from one another by `\n`.
    pub fn add_file(&mut self, path: impl AsRef<Path>) -> Result<()> {
        let (mut file, _) = niffler::from_path(path)?;
        let mut data = String::new();
        file.read_to_string(&mut data)?;
        // This gets rid of empty substrings for stability reasons. See also https://github.com/LEXUGE/dcompass/issues/33.
        data.split('\n').filter(|&x| !x.is_empty()).try_for_each(
            |x| -> std::result::Result<(), IpCidrError> {
                self.matcher.push(Cidr::from_str(x)?);
                Ok(())
            },
        )?;
        Ok(())
    }

    /// Check if IP CIDR set contains the given IP address.
    pub fn contains(&self, ip: IpAddr) -> bool {
        self.matcher.contains(ip)
    }
}

impl Default for IpCidr {
    fn default() -> Self {
        Self::new()
    }
}
