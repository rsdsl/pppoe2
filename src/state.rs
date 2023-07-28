use ppproperly::MacAddr;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Pppoe {
    Init,
    Requesting(MacAddr, Option<Vec<u8>>, usize),
    Active(MacAddr),
    Err,
}

impl Default for Pppoe {
    fn default() -> Self {
        Self::Init
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Ppp {
    Synchronize,
    Active,
}

impl Default for Ppp {
    fn default() -> Self {
        Self::Synchronize
    }
}
