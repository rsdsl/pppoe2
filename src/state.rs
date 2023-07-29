use ppproperly::MacAddr;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Pppoe {
    Init,
    Request(MacAddr, Option<Vec<u8>>, usize),
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
    Auth,
    Active,
    Terminated,
    Err,
}

impl Default for Ppp {
    fn default() -> Self {
        Self::Synchronize
    }
}
