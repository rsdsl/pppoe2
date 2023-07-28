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
