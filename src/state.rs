use ppproperly::{AuthProto, MacAddr};

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
    Synchronize(u8, u16, u32, usize),
    SyncAck(u8, u16, u32, usize),
    SyncAcked(usize),
    Auth(Option<AuthProto>),
    Active,
    Terminated,
    Err,
}

impl Default for Ppp {
    fn default() -> Self {
        Self::Synchronize(1, 1492, rand::random(), 0)
    }
}
