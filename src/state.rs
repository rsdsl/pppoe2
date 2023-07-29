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
    Synchronize(u8, u16, u32),
    SyncAck(u8, u16, u32),
    SyncAcked,
    Auth(AuthProto),
    Active,
    Terminated,
    Err,
}

impl Default for Ppp {
    fn default() -> Self {
        Self::Synchronize(1, 1492, rand::random())
    }
}
