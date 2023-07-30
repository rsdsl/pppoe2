use ppproperly::{AuthProto, MacAddr};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum Pppoe {
    #[default]
    Init,
    Request(MacAddr, Option<Vec<u8>>, usize),
    Active(MacAddr, u16),
    Err,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Ppp {
    Synchronize(u8, u16, u32, usize),
    SyncAck(u8, u16, Option<AuthProto>, u32, usize),
    SyncAcked(usize),
    Auth(Option<AuthProto>, usize),
    Active,
    Terminate(Vec<u8>, usize),
    Terminate2(String),
    Terminated,
    Err,
}

impl Default for Ppp {
    fn default() -> Self {
        Self::Synchronize(1, 1492, rand::random(), 0)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum Ncp {
    #[default]
    Dead,
    Configure(u8, usize),
    ConfAck(u8, usize),
    ConfAcked(usize),
    Active,
    Failed,
}
