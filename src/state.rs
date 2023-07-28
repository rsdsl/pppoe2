#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Pppoe {
    Init,
    Requesting,
    Active(u16),
    Err,
}

impl Default for Pppoe {
    fn default() -> Self {
        Self::Init
    }
}
