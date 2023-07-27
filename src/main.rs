use std::env;
use std::io::{BufWriter, Write};
use std::thread;
use std::time::Duration;

use ppproperly::{MacAddr, PppoePkt, PppoeVal, Serialize};
use rsdsl_pppoe2::{Pppoe, Result};
use rsdsl_pppoe2_sys::new_discovery_socket;

static PPPOE_XMIT_INTERVAL: Duration = Duration::from_secs(8);

fn main() -> Result<()> {
    connect(&env::args().nth(1).expect("usage: rsdsl_pppoe2 <interface>"))?;
    Ok(())
}

fn connect(interface: &str) -> Result<()> {
    let (sock_disc, local_mac) = new_discovery_socket(interface)?;
    let mut sock_w = BufWriter::with_capacity(1500, sock_disc);

    let pppoe_state = Pppoe::default();
    loop {
        match pppoe_state {
            Pppoe::Init => {
                new_padi(local_mac).serialize(&mut sock_w)?;
                sock_w.flush()?;
            }
            _ => todo!(),
        }

        thread::sleep(PPPOE_XMIT_INTERVAL);
    }
}

fn new_padi(local_mac: MacAddr) -> PppoePkt {
    PppoePkt::new_padi(
        local_mac,
        vec![
            PppoeVal::ServiceName("".into()).into(),
            PppoeVal::HostUniq(rand::random::<[u8; 16]>().into()).into(),
        ],
    )
}
