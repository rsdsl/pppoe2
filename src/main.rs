use std::io::{BufWriter, Write};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use ppproperly::{Deserialize, MacAddr, PppoePkt, PppoeVal, Serialize};
use rsdsl_pppoe2::{Pppoe, Result};
use rsdsl_pppoe2_sys::new_discovery_socket;
use socket2::Socket;

const PPPOE_UPLINK: &str = "eth1";

static PPPOE_XMIT_INTERVAL: Duration = Duration::from_secs(8);

fn main() -> Result<()> {
    connect(PPPOE_UPLINK)?;
    Ok(())
}

fn connect(interface: &str) -> Result<()> {
    let (sock_disc, local_mac) = new_discovery_socket(interface)?;
    let mut sock_w = BufWriter::with_capacity(1500, sock_disc.try_clone()?);

    let pppoe_state = Arc::new(Mutex::new(Pppoe::default()));

    let pppoe_state2 = pppoe_state.clone();
    let recv_disc = thread::spawn(
        move || match recv_discovery(sock_disc, pppoe_state2.clone()) {
            Ok(_) => Ok(()),
            Err(e) => {
                *pppoe_state2.lock().expect("pppoe state mutex is poisoned") = Pppoe::Err;
                Err(e)
            }
        },
    );

    loop {
        match *pppoe_state.lock().expect("pppoe state mutex is poisoned") {
            Pppoe::Init => {
                new_padi(local_mac).serialize(&mut sock_w)?;
                sock_w.flush()?;

                println!(" -> padi");
            }
            Pppoe::Err => {
                return Err(recv_disc
                    .join()
                    .expect("recv_discovery panic")
                    .expect_err("Pppoe::Err state entered without an error"));
            }
            _ => todo!(),
        }

        thread::sleep(PPPOE_XMIT_INTERVAL);
    }
}

fn recv_discovery(mut sock: Socket, state: Arc<Mutex<Pppoe>>) -> Result<()> {
    loop {
        let mut pkt = PppoePkt::default();
        pkt.deserialize(&mut sock)?;

        println!("{:?}", pkt);
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
