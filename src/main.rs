use std::io::{BufReader, BufWriter, Write};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use ppproperly::{Deserialize, MacAddr, PppoeData, PppoePkt, PppoeVal, Serialize};
use rsdsl_netlinkd::link;
use rsdsl_pppoe2::{Pppoe, Result};
use rsdsl_pppoe2_sys::new_discovery_socket;
use socket2::Socket;

const PPPOE_UPLINK: &str = "eth1";
const MAX_ATTEMPTS: usize = 10;

static PPPOE_XMIT_INTERVAL: Duration = Duration::from_secs(8);

fn main() -> Result<()> {
    println!("wait for up {}", PPPOE_UPLINK);

    link::wait_up(PPPOE_UPLINK.into())?;
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
                PppoePkt::new_padi(
                    local_mac,
                    vec![
                        PppoeVal::ServiceName("".into()).into(),
                        PppoeVal::HostUniq(rand::random::<[u8; 16]>().into()).into(),
                    ],
                )
                .serialize(&mut sock_w)?;
                sock_w.flush()?;

                println!(" -> [{}] padi", MacAddr::BROADCAST);
            }
            Pppoe::Requesting(remote_mac, ref ac_cookie, attempt) => {
                if attempt >= MAX_ATTEMPTS {
                    *pppoe_state.lock().expect("pppoe state mutex is poisoned") = Pppoe::Init;
                    continue;
                }

                PppoePkt::new_padr(
                    remote_mac,
                    local_mac,
                    if let Some(ac_cookie) = ac_cookie {
                        vec![
                            PppoeVal::ServiceName("".into()).into(),
                            PppoeVal::AcCookie(ac_cookie.to_owned()).into(),
                        ]
                    } else {
                        vec![PppoeVal::ServiceName("".into()).into()]
                    },
                )
                .serialize(&mut sock_w)?;
                sock_w.flush()?;

                println!(" -> [{}] padr {}/{}", remote_mac, attempt, MAX_ATTEMPTS);
                *pppoe_state.lock().expect("pppoe state mutex is poisoned") =
                    Pppoe::Requesting(remote_mac, ac_cookie.to_owned(), attempt + 1);
            }
            Pppoe::Active => {}
            Pppoe::Err => {
                return Err(recv_disc
                    .join()
                    .expect("recv_discovery panic")
                    .expect_err("Pppoe::Err state entered without an error"));
            }
        }

        thread::sleep(PPPOE_XMIT_INTERVAL);
    }
}

fn recv_discovery(sock: Socket, state: Arc<Mutex<Pppoe>>) -> Result<()> {
    let mut sock_r = BufReader::with_capacity(1500, sock);

    loop {
        let mut pkt = PppoePkt::default();
        pkt.deserialize(&mut sock_r)?;

        match pkt.data {
            PppoeData::Pado(pado) => {
                let ac_name = pado
                    .tags
                    .iter()
                    .find_map(|tag| {
                        if let PppoeVal::AcName(ac_name) = &tag.data {
                            Some(ac_name.to_owned())
                        } else {
                            None
                        }
                    })
                    .unwrap_or(String::new());

                let ac_cookie = pado.tags.iter().find_map(|tag| {
                    if let PppoeVal::AcCookie(ac_cookie) = &tag.data {
                        Some(ac_cookie.to_owned())
                    } else {
                        None
                    }
                });

                let mut state = state.lock().expect("pppoe state mutex is poisoned");
                if *state != Pppoe::Init {
                    println!(" <- [{}] unexpected pado, ac: {}", pkt.src_mac, ac_name);
                    continue;
                }

                *state = Pppoe::Requesting(pkt.src_mac, ac_cookie, 0);
                println!(" <- [{}] pado, ac: {}", pkt.src_mac, ac_name);
            }
            PppoeData::Pads(_) => {
                let mut state = state.lock().expect("pppoe state mutex is poisoned");
                if let Pppoe::Requesting(_, _, _) = *state {
                    *state = Pppoe::Active;
                    println!(" <- [{}] pads, session id: {}", pkt.src_mac, pkt.session_id);
                } else {
                    println!(
                        " <- [{}] unexpected pads, session id: {}",
                        pkt.src_mac, pkt.session_id
                    );
                }
            }
            PppoeData::Padt(padt) => {
                let generic_error = padt
                    .tags
                    .iter()
                    .find_map(|tag| {
                        if let PppoeVal::GenericError(generic_error) = &tag.data {
                            Some(generic_error.to_owned())
                        } else {
                            None
                        }
                    })
                    .unwrap_or(String::new());

                let mut state = state.lock().expect("pppoe state mutex is poisoned");
                if *state != Pppoe::Active {
                    println!(
                        " <- [{}] unexpected padt, error: {}",
                        pkt.src_mac, generic_error
                    );
                    continue;
                }

                *state = Pppoe::Init;
                println!(" <- [{}] padt, error: {}", pkt.src_mac, generic_error);
            }
            _ => todo!(),
        }
    }
}
