use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use ppproperly::{Deserialize, MacAddr, PppPkt, PppoeData, PppoePkt, PppoeVal, Serialize};
use rsdsl_netlinkd::link;
use rsdsl_pppoe2::{Ppp, Pppoe, Result};
use rsdsl_pppoe2_sys::{new_discovery_socket, new_session};
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

    let interface2 = interface.to_owned();
    let pppoe_state2 = pppoe_state.clone();
    let recv_disc =
        thread::spawn(
            move || match recv_discovery(&interface2, sock_disc, pppoe_state2.clone()) {
                Ok(_) => Ok(()),
                Err(e) => {
                    *pppoe_state2.lock().expect("pppoe state mutex is poisoned") = Pppoe::Err;
                    Err(e)
                }
            },
        );

    loop {
        {
            let mut pppoe_state = pppoe_state.lock().expect("pppoe state mutex is poisoned");
            match *pppoe_state {
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
                Pppoe::Request(remote_mac, ref ac_cookie, attempt) => {
                    if attempt >= MAX_ATTEMPTS {
                        *pppoe_state = Pppoe::Init;
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
                    *pppoe_state = Pppoe::Request(remote_mac, ac_cookie.to_owned(), attempt + 1);
                }
                Pppoe::Active(_) => {}
                Pppoe::Err => {
                    return Err(recv_disc
                        .join()
                        .expect("recv_discovery panic")
                        .expect_err("Pppoe::Err state entered without an error"));
                }
            }
        }

        thread::sleep(PPPOE_XMIT_INTERVAL);
    }
}

fn recv_discovery(interface: &str, sock: Socket, state: Arc<Mutex<Pppoe>>) -> Result<()> {
    let mut sock_r = BufReader::with_capacity(1500, sock);

    loop {
        let mut pkt = PppoePkt::default();
        pkt.deserialize(&mut sock_r)?;

        match *state.lock().expect("pppoe state mutex is poisoned") {
            Pppoe::Request(remote_mac, _, _) => {
                if pkt.src_mac != remote_mac {
                    println!(" <- [{}] unexpected mac, pkt: {:?}", pkt.src_mac, pkt);
                    continue;
                }
            }
            Pppoe::Active(remote_mac) => {
                if pkt.src_mac != remote_mac {
                    println!(" <- [{}] unexpected mac, pkt: {:?}", pkt.src_mac, pkt);
                    continue;
                }
            }
            _ => {}
        }

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

                *state = Pppoe::Request(pkt.src_mac, ac_cookie, 0);
                println!(" <- [{}] pado, ac: {}", pkt.src_mac, ac_name);
            }
            PppoeData::Pads(_) => {
                let mut state = state.lock().expect("pppoe state mutex is poisoned");
                if let Pppoe::Request(_, _, _) = *state {
                    let interface2 = interface.to_owned();
                    thread::spawn(move || {
                        match session(&interface2, pkt.src_mac, pkt.session_id) {
                            Ok(_) => {}
                            Err(e) => eprintln!("{}", e),
                        }
                    });

                    *state = Pppoe::Active(pkt.src_mac);
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
                if let Pppoe::Active(_) = *state {
                    *state = Pppoe::Init;
                    println!(" <- [{}] padt, error: {}", pkt.src_mac, generic_error);
                } else {
                    println!(
                        " <- [{}] unexpected padt, error: {}",
                        pkt.src_mac, generic_error
                    );
                }
            }
            _ => println!(" <- [{}] unsupported pkt {:?}", pkt.src_mac, pkt),
        }
    }
}

fn session(interface: &str, remote_mac: MacAddr, session_id: u16) -> Result<()> {
    let (_sock_sess, _ctl, ppp) = new_session(interface, remote_mac, session_id)?;

    let ppp_state = Arc::new(Mutex::new(Ppp::default()));

    let ppp_state2 = ppp_state.clone();
    let recv_sess = thread::spawn(move || match recv_session(ppp, ppp_state2.clone()) {
        Ok(_) => Ok(()),
        Err(e) => {
            *ppp_state2.lock().expect("ppp state mutex is poisoned") = Ppp::Err;
            Err(e)
        }
    });

    loop {
        let ppp_state = ppp_state.lock().expect("ppp state mutex is poisoned");
        match *ppp_state {
            Ppp::Synchronize => {}
            Ppp::Active => {}
            Ppp::Err => {
                return Err(recv_sess
                    .join()
                    .expect("recv_session panic")
                    .expect_err("Ppp::Err state entered without an error"));
            }
        }

        thread::sleep(PPPOE_XMIT_INTERVAL);
    }
}

fn recv_session(sock: File, state: Arc<Mutex<Ppp>>) -> Result<()> {
    let mut sock_r = BufReader::with_capacity(1500, sock);

    loop {
        let mut pkt = PppPkt::default();
        pkt.deserialize(&mut sock_r)?;

        println!(" <- ppp {:?}", pkt);
    }
}
