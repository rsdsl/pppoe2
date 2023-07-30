use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use ppproperly::{
    AuthProto, ChapAlgorithm, ChapData, ChapPkt, Deserialize, IpcpData, IpcpOpt, IpcpPkt,
    Ipv6cpData, Ipv6cpOpt, Ipv6cpPkt, LcpData, LcpOpt, LcpPkt, MacAddr, PapData, PapPkt, PppData,
    PppPkt, PppoeData, PppoePkt, PppoeVal, Serialize,
};
use rsdsl_ip_config::{DsConfig, Ipv4Config, Ipv6Config};
use rsdsl_netlinkd::link;
use rsdsl_pppoe2::{Ncp, Ppp, Pppoe, Result};
use rsdsl_pppoe2_sys::{new_discovery_socket, new_session};
use serde::{Deserialize as SDeserialize, Serialize as SSerialize};
use socket2::Socket;

const PPPOE_UPLINK: &str = "eth1";

const MAX_ATTEMPTS: usize = 10;
const MAX_STATUS_ATTEMPTS: usize = 2;

static PPPOE_XMIT_INTERVAL: Duration = Duration::from_secs(3);
static SESSION_INIT_GRACE_PERIOD: Duration = Duration::from_secs(1);

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum Network {
    Ipv4,
    Ipv6,
}

#[derive(Clone, Debug, Eq, PartialEq, SSerialize, SDeserialize)]
struct Config {
    username: String,
    password: String,
}

fn ifid(addr: Ipv6Addr) -> u64 {
    (u128::from(addr) & u64::MAX as u128) as u64
}

fn ll(if_id: u64) -> Ipv6Addr {
    ((0xfe80 << 112) | if_id as u128).into()
}

fn write_dsconfig(config4: Arc<Mutex<Ipv4Config>>, config6: Arc<Mutex<Ipv6Config>>) -> Result<()> {
    let config4 = config4.lock().expect("ipv4 config mutex is poisoned");
    let config6 = config6.lock().expect("ipv6 config mutex is poisoned");

    let dsconfig = DsConfig {
        v4: match config4.addr {
            Ipv4Addr::UNSPECIFIED => None,
            _ => Some(*config4),
        },
        v6: match config6.laddr {
            Ipv6Addr::UNSPECIFIED => None,
            _ => Some(*config6),
        },
    };

    let mut file = File::create(rsdsl_ip_config::LOCATION)?;
    serde_json::to_writer_pretty(&mut file, &dsconfig)?;

    println!("<-> write ds config to {}", rsdsl_ip_config::LOCATION);
    Ok(())
}

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
    let recv_disc = thread::spawn(move || {
        match recv_discovery(&interface2, sock_disc, local_mac, pppoe_state2.clone()) {
            Ok(_) => Ok(()),
            Err(e) => {
                *pppoe_state2.lock().expect("pppoe state mutex is poisoned") = Pppoe::Err;
                Err(e)
            }
        }
    });

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
                Pppoe::Active(..) => {}
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

fn recv_discovery(
    interface: &str,
    sock: Socket,
    local_mac: MacAddr,
    state: Arc<Mutex<Pppoe>>,
) -> Result<()> {
    let mut sock_w = BufWriter::with_capacity(1500, sock.try_clone()?);
    let mut sock_r = BufReader::with_capacity(1500, sock.try_clone()?);

    loop {
        let mut pkt = PppoePkt::default();
        pkt.deserialize(&mut sock_r)?;

        match *state.lock().expect("pppoe state mutex is poisoned") {
            Pppoe::Request(remote_mac, ..) => {
                if pkt.src_mac != remote_mac {
                    println!(" <- [{}] unexpected mac, pkt: {:?}", pkt.src_mac, pkt);
                    continue;
                }
            }
            Pppoe::Active(remote_mac, session_id) => {
                if pkt.src_mac != remote_mac {
                    println!(" <- [{}] unexpected mac, pkt: {:?}", pkt.src_mac, pkt);
                    continue;
                }

                if pkt.session_id != session_id {
                    println!(
                        " <- [{}] wrong session id {}, pkt: {:?}",
                        pkt.src_mac, pkt.session_id, pkt
                    );
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

                PppoePkt::new_padr(
                    pkt.src_mac,
                    local_mac,
                    if let Some(ref ac_cookie) = ac_cookie {
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

                *state = Pppoe::Request(pkt.src_mac, ac_cookie, 1);

                println!(" -> [{}] padr 0/{}", pkt.src_mac, MAX_ATTEMPTS);
                println!(" <- [{}] pado, ac: {}", pkt.src_mac, ac_name);
            }
            PppoeData::Pads(_) => {
                let state2 = state.clone();

                let mut state = state.lock().expect("pppoe state mutex is poisoned");
                if let Pppoe::Request(..) = *state {
                    let interface2 = interface.to_owned();
                    let sock2 = sock.try_clone()?;
                    thread::spawn(move || {
                        thread::sleep(SESSION_INIT_GRACE_PERIOD);
                        match session(
                            &interface2,
                            sock2,
                            pkt.src_mac,
                            local_mac,
                            state2,
                            pkt.session_id,
                        ) {
                            Ok(_) => {}
                            Err(e) => eprintln!("{}", e),
                        }
                    });

                    *state = Pppoe::Active(pkt.src_mac, pkt.session_id);
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
                if let Pppoe::Active(..) = *state {
                    *state = Pppoe::Init;
                }

                println!(" <- [{}] padt, error: {}", pkt.src_mac, generic_error);
            }
            _ => println!(" <- [{}] unsupported pppoe pkt {:?}", pkt.src_mac, pkt),
        }
    }
}

fn session(
    interface: &str,
    sock_disc: Socket,
    remote_mac: MacAddr,
    local_mac: MacAddr,
    pppoe_state: Arc<Mutex<Pppoe>>,
    session_id: u16,
) -> Result<()> {
    let mut file = File::open("/data/pppoe.conf")?;
    let config: Config = serde_json::from_reader(&mut file)?;

    let mut sock_disc_w = BufWriter::with_capacity(1500, sock_disc);

    let (_sock_sess, ctl, ppp) = new_session(interface, remote_mac, session_id)?;
    let mut ctl_w = BufWriter::with_capacity(1500, ctl.try_clone()?);

    let ppp_state = Arc::new(Mutex::new(Ppp::default()));

    let ncp_states = Arc::new(Mutex::new(HashMap::new()));

    {
        let mut ncps = ncp_states.lock().expect("ncp state mutex is poisoned");

        ncps.insert(Network::Ipv4, Ncp::default());
        ncps.insert(Network::Ipv6, Ncp::default());
    }

    let config4 = Arc::new(Mutex::new(Ipv4Config::default()));
    let config6 = Arc::new(Mutex::new(Ipv6Config::default()));

    let mut ipv4_active = false;
    let mut ipv6_active = false;

    let ctl2 = ctl.try_clone()?;
    let ppp_state2 = ppp_state.clone();
    let recv_link_handle = thread::spawn(move || match recv_link(ctl2, ppp_state2.clone()) {
        Ok(_) => Ok(()),
        Err(e) => {
            *ppp_state2.lock().expect("ppp state mutex is poisoned") = Ppp::Err;
            Err(e)
        }
    });

    let ppp_state2 = ppp_state.clone();
    let ncp_states2 = ncp_states.clone();
    let config42 = config4.clone();
    let config62 = config6.clone();
    let recv_network_handle = thread::spawn(move || {
        match recv_network(ppp, ppp_state2.clone(), ncp_states2, config42, config62) {
            Ok(_) => Ok(()),
            Err(e) => {
                *ppp_state2.lock().expect("ppp state mutex is poisoned") = Ppp::Err;
                Err(e)
            }
        }
    });

    loop {
        {
            let mut ppp_state = ppp_state.lock().expect("ppp state mutex is poisoned");
            match *ppp_state {
                Ppp::Synchronize(identifier, mru, magic_number, attempt) => {
                    if attempt >= MAX_ATTEMPTS {
                        *ppp_state = Ppp::Terminate2(
                            "Maximum number of Configure-Request attempts exceeded".into(),
                        );
                        continue;
                    }

                    PppPkt::new_lcp(LcpPkt::new_configure_request(
                        identifier,
                        vec![
                            LcpOpt::Mru(mru).into(),
                            LcpOpt::MagicNumber(magic_number).into(),
                        ],
                    ))
                    .serialize(&mut ctl_w)?;
                    ctl_w.flush()?;

                    println!(
                        " -> lcp configure-request {}, mru: {}, magic number: {}",
                        identifier, mru, magic_number
                    );

                    *ppp_state = Ppp::Synchronize(identifier, mru, magic_number, attempt + 1);
                }
                Ppp::SyncAck(identifier, mru, ref auth_proto, magic_number, attempt) => {
                    if attempt >= MAX_ATTEMPTS {
                        *ppp_state = Ppp::Terminate2(
                            "Maximum number of Configure-Request attempts exceeded".into(),
                        );
                        continue;
                    }

                    PppPkt::new_lcp(LcpPkt::new_configure_request(
                        identifier,
                        vec![
                            LcpOpt::Mru(mru).into(),
                            LcpOpt::MagicNumber(magic_number).into(),
                        ],
                    ))
                    .serialize(&mut ctl_w)?;
                    ctl_w.flush()?;

                    println!(
                        " -> lcp configure-request {}, mru: {}, magic number: {}",
                        identifier, mru, magic_number
                    );

                    *ppp_state = Ppp::SyncAck(
                        identifier,
                        mru,
                        auth_proto.clone(),
                        magic_number,
                        attempt + 1,
                    );
                }
                Ppp::SyncAcked(attempt) => {
                    // Packet handler takes care of the rest.

                    if attempt >= MAX_ATTEMPTS {
                        *ppp_state = Ppp::Terminate2(
                            "Maximum number of Configure-Ack attempts exceeded".into(),
                        );
                        continue;
                    }

                    *ppp_state = Ppp::SyncAcked(attempt + 1);
                }
                Ppp::Auth(ref auth_proto, attempt) => {
                    if attempt >= MAX_ATTEMPTS {
                        *ppp_state = Ppp::Terminate(
                            "Maximum number of authentication attempts exceeded".into(),
                            0,
                        );
                        continue;
                    }

                    match auth_proto {
                        None => {
                            *ppp_state = Ppp::Active;
                            continue;
                        }
                        Some(AuthProto::Pap) => {
                            PppPkt::new_pap(PapPkt::new_authenticate_request(
                                rand::random(),
                                config.username.clone(),
                                config.password.clone(),
                            ))
                            .serialize(&mut ctl_w)?;
                            ctl_w.flush()?;
                        }
                        Some(AuthProto::Chap(_)) => {} // Packet handler takes care of this.
                    }

                    *ppp_state = Ppp::Auth(auth_proto.clone(), attempt + 1);
                }
                Ppp::Active => {
                    let mut update = false;

                    let mut ncps = ncp_states.lock().expect("ncp state mutex is poisoned");
                    for (ncp, state) in ncps.iter_mut() {
                        if *state == Ncp::Dead {
                            *state = Ncp::Configure(1, 0);

                            let ctl2 = ctl.try_clone()?;
                            let ncp_states2 = ncp_states.clone();
                            let config42 = config4.clone();
                            let config62 = config6.clone();
                            match *ncp {
                                Network::Ipv4 => {
                                    thread::spawn(|| match ipcp(ctl2, ncp_states2, config42) {
                                        Ok(_) => Ok(()),
                                        Err(e) => {
                                            eprintln!("{}", e);
                                            Err(e)
                                        }
                                    });

                                    ipv4_active = false;
                                }
                                Network::Ipv6 => {
                                    thread::spawn(|| match ipv6cp(ctl2, ncp_states2, config62) {
                                        Ok(_) => Ok(()),
                                        Err(e) => {
                                            eprintln!("{}", e);
                                            Err(e)
                                        }
                                    });

                                    ipv6_active = false;
                                }
                            };
                        } else if *state == Ncp::Active {
                            match *ncp {
                                Network::Ipv4 if !ipv4_active => {
                                    ipv4_active = true;
                                    update = true;
                                }
                                Network::Ipv6 if !ipv6_active => {
                                    ipv6_active = true;
                                    update = true;
                                }
                                _ => {}
                            }
                        } else if *state == Ncp::Failed {
                            match *ncp {
                                Network::Ipv4 if ipv4_active => {
                                    ipv4_active = false;
                                    update = true;
                                }
                                Network::Ipv6 if ipv6_active => {
                                    ipv6_active = false;
                                    update = true;
                                }
                                _ => {}
                            }
                        }
                    }

                    if update {
                        write_dsconfig(
                            if ipv4_active {
                                config4.clone()
                            } else {
                                Arc::new(Mutex::new(Ipv4Config::default()))
                            },
                            if ipv6_active {
                                config6.clone()
                            } else {
                                Arc::new(Mutex::new(Ipv6Config::default()))
                            },
                        )?;
                    }
                }
                Ppp::Terminate(ref reason, attempt) => {
                    if attempt >= MAX_ATTEMPTS {
                        *ppp_state = Ppp::Terminate2(
                            String::from_utf8(reason.clone()).unwrap_or(String::new()),
                        );
                        continue;
                    }

                    PppPkt::new_lcp(LcpPkt::new_terminate_request(
                        rand::random(),
                        reason.clone(),
                    ))
                    .serialize(&mut ctl_w)?;
                    ctl_w.flush()?;

                    let reason_pretty =
                        String::from_utf8(reason.clone()).unwrap_or(format!("{:?}", reason));

                    println!(
                        " -> lcp terminate-request {}/{}, reason: {}",
                        attempt, MAX_STATUS_ATTEMPTS, reason_pretty
                    );

                    *ppp_state = Ppp::Terminate(reason.clone(), attempt + 1);
                }
                Ppp::Terminate2(ref reason) => {
                    PppoePkt::new_padt(
                        remote_mac,
                        local_mac,
                        session_id,
                        vec![PppoeVal::GenericError(reason.clone()).into()],
                    )
                    .serialize(&mut sock_disc_w)?;
                    sock_disc_w.flush()?;

                    println!(
                        " -> [{}] padt, session id: {}, reason: {}",
                        remote_mac, session_id, reason
                    );

                    *ppp_state = Ppp::Terminated;
                    *pppoe_state.lock().expect("pppoe state mutex is poisoned") = Pppoe::Init;
                    break;
                }
                Ppp::Terminated => {
                    break;
                }
                Ppp::Err => {
                    return Err(if recv_link_handle.is_finished() {
                        recv_link_handle
                            .join()
                            .expect("recv_link panic")
                            .expect_err("Ppp::Err state entered without an error")
                    } else {
                        recv_network_handle
                            .join()
                            .expect("recv_network panic")
                            .expect_err("Ppp::Err state entered without an error")
                    });
                }
            }
        }

        thread::sleep(PPPOE_XMIT_INTERVAL);
    }

    Ok(())
}

fn recv_link(ctl: File, state: Arc<Mutex<Ppp>>) -> Result<()> {
    let mut ctl_r = BufReader::with_capacity(1500, ctl.try_clone()?);
    let mut ctl_w = BufWriter::with_capacity(1500, ctl);

    let mut magic = 0;
    loop {
        if !ctl_r.fill_buf().map(|b| !b.is_empty())? {
            *state.lock().expect("ppp state mutex is poisoned") = Ppp::Terminated;
            break;
        }

        let mut ppp = PppPkt::default();
        ppp.deserialize(&mut ctl_r)?;

        match ppp.data {
            PppData::Lcp(lcp) => handle_lcp(lcp, &mut ctl_w, state.clone(), &mut magic)?,
            PppData::Pap(pap) => handle_pap(pap, state.clone())?,
            PppData::Chap(chap) => handle_chap(chap, &mut ctl_w, state.clone())?,
            _ => println!(" <- unsupported ppp pkt {:?}", ppp),
        }
    }

    Ok(())
}

fn recv_network(
    ppp: File,
    state: Arc<Mutex<Ppp>>,
    ncp_states: Arc<Mutex<HashMap<Network, Ncp>>>,
    config4: Arc<Mutex<Ipv4Config>>,
    config6: Arc<Mutex<Ipv6Config>>,
) -> Result<()> {
    let mut ppp_r = BufReader::with_capacity(1500, ppp.try_clone()?);
    let mut ppp_w = BufWriter::with_capacity(1500, ppp);

    loop {
        if !ppp_r.fill_buf().map(|b| !b.is_empty())? {
            *state.lock().expect("ppp state mutex is poisoned") = Ppp::Terminated;
            break;
        }

        let mut ppp = PppPkt::default();
        ppp.deserialize(&mut ppp_r)?;

        match ppp.data {
            PppData::Ipcp(ipcp) => handle_ipcp(
                ipcp,
                &mut ppp_w,
                state.clone(),
                ncp_states.clone(),
                config4.clone(),
            )?,
            PppData::Ipv6cp(ipv6cp) => handle_ipv6cp(
                ipv6cp,
                &mut ppp_w,
                state.clone(),
                ncp_states.clone(),
                config6.clone(),
            )?,
            _ => println!(" <- unsupported ppp pkt {:?}", ppp),
        }
    }

    Ok(())
}

fn handle_lcp(
    lcp: LcpPkt,
    ctl_w: &mut BufWriter<File>,
    state: Arc<Mutex<Ppp>>,
    magic: &mut u32,
) -> Result<()> {
    match lcp.data {
        LcpData::ConfigureRequest(configure_request) => {
            let mru = configure_request
                .options
                .iter()
                .find_map(|opt| {
                    if let LcpOpt::Mru(mru) = opt.value {
                        Some(mru)
                    } else {
                        None
                    }
                })
                .unwrap_or(1500);
            let auth_proto = configure_request.options.iter().find_map(|opt| {
                if let LcpOpt::AuthenticationProtocol(auth_proto) = &opt.value {
                    Some(auth_proto.protocol.clone())
                } else {
                    None
                }
            });
            let pfc = configure_request
                .options
                .iter()
                .any(|opt| opt.value == LcpOpt::ProtocolFieldCompression);
            let acfc = configure_request
                .options
                .iter()
                .any(|opt| opt.value == LcpOpt::AddrCtlFieldCompression);

            if mru < 1492 {
                PppPkt::new_lcp(LcpPkt::new_configure_nak(
                    lcp.identifier,
                    vec![LcpOpt::Mru(1492).into()],
                ))
                .serialize(ctl_w)?;
                ctl_w.flush()?;

                println!(
                    " -> lcp configure-nak {}, mru: {} -> 1492",
                    lcp.identifier, mru
                );
                return Ok(());
            }
            if pfc || acfc {
                let mut reject = Vec::new();
                if pfc {
                    reject.push(LcpOpt::ProtocolFieldCompression.into());
                }
                if acfc {
                    reject.push(LcpOpt::AddrCtlFieldCompression.into());
                }

                PppPkt::new_lcp(LcpPkt::new_configure_reject(lcp.identifier, reject))
                    .serialize(ctl_w)?;
                ctl_w.flush()?;

                println!(
                    " -> lcp configure-reject {}, pfc: {} -> false, acfc: {} -> false",
                    lcp.identifier, pfc, acfc
                );
                return Ok(());
            }

            let mut state = state.lock().expect("ppp state mutex is poisoned");
            match *state {
                Ppp::Synchronize(identifier, mru, magic_number, attempt) => {
                    *state =
                        Ppp::SyncAck(identifier, mru, auth_proto.clone(), magic_number, attempt)
                }
                Ppp::SyncAck(..) => {} // Simply retransmit our previous ack.
                Ppp::SyncAcked(..) => *state = Ppp::Auth(auth_proto.clone(), 0),
                _ => {
                    println!(
                        " <- unexpected lcp configure-request {}, mru: {}, authentication: {:?}",
                        lcp.identifier, mru, auth_proto
                    );
                    return Ok(());
                }
            }

            PppPkt::new_lcp(LcpPkt::new_configure_ack(
                lcp.identifier,
                configure_request.options,
            ))
            .serialize(ctl_w)?;
            ctl_w.flush()?;

            println!(
                " <- lcp configure-request {}, mru: {}, authentication: {:?}",
                lcp.identifier, mru, auth_proto
            );
            println!(" -> lcp configure-ack {}", lcp.identifier);

            Ok(())
        }
        LcpData::ConfigureAck(configure_ack) => {
            let magic_number = configure_ack
                .options
                .iter()
                .find_map(|opt| {
                    if let LcpOpt::MagicNumber(magic_number) = opt.value {
                        Some(magic_number)
                    } else {
                        None
                    }
                })
                .expect("receive lcp configure-ack without magic number");

            let mut state = state.lock().expect("ppp state mutex is poisoned");
            match *state {
                Ppp::Synchronize(identifier, .., attempt) if lcp.identifier == identifier => {
                    *state = Ppp::SyncAcked(attempt)
                }
                Ppp::SyncAck(identifier, _, ref auth_proto, ..) if lcp.identifier == identifier => {
                    *state = Ppp::Auth(auth_proto.clone(), 0)
                }
                _ => {
                    println!(" <- unexpected lcp configure-ack {}", lcp.identifier);
                    return Ok(());
                }
            }

            *magic = magic_number;

            println!(" <- lcp configure-ack {}", lcp.identifier);
            Ok(())
        }
        LcpData::ConfigureNak(configure_nak) => {
            let mut mru = configure_nak.options.iter().find_map(|opt| {
                if let LcpOpt::Mru(mru) = opt.value {
                    Some(mru)
                } else {
                    None
                }
            });
            let magic_number = configure_nak.options.iter().find_map(|opt| {
                if let LcpOpt::MagicNumber(magic_number) = opt.value {
                    Some(magic_number)
                } else {
                    None
                }
            });

            if let Some(inner) = mru {
                if inner < 1492 {
                    mru = None;
                }
            }

            let mut state = state.lock().expect("ppp state mutex is poisoned");
            match *state {
                Ppp::Synchronize(identifier, old_mru, old_magic_number, attempt)
                    if lcp.identifier == identifier =>
                {
                    *state = Ppp::Synchronize(
                        identifier,
                        mru.unwrap_or(old_mru),
                        magic_number.unwrap_or(old_magic_number),
                        attempt,
                    )
                }
                Ppp::SyncAck(identifier, old_mru, ref auth_proto, old_magic_number, attempt)
                    if lcp.identifier == identifier =>
                {
                    *state = Ppp::SyncAck(
                        identifier,
                        mru.unwrap_or(old_mru),
                        auth_proto.clone(),
                        magic_number.unwrap_or(old_magic_number),
                        attempt,
                    )
                }
                _ => {
                    println!(" <- unexpected lcp configure-nak {}", lcp.identifier);
                    return Ok(());
                }
            }

            println!(" <- lcp configure-nak {}", lcp.identifier);
            Ok(())
        }
        LcpData::ConfigureReject(..) => {
            // None of our options can be unset.
            // Ignore the packet and let the negotiation time out.

            match *state.lock().expect("ppp state mutex is poisoned") {
                Ppp::Synchronize(..) => println!(" <- lcp configure-reject {}", lcp.identifier),
                Ppp::SyncAck(..) => println!(" <- lcp configure-reject {}", lcp.identifier),
                _ => println!(" <- unexpected lcp configure-reject {}", lcp.identifier),
            }

            Ok(())
        }
        LcpData::TerminateRequest(terminate_request) => {
            PppPkt::new_lcp(LcpPkt::new_terminate_ack(
                lcp.identifier,
                terminate_request.data.clone(),
            ))
            .serialize(ctl_w)?;
            ctl_w.flush()?;

            let reason = String::from_utf8(terminate_request.data.clone())
                .unwrap_or(format!("{:?}", terminate_request.data));

            println!(
                " <- lcp terminate-request {}, reason: {}",
                lcp.identifier, reason
            );
            println!(" -> lcp terminate-ack {}", lcp.identifier);

            Ok(())
        }
        LcpData::TerminateAck(..) => {
            let mut state = state.lock().expect("ppp state mutex is poisoned");
            match *state {
                Ppp::Terminate(ref reason, ..) => {
                    *state =
                        Ppp::Terminate2(String::from_utf8(reason.clone()).unwrap_or(String::new()))
                }
                _ => {
                    println!(" <- unexpected lcp terminate-ack {}", lcp.identifier);
                    return Ok(());
                }
            }

            println!(" <- lcp terminate-ack {}", lcp.identifier);
            Ok(())
        }
        LcpData::CodeReject(code_reject) => {
            // Should never happen.

            println!(
                " <- lcp code-reject {}, packet: {:?}",
                lcp.identifier, code_reject.pkt
            );
            Ok(())
        }
        LcpData::ProtocolReject(protocol_reject) => {
            // TODO: update ncp state to failed

            println!(
                " <- lcp protocol-reject {}, protocol: {}, packet: {:?}",
                lcp.identifier, protocol_reject.protocol, protocol_reject.pkt
            );
            Ok(())
        }
        LcpData::EchoRequest(echo_request) => {
            PppPkt::new_lcp(LcpPkt::new_echo_reply(
                lcp.identifier,
                *magic,
                echo_request.data.clone(),
            ))
            .serialize(ctl_w)?;
            ctl_w.flush()?;

            println!(
                " <- lcp echo-request {}, magic number: {}, data: {:?}",
                lcp.identifier, echo_request.magic, echo_request.data
            );
            println!(" -> lcp echo-reply {}", lcp.identifier);

            Ok(())
        }
        LcpData::EchoReply(echo_reply) => {
            // We don't ever send an Echo-Request
            // so the Echo-Reply will always be unexpected.

            println!(
                " <- unexpected lcp echo-reply {}, magic number: {}, data: {:?}",
                lcp.identifier, echo_reply.magic, echo_reply.data
            );
            Ok(())
        }
        LcpData::DiscardRequest(discard_request) => {
            println!(
                " <- lcp discard-request {}, magic number: {}, data: {:?}",
                lcp.identifier, discard_request.magic, discard_request.data
            );
            Ok(())
        }
    }
}

fn handle_pap(pap: PapPkt, state: Arc<Mutex<Ppp>>) -> Result<()> {
    match *state.lock().expect("ppp state mutex is poisoned") {
        Ppp::Auth(Some(AuthProto::Pap), ..) => {}
        _ => {
            println!(" <- unexpected pap");
            return Ok(());
        }
    }

    match pap.data {
        PapData::AuthenticateRequest(..) => {
            // We never ask the peer to authenticate itself
            // so an Authenticate-Request will always be unexpected.

            println!(" <- unexpected pap authenticate-request {}", pap.identifier);
            Ok(())
        }
        PapData::AuthenticateAck(authenticate_ack) => {
            *state.lock().expect("ppp state mutex is poisoned") = Ppp::Active;

            println!(
                " <- pap authenticate-ack {}, message: {}",
                pap.identifier, authenticate_ack.msg
            );
            Ok(())
        }
        PapData::AuthenticateNak(authenticate_nak) => {
            // The peer should terminate the session
            // which is already handled by LCP.

            println!(
                " <- pap authenticate-nak {}, reason: {}",
                pap.identifier, authenticate_nak.msg
            );
            Ok(())
        }
    }
}

fn handle_chap(chap: ChapPkt, ctl_w: &mut BufWriter<File>, state: Arc<Mutex<Ppp>>) -> Result<()> {
    let mut file = File::open("/data/pppoe.conf")?;
    let config: Config = serde_json::from_reader(&mut file)?;

    let algorithm = match *state.lock().expect("ppp state mutex is poisoned") {
        Ppp::Auth(Some(AuthProto::Chap(algo)), ..) => algo,
        _ => {
            println!(" <- unexpected chap");
            return Ok(());
        }
    };

    match chap.data {
        ChapData::Challenge(chap_challenge) => {
            let mut hash_input = Vec::new();

            hash_input.push(chap.identifier);
            hash_input.extend_from_slice(config.password.as_bytes());
            hash_input.extend_from_slice(&chap_challenge.value);

            let challenge_hash = match algorithm {
                ChapAlgorithm::Md5 => *md5::compute(hash_input),
            };

            PppPkt::new_chap(ChapPkt::new_response(
                chap.identifier,
                challenge_hash.to_vec(),
                config.username.clone(),
            ))
            .serialize(ctl_w)?;
            ctl_w.flush()?;

            println!(
                " <- chap challenge {}, name: {}, value: {:?}",
                chap.identifier, chap_challenge.name, chap_challenge.value
            );
            println!(
                " -> chap response {}, name: {}, value: {:?}",
                chap.identifier, config.username, challenge_hash
            );

            Ok(())
        }
        ChapData::Response(chap_response) => {
            // We never ask the peer to authenticate itself
            // so a Response will always be unexpected.

            println!(
                " <- unexpected chap response {}, name: {}, value: {:?}",
                chap.identifier, chap_response.name, chap_response.value
            );
            Ok(())
        }
        ChapData::Success(chap_success) => {
            *state.lock().expect("ppp state mutex is poisoned") = Ppp::Active;

            println!(
                " <- chap success {}, message: {}",
                chap.identifier, chap_success.message
            );
            Ok(())
        }
        ChapData::Failure(chap_failure) => {
            // The peer should terminate the session
            // which is already handled by LCP.

            println!(
                " <- chap failure {}, reason: {}",
                chap.identifier, chap_failure.message
            );
            Ok(())
        }
    }
}

fn ipcp(
    ctl: File,
    states: Arc<Mutex<HashMap<Network, Ncp>>>,
    config: Arc<Mutex<Ipv4Config>>,
) -> Result<()> {
    let mut ctl_w = BufWriter::with_capacity(1500, ctl);

    {
        let mut config = config.lock().expect("ipv4 config mutex is poisoned");

        config.addr = Ipv4Addr::UNSPECIFIED;
        config.dns1 = Ipv4Addr::UNSPECIFIED;
        config.dns2 = Ipv4Addr::UNSPECIFIED;
    }

    loop {
        {
            let config = config.lock().expect("ipv4 config mutex is poisoned");

            let mut states = states.lock().expect("ncp state mutex is poisoned");
            match states[&Network::Ipv4] {
                Ncp::Dead => {}
                Ncp::Configure(identifier, attempt) => {
                    if attempt >= MAX_ATTEMPTS {
                        *states.get_mut(&Network::Ipv4).expect("no ipv4 state") = Ncp::Failed;
                        continue;
                    }

                    PppPkt::new_ipcp(IpcpPkt::new_configure_request(
                        identifier,
                        vec![
                            IpcpOpt::IpAddr(config.addr.into()).into(),
                            IpcpOpt::PrimaryDns(config.dns1.into()).into(),
                            IpcpOpt::SecondaryDns(config.dns2.into()).into(),
                        ],
                    ))
                    .serialize(&mut ctl_w)?;
                    ctl_w.flush()?;

                    *states.get_mut(&Network::Ipv4).expect("no ipv4 state") =
                        Ncp::Configure(identifier, attempt + 1);

                    println!(
                        " -> ipcp configure-request {}/{}, address: {}, dns1: {}, dns2: {}",
                        attempt, MAX_ATTEMPTS, config.addr, config.dns1, config.dns2
                    );
                }
                Ncp::ConfAck(identifier, attempt) => {
                    if attempt >= MAX_ATTEMPTS {
                        *states.get_mut(&Network::Ipv4).expect("no ipv4 state") = Ncp::Failed;
                        continue;
                    }

                    PppPkt::new_ipcp(IpcpPkt::new_configure_request(
                        identifier,
                        vec![
                            IpcpOpt::IpAddr(config.addr.into()).into(),
                            IpcpOpt::PrimaryDns(config.dns1.into()).into(),
                            IpcpOpt::SecondaryDns(config.dns2.into()).into(),
                        ],
                    ))
                    .serialize(&mut ctl_w)?;
                    ctl_w.flush()?;

                    *states.get_mut(&Network::Ipv4).expect("no ipv4 state") =
                        Ncp::ConfAck(identifier, attempt + 1);

                    println!(
                        " -> ipcp configure-request {}/{}, address: {}, dns1: {}, dns2: {}",
                        attempt, MAX_ATTEMPTS, config.addr, config.dns1, config.dns2
                    );
                }
                Ncp::ConfAcked(attempt) => {
                    // Packet handler takes care of the rest.

                    if attempt >= MAX_ATTEMPTS {
                        *states.get_mut(&Network::Ipv4).expect("no ipv4 state") = Ncp::Failed;
                        continue;
                    }

                    *states.get_mut(&Network::Ipv4).expect("no ipv4 state") =
                        Ncp::ConfAcked(attempt + 1);
                }
                Ncp::Active => {}
                Ncp::Failed => {}
            }
        }

        thread::sleep(PPPOE_XMIT_INTERVAL);
    }
}

fn ipv6cp(
    ctl: File,
    states: Arc<Mutex<HashMap<Network, Ncp>>>,
    config: Arc<Mutex<Ipv6Config>>,
) -> Result<()> {
    let mut ctl_w = BufWriter::with_capacity(1500, ctl);

    {
        let mut config = config.lock().expect("ipv6 config mutex is poisoned");

        config.laddr = ll(rand::random());
        config.raddr = Ipv6Addr::UNSPECIFIED;
    }

    loop {
        {
            let config = config.lock().expect("ipv6 config mutex is poisoned");

            let mut states = states.lock().expect("ncp state mutex is poisoned");
            match states[&Network::Ipv6] {
                Ncp::Dead => {}
                Ncp::Configure(identifier, attempt) => {
                    if attempt >= MAX_ATTEMPTS {
                        *states.get_mut(&Network::Ipv6).expect("no ipv6 state") = Ncp::Failed;
                        continue;
                    }

                    PppPkt::new_ipv6cp(Ipv6cpPkt::new_configure_request(
                        identifier,
                        vec![Ipv6cpOpt::InterfaceId(ifid(config.laddr)).into()],
                    ))
                    .serialize(&mut ctl_w)?;
                    ctl_w.flush()?;

                    *states.get_mut(&Network::Ipv6).expect("no ipv6 state") =
                        Ncp::Configure(identifier, attempt + 1);

                    println!(
                        " -> ipv6cp configure-request {}/{}, address: {}",
                        attempt, MAX_ATTEMPTS, config.laddr
                    );
                }
                Ncp::ConfAck(identifier, attempt) => {
                    if attempt >= MAX_ATTEMPTS {
                        *states.get_mut(&Network::Ipv6).expect("no ipv6 state") = Ncp::Failed;
                        continue;
                    }

                    PppPkt::new_ipv6cp(Ipv6cpPkt::new_configure_request(
                        identifier,
                        vec![Ipv6cpOpt::InterfaceId(ifid(config.laddr)).into()],
                    ))
                    .serialize(&mut ctl_w)?;
                    ctl_w.flush()?;

                    *states.get_mut(&Network::Ipv6).expect("no ipv6 state") =
                        Ncp::ConfAck(identifier, attempt + 1);

                    println!(
                        " -> ipv6cp configure-request {}/{}, address: {}",
                        attempt, MAX_ATTEMPTS, config.laddr
                    );
                }
                Ncp::ConfAcked(attempt) => {
                    // Packet handler takes care of the rest.

                    if attempt >= MAX_ATTEMPTS {
                        *states.get_mut(&Network::Ipv6).expect("no ipv6 state") = Ncp::Failed;
                        continue;
                    }

                    *states.get_mut(&Network::Ipv6).expect("no ipv6 state") =
                        Ncp::ConfAcked(attempt + 1);
                }
                Ncp::Active => {}
                Ncp::Failed => {}
            }
        }

        thread::sleep(PPPOE_XMIT_INTERVAL);
    }
}

fn handle_ipcp(
    ipcp: IpcpPkt,
    ppp_w: &mut BufWriter<File>,
    state: Arc<Mutex<Ppp>>,
    ncp_states: Arc<Mutex<HashMap<Network, Ncp>>>,
    config: Arc<Mutex<Ipv4Config>>,
) -> Result<()> {
    if *state.lock().expect("ppp state mutex is poisoned") != Ppp::Active {
        println!(" <- unexpected ipcp");
        return Ok(());
    }

    match ipcp.data {
        IpcpData::ConfigureRequest(configure_request) => {
            let compression = configure_request.options.iter().find_map(|opt| {
                if let IpcpOpt::IpCompressionProtocol(compression) = &opt.value {
                    Some(compression)
                } else {
                    None
                }
            });

            if let Some(compression) = compression {
                PppPkt::new_ipcp(IpcpPkt::new_configure_reject(
                    ipcp.identifier,
                    vec![IpcpOpt::IpCompressionProtocol(compression.clone()).into()],
                ))
                .serialize(ppp_w)?;
                ppp_w.flush()?;

                println!(
                    " -> ipcp configure-reject {}, compression: {:?} -> None",
                    ipcp.identifier, compression
                );
                return Ok(());
            }

            let mut ncp_states = ncp_states.lock().expect("ncp state mutex is poisoned");
            match ncp_states[&Network::Ipv4] {
                Ncp::Dead => return Ok(()), // If peer sends a request before we do it's not unexpected.
                Ncp::Configure(identifier, attempt) => {
                    *ncp_states.get_mut(&Network::Ipv4).expect("no ipv4 state") =
                        Ncp::ConfAck(identifier, attempt)
                }
                Ncp::ConfAck(..) => {} // Simply retransmit our previous ack.
                Ncp::ConfAcked(..) => {
                    *ncp_states.get_mut(&Network::Ipv4).expect("no ipv4 state") = Ncp::Active
                }
                _ => {
                    println!(" <- unexpected ipcp configure-request {}", ipcp.identifier);
                    return Ok(());
                }
            }

            PppPkt::new_ipcp(IpcpPkt::new_configure_ack(
                ipcp.identifier,
                configure_request.options,
            ))
            .serialize(ppp_w)?;
            ppp_w.flush()?;

            println!(" <- ipcp configure-request {}", ipcp.identifier);
            println!(" -> ipcp configure-ack {}", ipcp.identifier);

            Ok(())
        }
        IpcpData::ConfigureAck(..) => {
            let mut ncp_states = ncp_states.lock().expect("ncp state mutex is poisoned");
            match ncp_states[&Network::Ipv4] {
                Ncp::Configure(identifier, attempt) if ipcp.identifier == identifier => {
                    *ncp_states.get_mut(&Network::Ipv4).expect("no ipv4 state") =
                        Ncp::ConfAcked(attempt)
                }
                Ncp::ConfAck(identifier, ..) if ipcp.identifier == identifier => {
                    *ncp_states.get_mut(&Network::Ipv4).expect("no ipv4 state") = Ncp::Active
                }
                _ => {
                    println!(" <- unexpected ipcp configure-ack {}", ipcp.identifier);
                    return Ok(());
                }
            }

            println!(" <- ipcp configure-ack {}", ipcp.identifier);
            Ok(())
        }
        IpcpData::ConfigureNak(configure_nak) => {
            let mut config = config.lock().expect("ipv4 config mutex is poisoned");

            let addr = configure_nak
                .options
                .iter()
                .find_map(|opt| {
                    if let IpcpOpt::IpAddr(addr) = &opt.value {
                        Some(addr.0)
                    } else {
                        None
                    }
                })
                .expect("receive ipcp configure-nak without ipv4 address");
            let dns1 = configure_nak
                .options
                .iter()
                .find_map(|opt| {
                    if let IpcpOpt::PrimaryDns(dns1) = &opt.value {
                        Some(dns1.0)
                    } else {
                        None
                    }
                })
                .unwrap_or(config.dns1);
            let dns2 = configure_nak
                .options
                .iter()
                .find_map(|opt| {
                    if let IpcpOpt::SecondaryDns(dns2) = &opt.value {
                        Some(dns2.0)
                    } else {
                        None
                    }
                })
                .unwrap_or(config.dns2);

            match ncp_states.lock().expect("ncp state mutex is poisoned")[&Network::Ipv4] {
                Ncp::Configure(identifier, ..) if ipcp.identifier == identifier => {}
                Ncp::ConfAck(identifier, ..) if ipcp.identifier == identifier => {}
                _ => {
                    println!(" <- unexpected ipcp configure-nak {}", ipcp.identifier);
                    return Ok(());
                }
            }

            config.addr = addr;
            config.dns1 = dns1;
            config.dns2 = dns2;

            PppPkt::new_ipcp(IpcpPkt::new_configure_request(
                ipcp.identifier,
                vec![
                    IpcpOpt::IpAddr(addr.into()).into(),
                    IpcpOpt::PrimaryDns(dns1.into()).into(),
                    IpcpOpt::SecondaryDns(dns2.into()).into(),
                ],
            ))
            .serialize(ppp_w)?;
            ppp_w.flush()?;

            println!(" <- ipcp configure-nak {}", ipcp.identifier);
            println!(
                " -> ipcp configure-request {}, address: {}, dns1: {}, dns2: {}",
                ipcp.identifier, addr, dns1, dns2
            );

            Ok(())
        }
        IpcpData::ConfigureReject(..) => {
            // None of our options can be unset.
            // Ignore the packet and let the negotiation time out.

            match ncp_states.lock().expect("ncp state mutex is poisoned")[&Network::Ipv4] {
                Ncp::Configure(..) => println!(" <- ipcp configure-reject {}", ipcp.identifier),
                Ncp::ConfAck(..) => println!(" <- ipcp configure-reject {}", ipcp.identifier),
                _ => println!(" <- unexpected ipcp configure-reject {}", ipcp.identifier),
            }

            Ok(())
        }
        IpcpData::TerminateRequest(terminate_request) => {
            *ncp_states
                .lock()
                .expect("ncp state mutex is poisoned")
                .get_mut(&Network::Ipv4)
                .expect("no ipv4 state") = Ncp::Dead;

            PppPkt::new_ipcp(IpcpPkt::new_terminate_ack(
                ipcp.identifier,
                terminate_request.data.clone(),
            ))
            .serialize(ppp_w)?;
            ppp_w.flush()?;

            let reason = String::from_utf8(terminate_request.data.clone())
                .unwrap_or(format!("{:?}", terminate_request.data));

            println!(
                " <- ipcp terminate-request {}, reason: {}",
                ipcp.identifier, reason
            );
            println!(" -> ipcp terminate-ack {}", ipcp.identifier);

            Ok(())
        }
        IpcpData::TerminateAck(..) => {
            // We never terminate NCPs
            // so a Terminate-Ack will always be unexpected.

            println!(" <- unexpected lcp terminate-ack {}", ipcp.identifier);
            Ok(())
        }
        IpcpData::CodeReject(code_reject) => {
            // Should never happen.

            println!(
                " <- ipcp code-reject {}, packet: {:?}",
                ipcp.identifier, code_reject.pkt
            );
            Ok(())
        }
    }
}

fn handle_ipv6cp(
    ipv6cp: Ipv6cpPkt,
    ppp_w: &mut BufWriter<File>,
    state: Arc<Mutex<Ppp>>,
    ncp_states: Arc<Mutex<HashMap<Network, Ncp>>>,
    config: Arc<Mutex<Ipv6Config>>,
) -> Result<()> {
    if *state.lock().expect("ppp state mutex is poisoned") != Ppp::Active {
        println!(" <- unexpected ipv6cp");
        return Ok(());
    }

    match ipv6cp.data {
        Ipv6cpData::ConfigureRequest(configure_request) => {
            let if_id = configure_request
                .options
                .iter()
                .map(|opt| {
                    let Ipv6cpOpt::InterfaceId(if_id) = &opt.value;
                    *if_id
                })
                .next()
                .expect("receive ipv6cp configure-request without ipv6 interface identifier");

            let mut ncp_states = ncp_states.lock().expect("ncp state mutex is poisoned");
            match ncp_states[&Network::Ipv6] {
                Ncp::Dead => return Ok(()), // If peer sends a request before we do it's not unexpected.
                Ncp::Configure(identifier, attempt) => {
                    *ncp_states.get_mut(&Network::Ipv6).expect("no ipv6 state") =
                        Ncp::ConfAck(identifier, attempt)
                }
                Ncp::ConfAck(..) => {} // Simply retransmit our previous ack.
                Ncp::ConfAcked(..) => {
                    *ncp_states.get_mut(&Network::Ipv6).expect("no ipv6 state") = Ncp::Active
                }
                _ => {
                    println!(
                        " <- unexpected ipv6cp configure-request {}",
                        ipv6cp.identifier
                    );
                    return Ok(());
                }
            }

            PppPkt::new_ipv6cp(Ipv6cpPkt::new_configure_ack(
                ipv6cp.identifier,
                configure_request.options,
            ))
            .serialize(ppp_w)?;
            ppp_w.flush()?;

            let addr = ll(if_id);
            config.lock().expect("ipv6 config mutex is poisoned").raddr = addr;

            println!(
                " <- ipv6cp configure-request {}, address: {}",
                ipv6cp.identifier, addr
            );
            println!(" -> ipv6cp configure-ack {}", ipv6cp.identifier);

            Ok(())
        }
        Ipv6cpData::ConfigureAck(configure_ack) => {
            let if_id = configure_ack
                .options
                .iter()
                .map(|opt| {
                    let Ipv6cpOpt::InterfaceId(if_id) = &opt.value;
                    *if_id
                })
                .next()
                .expect("receive ipv6cp configure-ack without ipv6 interface identifier");

            let mut ncp_states = ncp_states.lock().expect("ncp state mutex is poisoned");
            match ncp_states[&Network::Ipv6] {
                Ncp::Configure(identifier, attempt) if ipv6cp.identifier == identifier => {
                    *ncp_states.get_mut(&Network::Ipv6).expect("no ipv6 state") =
                        Ncp::ConfAcked(attempt)
                }
                Ncp::ConfAck(identifier, ..) if ipv6cp.identifier == identifier => {
                    *ncp_states.get_mut(&Network::Ipv6).expect("no ipv6 state") = Ncp::Active
                }
                _ => {
                    println!(" <- unexpected ipv6cp configure-ack {}", ipv6cp.identifier);
                    return Ok(());
                }
            }

            let addr = ll(if_id);
            config.lock().expect("ipv6 config mutex is poisoned").laddr = addr;

            println!(" <- ipv6cp configure-ack {}", ipv6cp.identifier);
            Ok(())
        }
        Ipv6cpData::ConfigureNak(configure_nak) => {
            let if_id = configure_nak
                .options
                .iter()
                .map(|opt| {
                    let Ipv6cpOpt::InterfaceId(if_id) = &opt.value;
                    *if_id
                })
                .next()
                .expect("receive ipv6cp configure-nak without ipv6 interface identifier");

            let ncp_states = ncp_states.lock().expect("ncp state mutex is poisoned");
            match ncp_states[&Network::Ipv6] {
                Ncp::Configure(identifier, ..) if ipv6cp.identifier == identifier => {}
                Ncp::ConfAck(identifier, ..) if ipv6cp.identifier == identifier => {}
                _ => {
                    println!(" <- unexpected ipv6cp configure-nak {}", ipv6cp.identifier);
                    return Ok(());
                }
            }

            let addr = ll(if_id);
            config.lock().expect("ipv6 config mutex is poisoned").laddr = addr;

            PppPkt::new_ipv6cp(Ipv6cpPkt::new_configure_request(
                ipv6cp.identifier,
                vec![Ipv6cpOpt::InterfaceId(if_id).into()],
            ))
            .serialize(ppp_w)?;
            ppp_w.flush()?;

            println!(" <- ipv6cp configure-nak {}", ipv6cp.identifier);
            println!(
                " -> ipv6cp configure-request {}, address: {}",
                ipv6cp.identifier, addr
            );

            Ok(())
        }
        Ipv6cpData::ConfigureReject(..) => {
            // None of our options can be unset.
            // Ignore the packet and let the negotiation time out.

            match ncp_states.lock().expect("ncp state mutex is poisoned")[&Network::Ipv6] {
                Ncp::Configure(..) => println!(" <- ipv6cp configure-reject {}", ipv6cp.identifier),
                Ncp::ConfAck(..) => println!(" <- ipv6cp configure-reject {}", ipv6cp.identifier),
                _ => println!(
                    " <- unexpected ipv6cp configure-reject {}",
                    ipv6cp.identifier
                ),
            }

            Ok(())
        }
        Ipv6cpData::TerminateRequest(terminate_request) => {
            *ncp_states
                .lock()
                .expect("ncp state mutex is poisoned")
                .get_mut(&Network::Ipv6)
                .expect("no ipv6 state") = Ncp::Dead;

            PppPkt::new_ipv6cp(Ipv6cpPkt::new_terminate_ack(
                ipv6cp.identifier,
                terminate_request.data.clone(),
            ))
            .serialize(ppp_w)?;
            ppp_w.flush()?;

            let reason = String::from_utf8(terminate_request.data.clone())
                .unwrap_or(format!("{:?}", terminate_request.data));

            println!(
                " <- ipv6cp terminate-request {}, reason: {}",
                ipv6cp.identifier, reason
            );
            println!(" -> ipv6cp terminate-ack {}", ipv6cp.identifier);

            Ok(())
        }
        Ipv6cpData::TerminateAck(..) => {
            // We never terminate NCPs
            // so a Terminate-Ack will always be unexpected.

            println!(" <- unexpected lcp terminate-ack {}", ipv6cp.identifier);
            Ok(())
        }
        Ipv6cpData::CodeReject(code_reject) => {
            // Should never happen.

            println!(
                " <- ipv6cp code-reject {}, packet: {:?}",
                ipv6cp.identifier, code_reject.pkt
            );
            Ok(())
        }
    }
}
