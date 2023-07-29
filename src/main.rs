use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use ppproperly::{
    AuthProto, Deserialize, LcpData, LcpOpt, LcpPkt, MacAddr, PapPkt, PppData, PppPkt, PppoeData,
    PppoePkt, PppoeVal, Serialize,
};
use rsdsl_netlinkd::link;
use rsdsl_pppoe2::{Ppp, Pppoe, Result};
use rsdsl_pppoe2_sys::{new_discovery_socket, new_session};
use socket2::Socket;

const PPPOE_UPLINK: &str = "eth1";
const USERNAME: &str = "foo";
const PASSWORD: &str = "bar";

const MAX_ATTEMPTS: usize = 10;
const MAX_STATUS_ATTEMPTS: usize = 2;

static PPPOE_XMIT_INTERVAL: Duration = Duration::from_secs(3);
static SESSION_INIT_GRACE_PERIOD: Duration = Duration::from_secs(1);

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
                }

                println!(" <- [{}] padt, error: {}", pkt.src_mac, generic_error);
            }
            _ => println!(" <- [{}] unsupported pkt {:?}", pkt.src_mac, pkt),
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
    let mut sock_disc_w = BufWriter::with_capacity(1500, sock_disc);

    let (_sock_sess, ctl, _ppp) = new_session(interface, remote_mac, session_id)?;
    let mut ctl_w = BufWriter::with_capacity(1500, ctl.try_clone()?);

    let ppp_state = Arc::new(Mutex::new(Ppp::default()));

    let ppp_state2 = ppp_state.clone();
    let recv_sess = thread::spawn(move || match recv_session(ctl, ppp_state2.clone()) {
        Ok(_) => Ok(()),
        Err(e) => {
            *ppp_state2.lock().expect("ppp state mutex is poisoned") = Ppp::Err;
            Err(e)
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
                                USERNAME.into(),
                                PASSWORD.into(),
                            ))
                            .serialize(&mut ctl_w)?;
                            ctl_w.flush()?;
                        }
                        Some(AuthProto::Chap(_)) => {} // Packet handler takes care of this.
                    }

                    *ppp_state = Ppp::Auth(auth_proto.clone(), attempt + 1);
                }
                Ppp::Active => {}
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
                    return Err(recv_sess
                        .join()
                        .expect("recv_session panic")
                        .expect_err("Ppp::Err state entered without an error"));
                }
            }
        }

        thread::sleep(PPPOE_XMIT_INTERVAL);
    }

    Ok(())
}

fn recv_session(ctl: File, state: Arc<Mutex<Ppp>>) -> Result<()> {
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
            _ => println!(" <- unhandled ppp {:?}", ppp),
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
                    *state = Ppp::SyncAck(identifier, mru, None, magic_number, attempt)
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
                .expect("receive configure-ack without magic number");

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
