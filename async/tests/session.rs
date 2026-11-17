//! Session tests, client and server over a tokio duplex
#![cfg(all(feature = "tokio", feature = "std"))]

use std::cell::RefCell;
use std::time::Duration;

use sunset::{
    ChanHandle, CliEvent, CliSessionExit, KeyType, Pty, PubKey, ServEvent, SignKey,
    WinChange,
};
use sunset_async::embedded_io_async::{Read, Write};
use sunset_async::{ProgressHolder, SSHClient, SSHServer};
use tokio::sync::mpsc::unbounded_channel;

/// One more than MAX_CHANNELS, the last fails if channels aren't freed
const SESSIONS: usize = sunset::config::MAX_CHANNELS + 1;

/// Sessions with an RSA login, pty, resize and exit status,
/// each closed by the server.
#[tokio::test]
async fn server_sessions_size_resize_exit_and_close() {
    let (client_io, server_io) = tokio::io::duplex(1 << 16);
    let (mut client_read, mut client_write) = tokio::io::split(client_io);
    let (mut server_read, mut server_write) = tokio::io::split(server_io);

    let host = SignKey::generate(KeyType::Ed25519, None).unwrap();
    let user = SignKey::generate(KeyType::RSA, Some(2048)).unwrap();

    let server = SSHServer::new_owned();
    let client = SSHClient::new_owned();

    let ptys = RefCell::new(Vec::new());
    let exits = RefCell::new(Vec::new());
    let (shells, mut shell) = unbounded_channel::<ChanHandle>();
    let (resizes, mut resized) = unbounded_channel::<(u32, u32)>();
    let (authenticated, mut authed) = unbounded_channel::<()>();
    let (opens, mut opened) = unbounded_channel::<()>();

    let server_events = async {
        let mut accepted: Vec<ChanHandle> = Vec::new();
        loop {
            let mut ph = ProgressHolder::new();
            match server.progress(&mut ph).await.unwrap() {
                ServEvent::Hostkeys(r) => r.hostkeys(&[&host]).unwrap(),
                ServEvent::FirstAuth(mut r) => {
                    r.enable_password_auth(false).unwrap();
                    r.enable_pubkey_auth(true).unwrap();
                }
                ServEvent::PubkeyAuth(r) => {
                    assert!(matches!(r.pubkey().unwrap(), PubKey::RSA(_)));
                    r.allow().unwrap()
                }
                ServEvent::OpenSession(r) => accepted.push(r.accept().unwrap()),
                ServEvent::SessionPty(r) => {
                    let size = r.size().unwrap();
                    ptys.borrow_mut().push((
                        r.term().unwrap().to_string(),
                        size.cols,
                        size.rows,
                    ));
                    r.succeed().unwrap()
                }
                ServEvent::SessionShell(r) => {
                    let num = r.channel();
                    r.succeed().unwrap();
                    let at = accepted.iter().position(|h| h.num() == num).unwrap();
                    shells.send(accepted.remove(at)).unwrap();
                }
                ServEvent::SessionWinChange(r) => {
                    let size = r.size().unwrap();
                    resizes.send((size.cols, size.rows)).unwrap();
                }
                ServEvent::Defunct => return,
                _ => {}
            }
        }
    };

    let server_sessions = async {
        for session in 0..SESSIONS {
            let mut io = server.stdio(shell.recv().await.unwrap()).await.unwrap();
            let (cols, rows) = resized.recv().await.unwrap();
            io.write_all(format!("{cols}x{rows}").as_bytes()).await.unwrap();
            io.exit_status(session as u32).await.unwrap();
            io.close_channel().await.unwrap();
        }
    };

    let client_events = async {
        let mut offered = false;
        loop {
            let mut ph = ProgressHolder::new();
            match client.progress(&mut ph).await.unwrap() {
                CliEvent::Hostkey(r) => r.accept().unwrap(),
                CliEvent::Username(r) => r.username("miner").unwrap(),
                CliEvent::Pubkey(r) if !offered => {
                    offered = true;
                    r.pubkey(user.clone()).unwrap()
                }
                CliEvent::Pubkey(r) => r.skip().unwrap(),
                CliEvent::Password(r) => r.skip().unwrap(),
                CliEvent::Authenticated => authenticated.send(()).unwrap(),
                CliEvent::SessionOpened(mut o) => {
                    o.pty(Pty {
                        term: "xterm-256color".try_into().unwrap(),
                        cols: 120,
                        rows: 40,
                        width: 0,
                        height: 0,
                        modes: Default::default(),
                    })
                    .unwrap();
                    o.shell().unwrap();
                    opens.send(()).unwrap();
                }
                CliEvent::SessionExit(CliSessionExit::Status(status)) => {
                    exits.borrow_mut().push(status)
                }
                CliEvent::Defunct => return,
                _ => {}
            }
        }
    };

    let client_sessions = async {
        authed.recv().await.unwrap();
        for session in 0..SESSIONS as u32 {
            let mut io = client.open_session_pty().await.unwrap();
            opened.recv().await.unwrap();
            io.term_window_change(WinChange {
                cols: 100 + session,
                rows: 30,
                width: 0,
                height: 0,
            })
            .await
            .unwrap();

            let mut got = Vec::new();
            let mut buf = [0u8; 64];
            loop {
                match io.read(&mut buf).await.unwrap() {
                    0 => break,
                    n => got.extend_from_slice(&buf[..n]),
                }
            }
            assert_eq!(
                String::from_utf8(got).unwrap(),
                format!("{}x30", 100 + session)
            );
            io.until_closed().await.unwrap();
        }
    };

    let ran = tokio::time::timeout(Duration::from_secs(20), async {
        tokio::select! {
            _ = async { tokio::join!(server_sessions, client_sessions) } => {}
            r = server.run_tokio(&mut server_read, &mut server_write) => panic!("server stopped: {r:?}"),
            r = client.run_tokio(&mut client_read, &mut client_write) => panic!("client stopped: {r:?}"),
            _ = server_events => panic!("server events ended"),
            _ = client_events => panic!("client events ended"),
        }
    })
    .await;
    assert!(ran.is_ok(), "timed out");

    assert_eq!(
        *ptys.borrow(),
        vec![("xterm-256color".to_string(), 120, 40); SESSIONS]
    );
    assert_eq!(*exits.borrow(), (0..SESSIONS as u32).collect::<Vec<_>>());
}
