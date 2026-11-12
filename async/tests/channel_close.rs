//! Channel close tests, client and server over a tokio duplex
#![cfg(all(feature = "tokio", feature = "std"))]

use std::future::Future;
use std::time::Duration;

use sunset::{ChanHandle, CliEvent, KeyType, ServEvent, SignKey};
use sunset_async::embedded_io_async::{Read, Write};
use sunset_async::{ChanInOut, ProgressHolder, SSHClient, SSHServer};
use tokio::sync::mpsc::{UnboundedSender, unbounded_channel};

/// Run a client and server until `body` completes.
///
/// Accepted shell channels are sent to `shells`. `authed` and `opened`
/// are signalled after client authentication and session open.
async fn run(
    server: &SSHServer<'_>,
    client: &SSHClient<'_>,
    shells: UnboundedSender<ChanHandle>,
    authed: UnboundedSender<()>,
    opened: UnboundedSender<()>,
    body: impl Future<Output = ()>,
) {
    let (client_io, server_io) = tokio::io::duplex(1 << 16);
    let (mut client_read, mut client_write) = tokio::io::split(client_io);
    let (mut server_read, mut server_write) = tokio::io::split(server_io);
    let host = SignKey::generate(KeyType::Ed25519, None).unwrap();

    let server_events = async {
        let mut accepted: Vec<ChanHandle> = Vec::new();
        loop {
            let mut ph = ProgressHolder::new();
            match server.progress(&mut ph).await.unwrap() {
                ServEvent::Hostkeys(r) => r.hostkeys(&[&host]).unwrap(),
                ServEvent::FirstAuth(mut r) => {
                    r.enable_password_auth(true).unwrap();
                    r.enable_pubkey_auth(false).unwrap();
                }
                ServEvent::PasswordAuth(r) => r.allow().unwrap(),
                ServEvent::OpenSession(r) => accepted.push(r.accept().unwrap()),
                ServEvent::SessionShell(r) => {
                    let num = r.channel();
                    r.succeed().unwrap();
                    let at = accepted.iter().position(|h| h.num() == num).unwrap();
                    shells.send(accepted.remove(at)).unwrap();
                }
                ServEvent::Defunct => return,
                _ => {}
            }
        }
    };

    let client_events = async {
        loop {
            let mut ph = ProgressHolder::new();
            match client.progress(&mut ph).await.unwrap() {
                CliEvent::Hostkey(r) => r.accept().unwrap(),
                CliEvent::Username(r) => r.username("user").unwrap(),
                CliEvent::Pubkey(r) => r.skip().unwrap(),
                CliEvent::Password(r) => r.password("pw").unwrap(),
                CliEvent::Authenticated => authed.send(()).unwrap(),
                CliEvent::SessionOpened(mut o) => {
                    o.shell().unwrap();
                    opened.send(()).unwrap();
                }
                CliEvent::Defunct => return,
                _ => {}
            }
        }
    };

    let ran = tokio::time::timeout(Duration::from_secs(20), async {
        tokio::select! {
            _ = body => {}
            r = server.run_tokio(&mut server_read, &mut server_write) => panic!("server stopped: {r:?}"),
            r = client.run_tokio(&mut client_read, &mut client_write) => panic!("client stopped: {r:?}"),
            _ = server_events => panic!("server events ended"),
            _ = client_events => panic!("client events ended"),
        }
    })
    .await;
    assert!(ran.is_ok(), "timed out");
}

/// Read until EOF
async fn read_to_eof(io: &mut ChanInOut<'_>) -> Vec<u8> {
    let mut got = Vec::new();
    let mut buf = [0u8; 64];
    loop {
        match io.read(&mut buf).await.unwrap() {
            0 => return got,
            n => got.extend_from_slice(&buf[..n]),
        }
    }
}

/// Dropping a channel closes it, and closed channels are freed.
///
/// Runs MAX_CHANNELS + 1 sessions, the last fails if channels aren't freed.
#[tokio::test]
async fn dropped_channels_close_and_free() {
    const SESSIONS: usize = sunset::config::MAX_CHANNELS + 1;

    let server = SSHServer::new_owned();
    let client = SSHClient::new_owned();
    let (shells, mut shell) = unbounded_channel();
    let (authed, mut authed_rx) = unbounded_channel();
    let (opened, mut opened_rx) = unbounded_channel();

    let server_sessions = async {
        for _ in 0..SESSIONS {
            let mut io = server.stdio(shell.recv().await.unwrap()).await.unwrap();
            io.write_all(b"hi").await.unwrap();
            // drop closes the channel
        }
    };

    let client_sessions = async {
        authed_rx.recv().await.unwrap();
        for _ in 0..SESSIONS {
            let (mut io, _ext) = client.open_session_nopty().await.unwrap();
            opened_rx.recv().await.unwrap();
            assert_eq!(read_to_eof(&mut io).await, b"hi");
            io.until_closed().await.unwrap();
        }
    };

    let body = async {
        tokio::join!(server_sessions, client_sessions);
    };
    run(&server, &client, shells, authed, opened, body).await;
}

/// close_channel() with the handle kept, writes fail afterwards.
#[tokio::test]
async fn close_channel_with_handle() {
    let server = SSHServer::new_owned();
    let client = SSHClient::new_owned();
    let (shells, mut shell) = unbounded_channel();
    let (authed, mut authed_rx) = unbounded_channel();
    let (opened, mut opened_rx) = unbounded_channel();

    let server_session = async {
        let mut io = server.stdio(shell.recv().await.unwrap()).await.unwrap();
        io.write_all(b"bye").await.unwrap();
        io.close_channel().await.unwrap();
        assert!(io.write(b"more").await.is_err());
        io.until_closed().await.unwrap();
    };

    let client_session = async {
        authed_rx.recv().await.unwrap();
        let (mut io, _ext) = client.open_session_nopty().await.unwrap();
        opened_rx.recv().await.unwrap();
        assert_eq!(read_to_eof(&mut io).await, b"bye");
        io.until_closed().await.unwrap();
    };

    let body = async {
        tokio::join!(server_session, client_session);
    };
    run(&server, &client, shells, authed, opened, body).await;
}
