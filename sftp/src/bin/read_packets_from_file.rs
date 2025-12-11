use std::fs::File;
use std::io::{BufRead, BufReader};
use std::env;

use sunset_sftp::SftpSource;
use sunset_sftp::protocol::{NameEntry, SftpPacket};
use sunset::sshwire::{SSHDecode, SSHSource};
/// This program reads packets from a specified file and prints their byte representation.
/// 
/// We assume that each line contains an u8. a way to get this format is to use the 
/// `demo/sftp/std/testing/extract_txrx.sh` on a sunset-demo-sftp-std log file.
/// 
/// # Usage
/// ```
/// cargo run --package sunset-sftp --bin read_packets_from_file <file_path> 
/// ```
/// where `<file_path>` is the path to the file containing the packets.
/// 
fn main() {
    
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        eprintln!("Usage: {} <file_path>", args[0]);
        std::process::exit(1);
    }
    
    let file_path = &args[1];
    let file = File::open(file_path).expect("Failed to open file");
    let reader = BufReader::new(file);
    let mut bytes: Vec<u8> = Vec::new();
    for (i,line) in reader.lines().enumerate() {
        match line {
            Ok(content) => {
                let num = content.parse::<u8>().expect(format!("Failed to parse line {i} as u8").as_str());
                bytes.push(num);
            }
            Err(e) => eprintln!("Error reading line {}: {}",i, e),
        }
    }
    println!("Read {} u8 elements from file {}", bytes.len(), file_path);
    let mut used = 0;
    let mut source = SftpSource::new(&bytes.as_slice());
    while source.remaining() > 0 {
        match SftpPacket::decode(&mut source) {
            Ok(packet) => {

                match packet {
                    SftpPacket::Name(req_id, name) => {
                        println!("SFTP Name: {:?} {:?}", req_id, name);
                        for i in 0..name.count {
                            println!("--({i}) Entry: {:?}", NameEntry::dec(&mut source).expect("Failed to decode NameEntry"));
                        }
                    }
                    SftpPacket::Handle(req_id, handle ) => {
                        println!("SFTP Handle: {:?} {:?}", req_id, handle);
                    }
                    SftpPacket::Attrs(req_id, attrs ) => {
                        println!("SFTP Attrs: {:?} {:?}", req_id, attrs);
                    }
                    SftpPacket::Data(req_id, data ) => {
                        println!("SFTP Data: {:?} {:?} bytes", req_id, data);
                    }
                    _ => {
                        println!("Decoded packet: {:?}", packet);
                    }
                }
            }
            Err(e) => {
                println!("Error decoding packet: {:?}. Up to: {:?}", e, source.buffer_used().len());

                break;
            }
        }
        let prev_used = used;
        used = source.buffer_used().len();
        let last_used = used - prev_used;
        println!("Last 9 bytes : {:?}, Lines {:?}-{used}, Counters: ({last_used}/{used}) [last/total decoded]\n", &source.buffer_used()[used-9..], prev_used+1 );
    }
}