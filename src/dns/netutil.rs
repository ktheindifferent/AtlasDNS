use std::io::{Read, Result, Write};
use std::net::TcpStream;
extern crate sentry;

pub fn read_packet_length(stream: &mut TcpStream) -> Result<u16> {
    let mut len_buffer = [0; 2];
    stream.read_exact(&mut len_buffer).map_err(|e| {
        // Report network read error to Sentry
        sentry::configure_scope(|scope| {
            scope.set_tag("component", "network");
            scope.set_tag("operation", "read_packet_length");
            scope.set_tag("protocol", "tcp");
            scope.set_extra("error_type", "tcp_read_error".into());
            if let Ok(peer_addr) = stream.peer_addr() {
                scope.set_extra("peer_address", peer_addr.to_string().into());
            }
        });
        sentry::capture_message(
            &format!("Failed to read packet length from TCP stream: {}", e),
            sentry::Level::Warning
        );
        e
    })?;

    Ok(((len_buffer[0] as u16) << 8) | (len_buffer[1] as u16))
}

pub fn write_packet_length(stream: &mut TcpStream, len: usize) -> Result<()> {
    let mut len_buffer = [0; 2];
    len_buffer[0] = (len >> 8) as u8;
    len_buffer[1] = (len & 0xFF) as u8;

    stream.write_all(&len_buffer).map_err(|e| {
        // Report network write error to Sentry
        sentry::configure_scope(|scope| {
            scope.set_tag("component", "network");
            scope.set_tag("operation", "write_packet_length");
            scope.set_tag("protocol", "tcp");
            scope.set_extra("error_type", "tcp_write_error".into());
            scope.set_extra("packet_length", len.into());
            if let Ok(peer_addr) = stream.peer_addr() {
                scope.set_extra("peer_address", peer_addr.to_string().into());
            }
        });
        sentry::capture_message(
            &format!("Failed to write packet length {} to TCP stream: {}", len, e),
            sentry::Level::Warning
        );
        e
    })?;

    Ok(())
}

/// Generic version of read_packet_length for any Read stream
pub fn read_packet_length_generic<R: Read>(stream: &mut R) -> Result<u16> {
    let mut len_buffer = [0; 2];
    stream.read_exact(&mut len_buffer)?;
    Ok(((len_buffer[0] as u16) << 8) | (len_buffer[1] as u16))
}

/// Generic version of write_packet_length for any Write stream  
pub fn write_packet_length_generic<W: Write>(stream: &mut W, len: usize) -> Result<()> {
    let mut len_buffer = [0; 2];
    len_buffer[0] = (len >> 8) as u8;
    len_buffer[1] = (len & 0xFF) as u8;
    stream.write_all(&len_buffer)?;
    Ok(())
}
