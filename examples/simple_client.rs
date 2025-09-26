use std::net::UdpSocket;
use std::time::Duration;

// Simple RADIUS client example - manually crafted packets
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;

    // Create a simple Access-Request packet
    let mut packet = Vec::new();

    // RADIUS Header: Code=1 (Access-Request), ID=1, Length=TBD, Authenticator=16 zeros
    packet.push(1u8); // Code: Access-Request
    packet.push(1u8); // Identifier
    packet.extend_from_slice(&[0u8, 0u8]); // Length (will be filled later)
    packet.extend_from_slice(&[0u8; 16]); // Request Authenticator (zeros for now)

    // User-Name attribute (type=1)
    let username = "testuser";
    packet.push(1u8); // Attribute type: User-Name
    packet.push((2 + username.len()) as u8); // Attribute length
    packet.extend_from_slice(username.as_bytes());

    // User-Password attribute (type=2) - simplified (should be encrypted in real implementation)
    let password = "testpass";
    packet.push(2u8); // Attribute type: User-Password
    packet.push((2 + password.len()) as u8); // Attribute length
    packet.extend_from_slice(password.as_bytes());

    // NAS-IP-Address attribute (type=4)
    packet.push(4u8); // Attribute type: NAS-IP-Address
    packet.push(6u8); // Attribute length
    packet.extend_from_slice(&[127, 0, 0, 1]); // IP: 127.0.0.1

    // Update packet length
    let total_length = packet.len() as u16;
    packet[2..4].copy_from_slice(&total_length.to_be_bytes());

    println!("Sending RADIUS Access-Request to server...");
    socket.send_to(&packet, "127.0.0.1:1812")?;

    let mut buf = [0u8; 4096];
    match socket.recv_from(&mut buf) {
        Ok((len, _addr)) => {
            let response_code = buf[0];
            match response_code {
                2 => println!("✓ Authentication successful! (Access-Accept)"),
                3 => println!("✗ Authentication failed! (Access-Reject)"),
                _ => println!("? Unexpected response code: {}", response_code),
            }
        }
        Err(e) => {
            println!("Failed to receive response: {}", e);
        }
    }

    Ok(())
}