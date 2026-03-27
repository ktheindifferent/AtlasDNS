//! buffers for use when writing and reading dns packets

use std::collections::BTreeMap;
use std::io::Read;

use derive_more::{Display, Error, From};

#[derive(Debug, Display, From, Error)]
pub enum BufferError {
    Io(std::io::Error),
    EndOfBuffer,
}

type Result<T> = std::result::Result<T, BufferError>;

pub trait PacketBuffer {
    fn read(&mut self) -> Result<u8>;
    fn get(&mut self, pos: usize) -> Result<u8>;
    fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8]>;
    fn write(&mut self, val: u8) -> Result<()>;
    fn set(&mut self, pos: usize, val: u8) -> Result<()>;
    fn pos(&self) -> usize;
    fn seek(&mut self, pos: usize) -> Result<()>;
    fn step(&mut self, steps: usize) -> Result<()>;
    fn find_label(&self, label: &str) -> Option<usize>;
    fn save_label(&mut self, label: &str, pos: usize);

    fn write_u8(&mut self, val: u8) -> Result<()> {
        self.write(val)?;

        Ok(())
    }

    fn set_u16(&mut self, pos: usize, val: u16) -> Result<()> {
        self.set(pos, (val >> 8) as u8)?;
        self.set(pos + 1, (val & 0xFF) as u8)?;

        Ok(())
    }

    fn write_u16(&mut self, val: u16) -> Result<()> {
        self.write((val >> 8) as u8)?;
        self.write((val & 0xFF) as u8)?;

        Ok(())
    }

    fn write_u32(&mut self, val: u32) -> Result<()> {
        self.write(((val >> 24) & 0xFF) as u8)?;
        self.write(((val >> 16) & 0xFF) as u8)?;
        self.write(((val >> 8) & 0xFF) as u8)?;
        self.write((val & 0xFF) as u8)?;

        Ok(())
    }

    fn write_qname(&mut self, qname: &str) -> Result<()> {
        let split_str = qname.split('.').collect::<Vec<&str>>();

        let mut jump_performed = false;
        for (i, label) in split_str.iter().enumerate() {
            let search_lbl = split_str[i..split_str.len()].join(".");
            if let Some(prev_pos) = self.find_label(&search_lbl) {
                let jump_inst = (prev_pos as u16) | 0xC000;
                self.write_u16(jump_inst)?;
                jump_performed = true;

                break;
            }

            let pos = self.pos();
            self.save_label(&search_lbl, pos);

            let len = label.len();
            self.write_u8(len as u8)?;
            for b in label.as_bytes() {
                self.write_u8(*b)?;
            }
        }

        if !jump_performed {
            self.write_u8(0)?;
        }

        Ok(())
    }

    fn read_u16(&mut self) -> Result<u16> {
        let res = ((self.read()? as u16) << 8) | (self.read()? as u16);

        Ok(res)
    }

    fn read_u32(&mut self) -> Result<u32> {
        let res = ((self.read()? as u32) << 24)
            | ((self.read()? as u32) << 16)
            | ((self.read()? as u32) << 8)
            | (self.read()? as u32);

        Ok(res)
    }

    fn read_qname(&mut self, outstr: &mut String) -> Result<()> {
        let mut pos = self.pos();
        let mut jumped = false;
        
        // DNS name length limits per RFC 1035
        const MAX_NAME_LENGTH: usize = 255;
        const MAX_LABEL_LENGTH: usize = 63;
        let mut total_length = 0;

        let mut delim = "";
        loop {
            let len = self.get(pos)?;

            // A two byte sequence, where the two highest bits of the first byte is
            // set, represents a offset relative to the start of the buffer. We
            // handle this by jumping to the offset, setting a flag to indicate
            // that we shouldn't update the shared buffer position once done.
            if (len & 0xC0) > 0 {
                // When a jump is performed, we only modify the shared buffer
                // position once, and avoid making the change later on.
                if !jumped {
                    self.seek(pos + 2)?;
                }

                let b2 = self.get(pos + 1)? as u16;
                let offset = (((len as u16) ^ 0xC0) << 8) | b2;
                pos = offset as usize;
                jumped = true;
                continue;
            }

            pos += 1;

            // Names are terminated by an empty label of length 0
            if len == 0 {
                break;
            }
            
            // Check label length limit
            if len as usize > MAX_LABEL_LENGTH {
                return Err(BufferError::EndOfBuffer);
            }

            outstr.push_str(delim);

            let str_buffer = self.get_range(pos, len as usize)?;
            outstr.push_str(&String::from_utf8_lossy(str_buffer).to_lowercase());

            delim = ".";
            
            // Track total name length
            total_length += len as usize + 1; // +1 for the length byte itself
            if total_length > MAX_NAME_LENGTH {
                return Err(BufferError::EndOfBuffer);
            }

            pos += len as usize;
        }

        if !jumped {
            self.seek(pos)?;
        }

        Ok(())
    }
}

#[derive(Default)]
pub struct VectorPacketBuffer {
    pub buffer: Vec<u8>,
    pub pos: usize,
    pub label_lookup: BTreeMap<String, usize>,
}

impl VectorPacketBuffer {
    pub fn new() -> VectorPacketBuffer {
        VectorPacketBuffer {
            buffer: Vec::new(),
            pos: 0,
            label_lookup: BTreeMap::new(),
        }
    }
}

impl PacketBuffer for VectorPacketBuffer {
    fn find_label(&self, label: &str) -> Option<usize> {
        self.label_lookup.get(label).cloned()
    }

    fn save_label(&mut self, label: &str, pos: usize) {
        self.label_lookup.insert(label.to_string(), pos);
    }

    fn read(&mut self) -> Result<u8> {
        if self.pos >= self.buffer.len() {
            return Err(BufferError::EndOfBuffer);
        }
        let res = self.buffer[self.pos];
        self.pos += 1;

        Ok(res)
    }

    fn get(&mut self, pos: usize) -> Result<u8> {
        if pos >= self.buffer.len() {
            return Err(BufferError::EndOfBuffer);
        }
        Ok(self.buffer[pos])
    }

    fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8]> {
        let end = start.saturating_add(len);
        if end > self.buffer.len() {
            return Err(BufferError::EndOfBuffer);
        }
        Ok(&self.buffer[start..end])
    }

    fn write(&mut self, val: u8) -> Result<()> {
        self.buffer.push(val);
        self.pos += 1;

        Ok(())
    }

    fn set(&mut self, pos: usize, val: u8) -> Result<()> {
        self.buffer[pos] = val;

        Ok(())
    }

    fn pos(&self) -> usize {
        self.pos
    }

    fn seek(&mut self, pos: usize) -> Result<()> {
        self.pos = pos;

        Ok(())
    }

    fn step(&mut self, steps: usize) -> Result<()> {
        self.pos += steps;

        Ok(())
    }
}

pub struct StreamPacketBuffer<'a, T>
where
    T: Read,
{
    pub stream: &'a mut T,
    pub buffer: Vec<u8>,
    pub pos: usize,
}

impl<'a, T> StreamPacketBuffer<'a, T>
where
    T: Read + 'a,
{
    pub fn new(stream: &'a mut T) -> StreamPacketBuffer<'a, T> {
        StreamPacketBuffer {
            stream,
            buffer: Vec::new(),
            pos: 0,
        }
    }
}

impl<'a, T> PacketBuffer for StreamPacketBuffer<'a, T>
where
    T: Read + 'a,
{
    fn find_label(&self, _: &str) -> Option<usize> {
        None
    }

    fn save_label(&mut self, _: &str, _: usize) {
        // StreamPacketBuffer doesn't support label compression/storage
        // This is a no-op similar to BytePacketBuffer
    }

    fn read(&mut self) -> Result<u8> {
        while self.pos >= self.buffer.len() {
            let mut local_buffer = [0; 1];
            self.stream.read_exact(&mut local_buffer)?;
            self.buffer.push(local_buffer[0]);
        }

        let res = self.buffer[self.pos];
        self.pos += 1;

        Ok(res)
    }

    fn get(&mut self, pos: usize) -> Result<u8> {
        while pos >= self.buffer.len() {
            let mut local_buffer = [0; 1];
            self.stream.read_exact(&mut local_buffer)?;
            self.buffer.push(local_buffer[0]);
        }

        Ok(self.buffer[pos])
    }

    fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8]> {
        while start + len > self.buffer.len() {
            let mut local_buffer = [0; 1];
            self.stream.read_exact(&mut local_buffer)?;
            self.buffer.push(local_buffer[0]);
        }

        Ok(&self.buffer[start..start + len])
    }

    fn write(&mut self, _: u8) -> Result<()> {
        // StreamPacketBuffer is read-only
        Err(BufferError::EndOfBuffer)
    }

    fn set(&mut self, _: usize, _: u8) -> Result<()> {
        // StreamPacketBuffer is read-only
        Err(BufferError::EndOfBuffer)
    }

    fn pos(&self) -> usize {
        self.pos
    }

    fn seek(&mut self, pos: usize) -> Result<()> {
        self.pos = pos;
        Ok(())
    }

    fn step(&mut self, steps: usize) -> Result<()> {
        self.pos += steps;
        Ok(())
    }
}

pub struct BytePacketBuffer {
    pub buf: [u8; 512],
    pub pos: usize,
}

impl BytePacketBuffer {
    pub fn new() -> BytePacketBuffer {
        BytePacketBuffer {
            buf: [0; 512],
            pos: 0,
        }
    }
}

impl Default for BytePacketBuffer {
    fn default() -> Self {
        BytePacketBuffer::new()
    }
}

impl PacketBuffer for BytePacketBuffer {
    fn find_label(&self, _: &str) -> Option<usize> {
        None
    }

    fn save_label(&mut self, _: &str, _: usize) {}

    fn read(&mut self) -> Result<u8> {
        if self.pos >= 512 {
            return Err(BufferError::EndOfBuffer);
        }
        let res = self.buf[self.pos];
        self.pos += 1;

        Ok(res)
    }

    fn get(&mut self, pos: usize) -> Result<u8> {
        if pos >= 512 {
            return Err(BufferError::EndOfBuffer);
        }
        Ok(self.buf[pos])
    }

    fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8]> {
        if start + len > 512 {
            return Err(BufferError::EndOfBuffer);
        }
        Ok(&self.buf[start..start + len])
    }

    fn write(&mut self, val: u8) -> Result<()> {
        if self.pos >= 512 {
            return Err(BufferError::EndOfBuffer);
        }
        self.buf[self.pos] = val;
        self.pos += 1;
        Ok(())
    }

    fn set(&mut self, pos: usize, val: u8) -> Result<()> {
        self.buf[pos] = val;

        Ok(())
    }

    fn pos(&self) -> usize {
        self.pos
    }

    fn seek(&mut self, pos: usize) -> Result<()> {
        self.pos = pos;

        Ok(())
    }

    fn step(&mut self, steps: usize) -> Result<()> {
        self.pos += steps;

        Ok(())
    }
}

/// Stack-allocated name buffer for zero-copy DNS name parsing.
///
/// Avoids heap allocation when parsing domain names from DNS packets.
/// Names are written into a fixed `[u8; 256]` buffer (RFC 1035 max = 255).
pub struct NameBuffer {
    buf: [u8; 256],
    len: usize,
}

impl NameBuffer {
    /// Create a new empty name buffer (stack-allocated).
    #[inline]
    pub fn new() -> Self {
        Self {
            buf: [0u8; 256],
            len: 0,
        }
    }

    /// Return the parsed name as a `&str` (zero-copy, borrowed from stack).
    #[inline]
    pub fn as_str(&self) -> &str {
        // Safety: we only write valid lowercase ASCII bytes
        unsafe { std::str::from_utf8_unchecked(&self.buf[..self.len]) }
    }

    /// Convert to an owned `String` (single allocation at the end).
    #[inline]
    pub fn to_string_owned(&self) -> String {
        self.as_str().to_owned()
    }

    /// Current length in bytes.
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the buffer is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Push a byte, lowercasing ASCII in-place.
    #[inline(always)]
    fn push_byte(&mut self, b: u8) -> Result<()> {
        if self.len >= 255 {
            return Err(BufferError::EndOfBuffer);
        }
        // ASCII lowercase without allocation
        self.buf[self.len] = if b.is_ascii_uppercase() { b | 0x20 } else { b };
        self.len += 1;
        Ok(())
    }

    /// Push a dot separator.
    #[inline(always)]
    fn push_dot(&mut self) -> Result<()> {
        if self.len >= 255 {
            return Err(BufferError::EndOfBuffer);
        }
        self.buf[self.len] = b'.';
        self.len += 1;
        Ok(())
    }
}

/// Zero-copy DNS name reader.
///
/// Reads a DNS name from a `PacketBuffer` into a stack-allocated `NameBuffer`,
/// performing ASCII lowercasing in-place without any heap allocation.
pub fn read_qname_zerocopy(buffer: &mut dyn PacketBuffer) -> Result<NameBuffer> {
    let mut name = NameBuffer::new();
    let mut pos = buffer.pos();
    let mut jumped = false;

    const MAX_LABEL_LENGTH: usize = 63;

    let mut first = true;
    loop {
        let len = buffer.get(pos)?;

        // Compression pointer
        if (len & 0xC0) != 0 {
            if !jumped {
                buffer.seek(pos + 2)?;
            }
            let b2 = buffer.get(pos + 1)? as u16;
            let offset = (((len as u16) ^ 0xC0) << 8) | b2;
            pos = offset as usize;
            jumped = true;
            continue;
        }

        pos += 1;

        if len == 0 {
            break;
        }

        if len as usize > MAX_LABEL_LENGTH {
            return Err(BufferError::EndOfBuffer);
        }

        if !first {
            name.push_dot()?;
        }
        first = false;

        let label_bytes = buffer.get_range(pos, len as usize)?;
        for &b in label_bytes {
            name.push_byte(b)?;
        }

        pos += len as usize;
    }

    if !jumped {
        buffer.seek(pos)?;
    }

    Ok(name)
}

/// Parse a DNS question section with zero-copy, returning (name, qtype_num) without
/// allocating a `DnsQuestion`.  Caller can construct one if needed.
#[inline]
pub fn parse_question_zerocopy(buffer: &mut dyn PacketBuffer) -> Result<(NameBuffer, u16)> {
    let name = read_qname_zerocopy(buffer)?;
    let qtype = buffer.read_u16()?;
    let _qclass = buffer.read_u16()?;
    Ok((name, qtype))
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_qname() {
        let mut buffer = VectorPacketBuffer::new();

        let instr1 = "a.google.com".to_string();
        let instr2 = "b.google.com".to_string();

        // First write the standard string
        match buffer.write_qname(&instr1) {
            Ok(_) => {}
            Err(e) => panic!("Failed to write qname '{}': {}", instr1, e),
        }

        // Then we set up a slight variation with relies on a jump back to the data of
        // the first name
        let crafted_data = [0x01, b'b', 0xC0, 0x02];
        for b in &crafted_data {
            match buffer.write_u8(*b) {
                Ok(_) => {}
                Err(e) => panic!("Failed to write byte {:#02x}: {}", b, e),
            }
        }

        // Reset the buffer position for reading
        buffer.pos = 0;

        // Read the standard name
        let mut outstr1 = String::new();
        match buffer.read_qname(&mut outstr1) {
            Ok(_) => {}
            Err(e) => panic!("Failed to read first qname: {}", e),
        }

        assert_eq!(instr1, outstr1);

        // Read the name with a jump
        let mut outstr2 = String::new();
        match buffer.read_qname(&mut outstr2) {
            Ok(_) => {}
            Err(e) => panic!("Failed to read second qname: {}", e),
        }

        assert_eq!(instr2, outstr2);

        // Make sure we're now at the end of the buffer
        assert_eq!(buffer.pos, buffer.buffer.len());
    }

    #[test]
    fn test_write_qname() {
        let mut buffer = VectorPacketBuffer::new();

        match buffer.write_qname(&"ns1.google.com".to_string()) {
            Ok(_) => {}
            Err(e) => panic!("Failed to write ns1.google.com: {}", e),
        }
        match buffer.write_qname(&"ns2.google.com".to_string()) {
            Ok(_) => {}
            Err(e) => panic!("Failed to write ns2.google.com: {}", e),
        }

        assert_eq!(22, buffer.pos());

        match buffer.seek(0) {
            Ok(_) => {}
            Err(e) => panic!("Failed to seek to position 0: {}", e),
        }

        let mut str1 = String::new();
        match buffer.read_qname(&mut str1) {
            Ok(_) => {}
            Err(e) => panic!("Failed to read first qname: {}", e),
        }

        assert_eq!("ns1.google.com", str1);

        let mut str2 = String::new();
        match buffer.read_qname(&mut str2) {
            Ok(_) => {}
            Err(e) => panic!("Failed to read second qname: {}", e),
        }

        assert_eq!("ns2.google.com", str2);
    }

    #[test]
    fn test_zerocopy_qname() {
        let mut buffer = VectorPacketBuffer::new();
        buffer.write_qname(&"Example.COM".to_string()).unwrap();
        buffer.pos = 0;

        let name = read_qname_zerocopy(&mut buffer).unwrap();
        assert_eq!(name.as_str(), "example.com");
    }

    #[test]
    fn test_zerocopy_qname_with_compression() {
        let mut buffer = VectorPacketBuffer::new();
        buffer.write_qname(&"a.google.com").unwrap();
        // compressed pointer: label "b" then pointer to offset 2 ("google.com")
        let crafted = [0x01, b'b', 0xC0, 0x02];
        for b in &crafted {
            buffer.write_u8(*b).unwrap();
        }
        buffer.pos = 0;

        let n1 = read_qname_zerocopy(&mut buffer).unwrap();
        assert_eq!(n1.as_str(), "a.google.com");

        let n2 = read_qname_zerocopy(&mut buffer).unwrap();
        assert_eq!(n2.as_str(), "b.google.com");
    }

    #[test]
    fn test_name_buffer_stack_allocated() {
        let name = NameBuffer::new();
        assert!(name.is_empty());
        assert_eq!(name.len(), 0);
        assert_eq!(name.as_str(), "");
    }
}
