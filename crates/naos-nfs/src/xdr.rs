use std::str;

use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum XdrError {
    #[error("truncated XDR input")]
    Truncated,
    #[error("XDR value exceeds configured limit")]
    LimitExceeded,
    #[error("XDR string is not valid UTF-8")]
    InvalidUtf8,
    #[error("trailing XDR data")]
    TrailingData,
}

pub struct XdrReader<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> XdrReader<'a> {
    pub const fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    pub fn u32(&mut self) -> Result<u32, XdrError> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes(bytes.try_into().expect("fixed length")))
    }

    pub fn u64(&mut self) -> Result<u64, XdrError> {
        let bytes = self.take(8)?;
        Ok(u64::from_be_bytes(bytes.try_into().expect("fixed length")))
    }

    pub fn fixed_opaque(&mut self, length: usize) -> Result<Vec<u8>, XdrError> {
        let value = self.take(length)?.to_vec();
        self.skip_padding(length)?;
        Ok(value)
    }

    pub fn opaque(&mut self, max_length: usize) -> Result<Vec<u8>, XdrError> {
        let length = usize::try_from(self.u32()?).map_err(|_| XdrError::LimitExceeded)?;
        if length > max_length {
            return Err(XdrError::LimitExceeded);
        }
        self.fixed_opaque(length)
    }

    pub fn string(&mut self, max_length: usize) -> Result<String, XdrError> {
        let value = self.opaque(max_length)?;
        str::from_utf8(&value)
            .map(str::to_owned)
            .map_err(|_| XdrError::InvalidUtf8)
    }

    pub fn u32_array(&mut self, max_items: usize) -> Result<Vec<u32>, XdrError> {
        let count = usize::try_from(self.u32()?).map_err(|_| XdrError::LimitExceeded)?;
        if count > max_items {
            return Err(XdrError::LimitExceeded);
        }

        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            values.push(self.u32()?);
        }
        Ok(values)
    }

    pub fn remaining(&self) -> &'a [u8] {
        &self.input[self.position..]
    }

    pub fn finish(self) -> Result<(), XdrError> {
        if self.position == self.input.len() {
            Ok(())
        } else {
            Err(XdrError::TrailingData)
        }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], XdrError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(XdrError::Truncated)?;
        let bytes = self
            .input
            .get(self.position..end)
            .ok_or(XdrError::Truncated)?;
        self.position = end;
        Ok(bytes)
    }

    fn skip_padding(&mut self, length: usize) -> Result<(), XdrError> {
        let padding = (4 - (length % 4)) % 4;
        self.take(padding)?;
        Ok(())
    }
}

#[derive(Default)]
pub struct XdrWriter {
    output: Vec<u8>,
}

impl XdrWriter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn u32(&mut self, value: u32) {
        self.output.extend_from_slice(&value.to_be_bytes());
    }

    pub fn u64(&mut self, value: u64) {
        self.output.extend_from_slice(&value.to_be_bytes());
    }

    pub fn fixed_opaque(&mut self, value: &[u8]) {
        self.output.extend_from_slice(value);
        self.pad(value.len());
    }

    pub fn opaque(&mut self, value: &[u8]) -> Result<(), XdrError> {
        let length = u32::try_from(value.len()).map_err(|_| XdrError::LimitExceeded)?;
        self.u32(length);
        self.fixed_opaque(value);
        Ok(())
    }

    pub fn string(&mut self, value: &str) -> Result<(), XdrError> {
        self.opaque(value.as_bytes())
    }

    pub fn u32_array(&mut self, values: &[u32]) -> Result<(), XdrError> {
        let count = u32::try_from(values.len()).map_err(|_| XdrError::LimitExceeded)?;
        self.u32(count);
        for value in values {
            self.u32(*value);
        }
        Ok(())
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.output
    }

    fn pad(&mut self, length: usize) {
        let padding = (4 - (length % 4)) % 4;
        self.output.resize(self.output.len() + padding, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_scalars_strings_and_arrays() {
        let mut writer = XdrWriter::new();
        writer.u32(7);
        writer.u64(9);
        writer.string("naos").unwrap();
        writer.opaque(&[1, 2, 3]).unwrap();
        writer.u32_array(&[10, 11, 12]).unwrap();

        let bytes = writer.into_bytes();
        let mut reader = XdrReader::new(&bytes);
        assert_eq!(reader.u32().unwrap(), 7);
        assert_eq!(reader.u64().unwrap(), 9);
        assert_eq!(reader.string(8).unwrap(), "naos");
        assert_eq!(reader.opaque(8).unwrap(), vec![1, 2, 3]);
        assert_eq!(reader.u32_array(4).unwrap(), vec![10, 11, 12]);
        reader.finish().unwrap();
    }

    #[test]
    fn rejects_oversized_and_truncated_values() {
        let mut writer = XdrWriter::new();
        writer.string("too-long").unwrap();
        let bytes = writer.into_bytes();
        assert_eq!(
            XdrReader::new(&bytes).string(3),
            Err(XdrError::LimitExceeded)
        );

        let mut reader = XdrReader::new(&[0, 0, 0]);
        assert_eq!(reader.u32(), Err(XdrError::Truncated));
    }
}
