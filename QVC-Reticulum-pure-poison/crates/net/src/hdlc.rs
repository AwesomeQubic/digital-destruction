use std::io::{Read, Result, Write};
use std::net::TcpStream;

use reticulum::context::RnsContext;
use reticulum::{OnSend, TestInf};

const FRAME_BOUNDARY: u8 = 0x7e;
const ESCAPE_BYTE: u8 = 0x7d;
const FLIP_MASK: u8 = 0b00100000;

#[derive(Clone)]
pub struct Hdlc<I> {
    inner: I,
    escaping: bool,
    started: bool,
    finished: bool,
}

impl<I> Hdlc<I> {
    pub const fn new(inner: I) -> Self {
        Self {
            inner,
            escaping: false,
            started: false,
            finished: false,
        }
    }
}

impl Hdlc<TcpStream> {
    pub fn try_clone(&self) -> std::io::Result<Hdlc<TcpStream>> {
        Ok(Hdlc {
            inner: self.inner.try_clone()?,
            escaping: self.escaping,
            started: self.started,
            finished: self.finished,
        })
    }
}

impl<W: Write> Write for Hdlc<W> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let _ = self.inner.write(&[FRAME_BOUNDARY])?;

        for b in buf {
            if *b == FRAME_BOUNDARY || *b == ESCAPE_BYTE {
                let _ = self.inner.write(&[ESCAPE_BYTE, *b ^ FLIP_MASK])?;
            } else {
                let _ = self.inner.write(&[*b])?;
            }
        }
        let _ = self.inner.write(&[FRAME_BOUNDARY])?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<()> {
        self.inner.flush()
    }
}

impl<R: Read> Read for Hdlc<R> {
    // TODO: Does not work for buffer of size 1
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let mut eff_len = self.inner.read(buf)?;

        let mut i = 0;

        while i <= eff_len {
            if i < eff_len && buf[i] == FRAME_BOUNDARY {
                eff_len -= 1;
                if !self.started {
                    self.started = true;
                    buf[..].rotate_left(1);
                } else {
                    self.finished = true;
                }
            }

            if self.escaping {
                self.escaping = false;
                if i == 0 {
                    buf[0] ^= FLIP_MASK;
                } else {
                    buf[i - 1] ^= FLIP_MASK;
                }
            }

            if self.finished {
                self.started = false;
                self.finished = false;
                self.escaping = false;
                return Ok(eff_len);
            }

            if i < eff_len && buf[i] == ESCAPE_BYTE {
                self.escaping = true;
                buf[i..].rotate_left(1);
                eff_len -= 1;
            }

            i += 1;
        }

        Ok(eff_len)
    }
}

impl OnSend<TestInf, RnsContext> for Hdlc<TcpStream> {
    fn send(&mut self, bytes: &[u8]) {
        let _ = self.write(bytes).expect("successfully written bytes");
        self.flush().expect("successfully flushed");
    }
}
