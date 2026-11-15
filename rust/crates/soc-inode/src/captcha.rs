//! CAPTCHA handling for the V7 gateway (port of `captcha.py`).
//!
//! The gateway (`supportvldimg=true`) gates login on a small BMP image served
//! from `vldimg.cgi`. This module provides, with no third-party deps:
//!   * [`decode_bmp`]  — minimal BMP reader (24/32/8-bit, uncompressed), fully
//!     ported including the attacker-controlled-size guards;
//!   * [`render_ansi`] — truecolor half-block preview so a terminal operator can
//!     read and type the code (fully ported);
//!   * [`solve`]       — optional auto-solver; shells out to `tesseract` on a
//!     whole-image render (see the SIMPLIFICATION note below).
//!
//! SIMPLIFICATION vs. `captcha.py`: the pure-pixel per-glyph segmentation (colour
//! clustering + connected components + multi-render voting) is NOT ported. The
//! auto-solver runs whole-image OCR only; when it is unsure the caller falls back
//! to the fully-ported ANSI preview + manual entry, and the gateway's reply is
//! the success oracle for a captcha retry — so correctness is unaffected, only
//! the hands-free hit rate on cleanly-separable glyphs.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use crate::error::{InodeError, Result};

/// A pixel with all channels above this is "background".
const WHITE_CUTOFF: u8 = 200;
const WHITELIST: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/// A decoded BMP. `rows[y][x] == [r, g, b]`, row 0 is the TOP of the image.
#[derive(Debug, Clone)]
pub struct Bmp {
    pub width: usize,
    pub height: usize,
    pub rows: Vec<Vec<[u8; 3]>>,
}

fn byte_at(d: &[u8], o: usize) -> u8 {
    d.get(o).copied().unwrap_or(0)
}

fn u16_le(d: &[u8], o: usize) -> u16 {
    d.get(o..o + 2).and_then(|s| <[u8; 2]>::try_from(s).ok()).map(u16::from_le_bytes).unwrap_or(0)
}

fn u32_le(d: &[u8], o: usize) -> u32 {
    d.get(o..o + 4).and_then(|s| <[u8; 4]>::try_from(s).ok()).map(u32::from_le_bytes).unwrap_or(0)
}

fn i32_le(d: &[u8], o: usize) -> i32 {
    d.get(o..o + 4).and_then(|s| <[u8; 4]>::try_from(s).ok()).map(i32::from_le_bytes).unwrap_or(0)
}

fn usize_le32(d: &[u8], o: usize) -> usize {
    usize::try_from(u32_le(d, o)).unwrap_or(0)
}

/// Decode an uncompressed BMP into rows of `[r, g, b]` (top row first).
pub fn decode_bmp(data: &[u8]) -> Result<Bmp> {
    if data.get(..2) != Some(&b"BM"[..]) {
        return Err(InodeError::Protocol("not a BMP image".into()));
    }
    // 54 = end of BITMAPFILEHEADER(14)+BITMAPINFOHEADER(40); covers every fixed
    // read below (ncol@46 ends at 50).
    if data.len() < 54 {
        return Err(InodeError::Protocol("BMP header truncated".into()));
    }
    let pix_off = usize_le32(data, 10);
    let dib = usize_le32(data, 14);
    let width_i = i32_le(data, 18);
    let height_i = i32_le(data, 22);
    let bpp = usize::from(u16_le(data, 28));
    let compression = u32_le(data, 30);
    if compression != 0 {
        return Err(InodeError::Protocol(format!("unsupported BMP compression {compression}")));
    }
    let top_down = height_i < 0;
    let h = usize::try_from(height_i.unsigned_abs()).unwrap_or(0);
    let width = usize::try_from(width_i).unwrap_or(0);

    // width/height are attacker-controlled; bound them hard, then verify the
    // declared pixel array actually fits before allocating.
    const MAX_DIM: usize = 4096;
    const MAX_PIXELS: usize = 1 << 20;
    if !(width > 0 && width <= MAX_DIM && h > 0 && h <= MAX_DIM) {
        return Err(InodeError::Protocol(format!("BMP dimensions out of range: {width_i}x{height_i}")));
    }
    if width.saturating_mul(h) > MAX_PIXELS {
        return Err(InodeError::Protocol(format!("BMP too large: {width}x{h} pixels")));
    }
    let row_size = (bpp.saturating_mul(width).saturating_add(31) / 32).saturating_mul(4);
    if pix_off.saturating_add(row_size.saturating_mul(h)) > data.len() {
        return Err(InodeError::Protocol("BMP pixel data truncated / inconsistent with header".into()));
    }

    let mut palette: Vec<[u8; 3]> = Vec::new();
    if bpp <= 8 {
        let poff = 14 + dib;
        let ncol_default = 1usize << bpp.min(8);
        let ncol_raw = usize_le32(data, 46);
        let ncol = if ncol_raw == 0 { ncol_default } else { ncol_raw }
            .min(ncol_default)
            .min(data.len().saturating_sub(poff) / 4);
        for i in 0..ncol {
            let base = poff + i * 4;
            palette.push([byte_at(data, base + 2), byte_at(data, base + 1), byte_at(data, base)]);
        }
    }

    let mut rows: Vec<Vec<[u8; 3]>> = Vec::with_capacity(h);
    for ry in 0..h {
        let src = if top_down { ry } else { h - 1 - ry };
        let base = pix_off + src * row_size;
        let mut row: Vec<[u8; 3]> = Vec::with_capacity(width);
        match bpp {
            24 => {
                for x in 0..width {
                    let o = base + x * 3;
                    row.push([byte_at(data, o + 2), byte_at(data, o + 1), byte_at(data, o)]);
                }
            }
            32 => {
                for x in 0..width {
                    let o = base + x * 4;
                    row.push([byte_at(data, o + 2), byte_at(data, o + 1), byte_at(data, o)]);
                }
            }
            8 => {
                for x in 0..width {
                    let idx = usize::from(byte_at(data, base + x));
                    row.push(palette.get(idx).copied().unwrap_or([0, 0, 0]));
                }
            }
            other => return Err(InodeError::Protocol(format!("unsupported BMP depth {other}"))),
        }
        rows.push(row);
    }
    Ok(Bmp { width, height: h, rows })
}

/// Render the captcha as truecolor Unicode half-blocks (two vertical pixels per
/// cell), downscaling (nearest) if wider than `max_width`.
pub fn render_ansi(rows: &[Vec<[u8; 3]>], max_width: usize) -> String {
    let h = rows.len();
    let w = rows.first().map(Vec::len).unwrap_or(0);
    if w == 0 {
        return String::new();
    }
    let mw = max_width.max(1);
    let step = w.div_ceil(mw).max(1);
    let at = |y: usize, x: usize| -> [u8; 3] { rows.get(y).and_then(|r| r.get(x)).copied().unwrap_or([255, 255, 255]) };

    let mut out: Vec<String> = Vec::new();
    let mut y = 0;
    while y < h {
        let mut line = String::new();
        let mut x = 0;
        while x < w {
            let [tr, tg, tb] = at(y, x);
            let [br, bg, bb] = at(y + step, x);
            line.push_str(&format!("\x1b[38;2;{tr};{tg};{tb}m\x1b[48;2;{br};{bg};{bb}m\u{2580}"));
            x += step;
        }
        line.push_str("\x1b[0m");
        out.push(line);
        y += 2 * step;
    }
    out.join("\n")
}

/// `true` when the `tesseract` binary is on `PATH`.
pub fn have_solver() -> bool {
    match std::env::var_os("PATH") {
        Some(paths) => std::env::split_paths(&paths).any(|dir| dir.join("tesseract").is_file()),
        None => false,
    }
}

/// Auto-solve via whole-image OCR. Returns the code, or `None` when `tesseract`
/// is unavailable or produced no confident read (caller falls back to manual).
pub fn solve(bmp_bytes: &[u8], expect_len: usize) -> Option<String> {
    if !have_solver() {
        return None;
    }
    let img = decode_bmp(bmp_bytes).ok()?;
    let grid = ink_grid(&img.rows);
    let (y0, y1) = crop_rows(&grid);
    let w = grid.first().map(Vec::len).unwrap_or(0);
    let path = write_pgm(&grid, y0, y1, 0, w, 10).ok()?;
    let mut answer = None;
    for psm in [7u8, 8, 6] {
        let text = tesseract(&path, psm);
        let filtered: String = text.chars().filter(|ch| WHITELIST.contains(*ch)).collect();
        if filtered.chars().count() == expect_len {
            answer = Some(filtered);
            break;
        }
    }
    drop(std::fs::remove_file(&path));
    answer
}

fn ink_grid(rows: &[Vec<[u8; 3]>]) -> Vec<Vec<bool>> {
    rows.iter()
        .map(|row| row.iter().map(|&[r, g, b]| !(r > WHITE_CUTOFF && g > WHITE_CUTOFF && b > WHITE_CUTOFF)).collect())
        .collect()
}

fn crop_rows(grid: &[Vec<bool>]) -> (usize, usize) {
    let h = grid.len();
    let ys: Vec<usize> = (0..h).filter(|&y| grid.get(y).map(|r| r.iter().any(|&b| b)).unwrap_or(false)).collect();
    match (ys.first(), ys.last()) {
        (Some(&a), Some(&b)) => (a, b + 1),
        _ => (0, h),
    }
}

/// Write a scaled, padded P5 (grayscale) PNM of `grid[y0:y1, x0:x1]` to a temp
/// file and return its path. Black ink (0) on white (255).
fn write_pgm(grid: &[Vec<bool>], y0: usize, y1: usize, x0: usize, x1: usize, scale: usize) -> Result<String> {
    let scale = scale.max(1);
    let pad = 6usize;
    let gh = y1.saturating_sub(y0);
    let gw = x1.saturating_sub(x0);
    let full_w = gw.saturating_add(2 * pad).saturating_mul(scale);
    let full_h = gh.saturating_add(2 * pad).saturating_mul(scale);
    if full_w.saturating_mul(full_h) > 64 * 1024 * 1024 {
        return Err(InodeError::Protocol("captcha render too large".into()));
    }
    let mut buf = vec![0xffu8; full_w.saturating_mul(full_h)];
    for y in 0..gh {
        for x in 0..gw {
            let inked = grid.get(y0 + y).and_then(|r| r.get(x0 + x)).copied().unwrap_or(false);
            if !inked {
                continue;
            }
            for sy in 0..scale {
                let oy = (pad * scale + y * scale + sy) * full_w;
                let rowbase = oy + pad * scale + x * scale;
                for sx in 0..scale {
                    if let Some(px) = buf.get_mut(rowbase + sx) {
                        *px = 0;
                    }
                }
            }
        }
    }
    let path = temp_pgm_path();
    let mut f = std::fs::File::create(&path).map_err(InodeError::Io)?;
    f.write_all(format!("P5\n{full_w} {full_h}\n255\n").as_bytes()).map_err(InodeError::Io)?;
    f.write_all(&buf).map_err(InodeError::Io)?;
    Ok(path.to_string_lossy().into_owned())
}

fn tesseract(path: &str, psm: u8) -> String {
    let whitelist = format!("tessedit_char_whitelist={WHITELIST}");
    let psm_s = psm.to_string();
    match Command::new("tesseract")
        .args([path, "stdout", "--psm", psm_s.as_str(), "-c", whitelist.as_str()])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
    {
        Ok(o) => String::from_utf8_lossy(&o.stdout).chars().filter(|c| !c.is_whitespace()).collect(),
        Err(e) => {
            drop(e);
            String::new()
        }
    }
}

fn temp_pgm_path() -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    std::env::temp_dir().join(format!("h3csvpn-{}-{nanos}-{seq}.pgm", std::process::id()))
}
