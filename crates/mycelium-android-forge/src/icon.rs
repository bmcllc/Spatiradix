use crc32fast::Hasher as Crc32;
use flate2::{write::ZlibEncoder, Compression};
use std::io::Write;

fn png_chunk(chunk_type: &[u8; 4], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + data.len());
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(chunk_type);
    out.extend_from_slice(data);
    let mut crc = Crc32::new();
    crc.update(chunk_type);
    crc.update(data);
    out.extend_from_slice(&crc.finalize().to_be_bytes());
    out
}

/// Gera ícone RGBA PNG 192x192 em Rust puro para `res/drawable/ic_launcher.png`.
pub fn generate_launcher_icon_png() -> Vec<u8> {
    let w = 192u32;
    let h = 192u32;
    let mut raw_scanlines = Vec::with_capacity(((w * 4 + 1) * h) as usize);

    let cx = w as f32 / 2.0;
    let cy = h as f32 / 2.0;
    let nodes = [
        (cx, cy - 46.0),
        (cx - 42.0, cy + 24.0),
        (cx + 42.0, cy + 24.0),
        (cx, cy),
    ];

    let dist_seg = |px: f32, py: f32, ax: f32, ay: f32, bx: f32, by: f32| -> f32 {
        let vx = bx - ax;
        let vy = by - ay;
        let wx = px - ax;
        let wy = py - ay;
        let len2 = vx * vx + vy * vy;
        let t = if len2 > 0.0 {
            ((wx * vx + wy * vy) / len2).clamp(0.0, 1.0)
        } else {
            0.0
        };
        let dx = px - (ax + t * vx);
        let dy = py - (ay + t * vy);
        (dx * dx + dy * dy).sqrt()
    };

    for y in 0..h {
        raw_scanlines.push(0); // filter type 0 (None)
        for x in 0..w {
            let px = x as f32 + 0.5;
            let py = y as f32 + 0.5;
            let dx = (px - cx).abs();
            let dy = (py - cy).abs();

            // Fundo obsidian com borda arredondada
            let in_box = dx < 84.0 && dy < 84.0;
            let corner = (dx - 58.0).max(0.0).hypot((dy - 58.0).max(0.0));
            let alpha = if !in_box || corner > 26.0 { 0u8 } else { 255u8 };

            let mut r = 6.0f32;
            let mut g = 16.0f32;
            let mut b = 12.0f32;

            // Anel esmeralda externo
            let ring_d = ((px - cx).hypot(py - cy) - 62.0).abs();
            if ring_d < 4.5 {
                let f = 1.0 - (ring_d / 4.5);
                r += 10.0 * f;
                g += 169.0 * f;
                b += 117.0 * f;
            }

            // Conexões da malha micelial
            for (i, &(ax, ay)) in nodes.iter().enumerate() {
                for &(bx, by) in &nodes[i + 1..] {
                    let sd = dist_seg(px, py, ax, ay, bx, by);
                    if sd < 4.0 {
                        let f = 1.0 - sd / 4.0;
                        r += 16.0 * f;
                        g += 185.0 * f;
                        b += 170.0 * f;
                    }
                }
            }

            // Nós brilhantes
            for (idx, &(nx, ny)) in nodes.iter().enumerate() {
                let d = (px - nx).hypot(py - ny);
                let rad = if idx == 3 { 13.5 } else { 10.5 };
                if d < rad {
                    r = if idx == 3 { 52.0 } else { 16.0 };
                    g = 211.0;
                    b = if idx == 3 { 153.0 } else { 220.0 };
                }
            }

            raw_scanlines.push(r.clamp(0.0, 255.0) as u8);
            raw_scanlines.push(g.clamp(0.0, 255.0) as u8);
            raw_scanlines.push(b.clamp(0.0, 255.0) as u8);
            raw_scanlines.push(alpha);
        }
    }

    let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
    enc.write_all(&raw_scanlines).expect("zlib write");
    let compressed = enc.finish().expect("zlib finish");

    let mut ihdr = Vec::with_capacity(13);
    ihdr.extend_from_slice(&w.to_be_bytes());
    ihdr.extend_from_slice(&h.to_be_bytes());
    ihdr.push(8); // bit depth
    ihdr.push(6); // RGBA
    ihdr.push(0); // compression
    ihdr.push(0); // filter
    ihdr.push(0); // interlace

    let mut png = Vec::new();
    png.extend_from_slice(&[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]);
    png.extend_from_slice(&png_chunk(b"IHDR", &ihdr));
    png.extend_from_slice(&png_chunk(b"IDAT", &compressed));
    png.extend_from_slice(&png_chunk(b"IEND", &[]));
    png
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_valid_png_header_and_iend() {
        let png = generate_launcher_icon_png();
        assert_eq!(&png[..8], &[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]);
        assert_eq!(&png[12..16], b"IHDR");
        assert!(png.ends_with(b"IEND\xae\x42\x60\x82"));
        assert!(png.len() > 200);
    }
}
