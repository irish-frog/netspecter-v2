pub fn record(payload: &[u8]) -> Vec<u8> {
    let mut out = vec![22, 3, 3];
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}
pub fn hello(name: Option<&[u8]>, ech: bool) -> Vec<u8> {
    let mut extensions = Vec::new();
    if let Some(name) = name {
        let mut sni = Vec::new();
        sni.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
        sni.push(0);
        sni.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sni.extend_from_slice(name);
        extensions.extend_from_slice(&[0, 0]);
        extensions.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        extensions.extend(sni);
    }
    if ech {
        extensions.extend_from_slice(&[0xfe, 0x0d, 0, 1, 0]);
    }
    let mut body = vec![3, 3];
    body.extend([0; 32]);
    body.extend_from_slice(&[0, 0, 2, 0x13, 1, 1, 0]);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend(extensions);
    let mut handshake = vec![1, 0, (body.len() >> 8) as u8, body.len() as u8];
    handshake.extend(body);
    record(&handshake)
}
