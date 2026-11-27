const RES_TABLE_TYPE: u16 = 0x0002;
const RES_STRING_POOL_TYPE: u16 = 0x0001;
const RES_TABLE_PACKAGE_TYPE: u16 = 0x0200;
const RES_TABLE_TYPE_TYPE: u16 = 0x0201;
const RES_TABLE_TYPE_SPEC_TYPE: u16 = 0x0202;

fn encode_utf16_string_pool(strings: &[&str]) -> Vec<u8> {
    let mut offsets = Vec::with_capacity(strings.len());
    let mut data = Vec::new();
    for s in strings {
        offsets.push(data.len() as u32);
        let units: Vec<u16> = s.encode_utf16().collect();
        data.extend_from_slice(&(units.len() as u16).to_le_bytes());
        for u in units {
            data.extend_from_slice(&u.to_le_bytes());
        }
        data.extend_from_slice(&0u16.to_le_bytes());
    }
    while data.len() % 4 != 0 {
        data.push(0);
    }

    let header_size = 28u16;
    let string_count = strings.len() as u32;
    let strings_start = header_size as u32 + string_count * 4;
    let total_size = strings_start + data.len() as u32;

    let mut out = Vec::with_capacity(total_size as usize);
    out.extend_from_slice(&RES_STRING_POOL_TYPE.to_le_bytes());
    out.extend_from_slice(&header_size.to_le_bytes());
    out.extend_from_slice(&total_size.to_le_bytes());
    out.extend_from_slice(&string_count.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // UTF-16LE
    out.extend_from_slice(&strings_start.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    for off in offsets {
        out.extend_from_slice(&off.to_le_bytes());
    }
    out.extend_from_slice(&data);
    out
}

fn encode_type_spec(type_id: u8, entry_count: u32) -> Vec<u8> {
    let total = 16 + entry_count * 4;
    let mut out = Vec::with_capacity(total as usize);
    out.extend_from_slice(&RES_TABLE_TYPE_SPEC_TYPE.to_le_bytes());
    out.extend_from_slice(&16u16.to_le_bytes());
    out.extend_from_slice(&total.to_le_bytes());
    out.push(type_id);
    out.push(0);
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&entry_count.to_le_bytes());
    for _ in 0..entry_count {
        out.extend_from_slice(&0u32.to_le_bytes());
    }
    out
}

fn encode_type_single_string_entry(type_id: u8, key_idx: u32, global_str_idx: u32) -> Vec<u8> {
    let config_size = 64u32;
    let header_size = 20u16 + config_size as u16; // 84 bytes
    let entries_start = header_size as u32 + 4; // 1 offset u32
    let entry_len = 16u32; // ResTable_entry(8) + Res_value(8)
    let total_size = entries_start + entry_len;

    let mut out = Vec::with_capacity(total_size as usize);
    out.extend_from_slice(&RES_TABLE_TYPE_TYPE.to_le_bytes());
    out.extend_from_slice(&header_size.to_le_bytes());
    out.extend_from_slice(&total_size.to_le_bytes());
    out.push(type_id);
    out.push(0);
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes()); // entryCount
    out.extend_from_slice(&entries_start.to_le_bytes());

    // ResTable_config (64 bytes, zeros = default config)
    out.extend_from_slice(&config_size.to_le_bytes());
    out.resize(header_size as usize, 0);

    // entry offsets table
    out.extend_from_slice(&0u32.to_le_bytes());

    // ResTable_entry
    out.extend_from_slice(&8u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&key_idx.to_le_bytes());

    // Res_value (TYPE_STRING = 0x03)
    out.extend_from_slice(&8u16.to_le_bytes());
    out.push(0);
    out.push(0x03);
    out.extend_from_slice(&global_str_idx.to_le_bytes());

    out
}

/// Gera `resources.arsc` definindo pacote `0x7f` (`network.mycelium.rhizome`),
/// `0x7f010000` (`drawable/ic_launcher`) e `0x7f020000` (`string/app_name`).
pub fn encode_resources_arsc() -> Vec<u8> {
    let global_pool = encode_utf16_string_pool(&["res/drawable/ic_launcher.png", "Spatiradix Rhizome"]);
    let type_pool = encode_utf16_string_pool(&["drawable", "string"]);
    let key_pool = encode_utf16_string_pool(&["ic_launcher", "app_name"]);

    let pkg_header_size = 288u16;
    let type_strings_off = pkg_header_size as u32;
    let key_strings_off = type_strings_off + type_pool.len() as u32;

    let mut pkg_body = Vec::new();
    pkg_body.extend_from_slice(&type_pool);
    pkg_body.extend_from_slice(&key_pool);
    pkg_body.extend_from_slice(&encode_type_spec(1, 1));
    pkg_body.extend_from_slice(&encode_type_single_string_entry(1, 0, 0)); // 0x7f010000 -> res/drawable/ic_launcher.png
    pkg_body.extend_from_slice(&encode_type_spec(2, 1));
    pkg_body.extend_from_slice(&encode_type_single_string_entry(2, 1, 1)); // 0x7f020000 -> Spatiradix Rhizome

    let pkg_total_size = pkg_header_size as u32 + pkg_body.len() as u32;
    let mut pkg = Vec::with_capacity(pkg_total_size as usize);
    pkg.extend_from_slice(&RES_TABLE_PACKAGE_TYPE.to_le_bytes());
    pkg.extend_from_slice(&pkg_header_size.to_le_bytes());
    pkg.extend_from_slice(&pkg_total_size.to_le_bytes());
    pkg.extend_from_slice(&0x7fu32.to_le_bytes());
    let mut pkg_name_utf16 = [0u16; 128];
    for (i, u) in "network.mycelium.rhizome".encode_utf16().enumerate() {
        pkg_name_utf16[i] = u;
    }
    for u in pkg_name_utf16 {
        pkg.extend_from_slice(&u.to_le_bytes());
    }
    pkg.extend_from_slice(&type_strings_off.to_le_bytes());
    pkg.extend_from_slice(&2u32.to_le_bytes()); // lastPublicType
    pkg.extend_from_slice(&key_strings_off.to_le_bytes());
    pkg.extend_from_slice(&2u32.to_le_bytes()); // lastPublicKey
    pkg.extend_from_slice(&0u32.to_le_bytes()); // typeIdOffset
    pkg.extend_from_slice(&pkg_body);

    let table_total = 12u32 + global_pool.len() as u32 + pkg.len() as u32;
    let mut out = Vec::with_capacity(table_total as usize);
    out.extend_from_slice(&RES_TABLE_TYPE.to_le_bytes());
    out.extend_from_slice(&12u16.to_le_bytes());
    out.extend_from_slice(&table_total.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes()); // packageCount
    out.extend_from_slice(&global_pool);
    out.extend_from_slice(&pkg);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arsc_package_and_resource_entries_valid() {
        let arsc = encode_resources_arsc();
        let app_name: Vec<u8> = "Spatiradix Rhizome"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert!(arsc.windows(app_name.len()).any(|bytes| bytes == app_name));
        assert_eq!(u16::from_le_bytes([arsc[0], arsc[1]]), RES_TABLE_TYPE);
        let total = u32::from_le_bytes(arsc[4..8].try_into().unwrap()) as usize;
        assert_eq!(total, arsc.len());
        let gpool_size = u32::from_le_bytes(arsc[16..20].try_into().unwrap()) as usize;
        let pkg_off = 12 + gpool_size;
        assert_eq!(u16::from_le_bytes([arsc[pkg_off], arsc[pkg_off + 1]]), RES_TABLE_PACKAGE_TYPE);
        assert_eq!(u32::from_le_bytes(arsc[pkg_off + 8..pkg_off + 12].try_into().unwrap()), 0x7f);
    }
}
