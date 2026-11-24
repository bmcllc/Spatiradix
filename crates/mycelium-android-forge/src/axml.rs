use std::collections::HashMap;

const RES_XML_TYPE: u16 = 0x0003;
const RES_STRING_POOL_TYPE: u16 = 0x0001;
const RES_XML_RESOURCE_MAP_TYPE: u16 = 0x0180;
const RES_XML_START_NAMESPACE_TYPE: u16 = 0x0100;
const RES_XML_END_NAMESPACE_TYPE: u16 = 0x0101;
const RES_XML_START_ELEMENT_TYPE: u16 = 0x0102;
const RES_XML_END_ELEMENT_TYPE: u16 = 0x0103;

const ANDROID_NS: &str = "http://schemas.android.com/apk/res/android";

const TYPE_REFERENCE: u8 = 0x01;
const TYPE_STRING: u8 = 0x03;
const TYPE_INT_DEC: u8 = 0x10;
const TYPE_INT_HEX: u8 = 0x11;
const TYPE_INT_BOOLEAN: u8 = 0x12;

/// Atributos `android:*` ordenados por Resource ID crescente (`android.R.attr`).
const RES_ATTR_IDS: &[(&str, u32)] = &[
    ("theme", 0x01010000),
    ("label", 0x01010001),
    ("icon", 0x01010002),
    ("name", 0x01010003),
    ("permission", 0x01010006),
    ("debuggable", 0x0101000f),
    ("exported", 0x01010010),
    ("launchMode", 0x0101001d),
    ("configChanges", 0x0101001f),
    ("mimeType", 0x01010026),
    ("scheme", 0x01010027),
    ("minSdkVersion", 0x0101020c),
    ("versionCode", 0x0101021b),
    ("versionName", 0x0101021c),
    ("targetSdkVersion", 0x01010270),
    ("extractNativeLibs", 0x010104ea),
    ("usesCleartextTraffic", 0x010104ec),
    ("foregroundServiceType", 0x01010599),
];

struct StringPool {
    strings: Vec<String>,
    index: HashMap<String, u32>,
}

impl StringPool {
    fn new_with_res_attrs() -> Self {
        let mut pool = Self {
            strings: Vec::new(),
            index: HashMap::new(),
        };
        for &(name, _) in RES_ATTR_IDS {
            pool.intern(name);
        }
        pool
    }

    fn intern(&mut self, s: &str) -> u32 {
        if let Some(&idx) = self.index.get(s) {
            return idx;
        }
        let idx = self.strings.len() as u32;
        self.strings.push(s.to_string());
        self.index.insert(s.to_string(), idx);
        idx
    }

    fn encode_utf16_chunk(&self) -> Vec<u8> {
        let mut offsets = Vec::with_capacity(self.strings.len());
        let mut data = Vec::new();
        for s in &self.strings {
            offsets.push(data.len() as u32);
            let units: Vec<u16> = s.encode_utf16().collect();
            let len = units.len();
            if len >= 0x8000 {
                let hi = 0x8000 | ((len >> 16) as u16);
                let lo = (len & 0xffff) as u16;
                data.extend_from_slice(&hi.to_le_bytes());
                data.extend_from_slice(&lo.to_le_bytes());
            } else {
                data.extend_from_slice(&(len as u16).to_le_bytes());
            }
            for u in units {
                data.extend_from_slice(&u.to_le_bytes());
            }
            data.extend_from_slice(&0u16.to_le_bytes());
        }
        while data.len() % 4 != 0 {
            data.push(0);
        }

        let header_size = 28u16;
        let string_count = self.strings.len() as u32;
        let strings_start = header_size as u32 + string_count * 4;
        let total_size = strings_start + data.len() as u32;

        let mut out = Vec::with_capacity(total_size as usize);
        out.extend_from_slice(&RES_STRING_POOL_TYPE.to_le_bytes());
        out.extend_from_slice(&header_size.to_le_bytes());
        out.extend_from_slice(&total_size.to_le_bytes());
        out.extend_from_slice(&string_count.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // styleCount
        out.extend_from_slice(&0u32.to_le_bytes()); // flags = 0 (UTF-16LE)
        out.extend_from_slice(&strings_start.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // stylesStart
        for off in offsets {
            out.extend_from_slice(&off.to_le_bytes());
        }
        out.extend_from_slice(&data);
        out
    }
}

#[derive(Clone)]
enum AttrVal {
    Ref(u32),
    Str(String),
    IntDec(u32),
    IntHex(u32),
    Bool(bool),
}

struct XmlAttr {
    ns: Option<&'static str>,
    name: &'static str,
    val: AttrVal,
}

enum XmlEvent {
    StartElem {
        tag: &'static str,
        attrs: Vec<XmlAttr>,
    },
    EndElem {
        tag: &'static str,
    },
}

fn attr_sort_key(a: &XmlAttr) -> (u8, u32, &str) {
    if let Some((_, id)) = RES_ATTR_IDS.iter().find(|&&(n, _)| n == a.name) {
        (0, *id, a.name)
    } else {
        (1, u32::MAX, a.name)
    }
}

fn push_start(events: &mut Vec<XmlEvent>, tag: &'static str, mut attrs: Vec<XmlAttr>) {
    attrs.sort_by(|a, b| attr_sort_key(a).cmp(&attr_sort_key(b)));
    events.push(XmlEvent::StartElem { tag, attrs });
}

/// Compila um `AndroidManifest.xml` binário (AXML) completo e alinhado para Android ARM64.
pub fn encode_android_manifest(version_code: u32, version_name: &str, debuggable: bool) -> Vec<u8> {
    let mut events = Vec::new();

    push_start(
        &mut events,
        "manifest",
        vec![
            XmlAttr {
                ns: None,
                name: "package",
                val: AttrVal::Str("network.mycelium.rhizome".into()),
            },
            XmlAttr {
                ns: Some(ANDROID_NS),
                name: "versionCode",
                val: AttrVal::IntDec(version_code),
            },
            XmlAttr {
                ns: Some(ANDROID_NS),
                name: "versionName",
                val: AttrVal::Str(version_name.to_string()),
            },
        ],
    );

    push_start(
        &mut events,
        "uses-sdk",
        vec![
            XmlAttr {
                ns: Some(ANDROID_NS),
                name: "minSdkVersion",
                val: AttrVal::IntDec(26),
            },
            XmlAttr {
                ns: Some(ANDROID_NS),
                name: "targetSdkVersion",
                val: AttrVal::IntDec(34),
            },
        ],
    );
    events.push(XmlEvent::EndElem { tag: "uses-sdk" });

    for perm in [
        "android.permission.INTERNET",
        "android.permission.ACCESS_NETWORK_STATE",
        "android.permission.ACCESS_WIFI_STATE",
        "android.permission.CHANGE_WIFI_MULTICAST_STATE",
        "android.permission.FOREGROUND_SERVICE",
        "android.permission.FOREGROUND_SERVICE_DATA_SYNC",
        "android.permission.POST_NOTIFICATIONS",
        "android.permission.NFC",
        "android.permission.READ_CONTACTS",
    ] {
        push_start(
            &mut events,
            "uses-permission",
            vec![XmlAttr {
                ns: Some(ANDROID_NS),
                name: "name",
                val: AttrVal::Str(perm.into()),
            }],
        );
        events.push(XmlEvent::EndElem {
            tag: "uses-permission",
        });
    }

    // Visibilidade explícita dos 9 aplicativos sociais no Android 11–15 (<queries>)
    push_start(&mut events, "queries", vec![]);
    for pkg in [
        "com.instagram.android",
        "com.facebook.katana",
        "com.whatsapp",
        "com.twitter.android",
        "org.telegram.messenger",
        "com.reddit.frontpage",
        "com.google.android.youtube",
        "tv.twitch.android.app",
        "com.zhiliaoapp.musically",
    ] {
        push_start(
            &mut events,
            "package",
            vec![XmlAttr {
                ns: Some(ANDROID_NS),
                name: "name",
                val: AttrVal::Str(pkg.into()),
            }],
        );
        events.push(XmlEvent::EndElem { tag: "package" });
    }
    events.push(XmlEvent::EndElem { tag: "queries" });

    let mut app_attrs = vec![
        XmlAttr {
            ns: Some(ANDROID_NS),
            name: "label",
            val: AttrVal::Ref(0x7f020000),
        },
        XmlAttr {
            ns: Some(ANDROID_NS),
            name: "icon",
            val: AttrVal::Ref(0x7f010000),
        },
        XmlAttr {
            ns: Some(ANDROID_NS),
            name: "extractNativeLibs",
            val: AttrVal::Bool(true),
        },
        XmlAttr {
            ns: Some(ANDROID_NS),
            name: "usesCleartextTraffic",
            val: AttrVal::Bool(true),
        },
    ];
    if debuggable {
        app_attrs.push(XmlAttr {
            ns: Some(ANDROID_NS),
            name: "debuggable",
            val: AttrVal::Bool(true),
        });
    }
    push_start(&mut events, "application", app_attrs);

    push_start(
        &mut events,
        "activity",
        vec![
            XmlAttr {
                ns: Some(ANDROID_NS),
                name: "theme",
                val: AttrVal::Ref(0x01030129), // Theme.DeviceDefault.NoActionBar
            },
            XmlAttr {
                ns: Some(ANDROID_NS),
                name: "label",
                val: AttrVal::Ref(0x7f020000),
            },
            XmlAttr {
                ns: Some(ANDROID_NS),
                name: "name",
                val: AttrVal::Str("network.mycelium.rhizome.MainActivity".into()),
            },
            XmlAttr {
                ns: Some(ANDROID_NS),
                name: "exported",
                val: AttrVal::Bool(true),
            },
            XmlAttr {
                ns: Some(ANDROID_NS),
                name: "launchMode",
                val: AttrVal::IntDec(1), // singleTop
            },
            XmlAttr {
                ns: Some(ANDROID_NS),
                name: "configChanges",
                val: AttrVal::IntHex(0x0fb0),
            },
        ],
    );
    push_start(&mut events, "intent-filter", vec![]);
    push_start(
        &mut events,
        "action",
        vec![XmlAttr {
            ns: Some(ANDROID_NS),
            name: "name",
            val: AttrVal::Str("android.intent.action.MAIN".into()),
        }],
    );
    events.push(XmlEvent::EndElem { tag: "action" });
    push_start(
        &mut events,
        "category",
        vec![XmlAttr {
            ns: Some(ANDROID_NS),
            name: "name",
            val: AttrVal::Str("android.intent.category.LAUNCHER".into()),
        }],
    );
    events.push(XmlEvent::EndElem { tag: "category" });
    events.push(XmlEvent::EndElem {
        tag: "intent-filter",
    });

    // NFC NDEF Discovered (urn:mycelium:nfc:cpx:v1:...)
    push_start(&mut events, "intent-filter", vec![]);
    push_start(
        &mut events,
        "action",
        vec![XmlAttr {
            ns: Some(ANDROID_NS),
            name: "name",
            val: AttrVal::Str("android.nfc.action.NDEF_DISCOVERED".into()),
        }],
    );
    events.push(XmlEvent::EndElem { tag: "action" });
    push_start(
        &mut events,
        "category",
        vec![XmlAttr {
            ns: Some(ANDROID_NS),
            name: "name",
            val: AttrVal::Str("android.intent.category.DEFAULT".into()),
        }],
    );
    events.push(XmlEvent::EndElem { tag: "category" });
    push_start(
        &mut events,
        "data",
        vec![XmlAttr {
            ns: Some(ANDROID_NS),
            name: "scheme",
            val: AttrVal::Str("urn".into()),
        }],
    );
    events.push(XmlEvent::EndElem { tag: "data" });
    events.push(XmlEvent::EndElem {
        tag: "intent-filter",
    });

    // Share Target (ACTION_SEND) para receber links/vCards dos 9 apps sociais
    push_start(&mut events, "intent-filter", vec![]);
    push_start(
        &mut events,
        "action",
        vec![XmlAttr {
            ns: Some(ANDROID_NS),
            name: "name",
            val: AttrVal::Str("android.intent.action.SEND".into()),
        }],
    );
    events.push(XmlEvent::EndElem { tag: "action" });
    push_start(
        &mut events,
        "category",
        vec![XmlAttr {
            ns: Some(ANDROID_NS),
            name: "name",
            val: AttrVal::Str("android.intent.category.DEFAULT".into()),
        }],
    );
    events.push(XmlEvent::EndElem { tag: "category" });
    for mt in ["text/plain", "text/x-vcard"] {
        push_start(
            &mut events,
            "data",
            vec![XmlAttr {
                ns: Some(ANDROID_NS),
                name: "mimeType",
                val: AttrVal::Str(mt.into()),
            }],
        );
        events.push(XmlEvent::EndElem { tag: "data" });
    }
    events.push(XmlEvent::EndElem {
        tag: "intent-filter",
    });

    events.push(XmlEvent::EndElem { tag: "activity" });

    push_start(
        &mut events,
        "service",
        vec![
            XmlAttr {
                ns: Some(ANDROID_NS),
                name: "name",
                val: AttrVal::Str("network.mycelium.rhizome.MyceliumService".into()),
            },
            XmlAttr {
                ns: Some(ANDROID_NS),
                name: "exported",
                val: AttrVal::Bool(false),
            },
            XmlAttr {
                ns: Some(ANDROID_NS),
                name: "foregroundServiceType",
                val: AttrVal::IntHex(0x00000001), // dataSync
            },
        ],
    );
    events.push(XmlEvent::EndElem { tag: "service" });

    // Serviço nativo Android VpnService para o túnel global VEIL Ω
    push_start(
        &mut events,
        "service",
        vec![
            XmlAttr {
                ns: Some(ANDROID_NS),
                name: "name",
                val: AttrVal::Str("network.mycelium.rhizome.VeilVpnService".into()),
            },
            XmlAttr {
                ns: Some(ANDROID_NS),
                name: "permission",
                val: AttrVal::Str("android.permission.BIND_VPN_SERVICE".into()),
            },
            XmlAttr {
                ns: Some(ANDROID_NS),
                name: "exported",
                val: AttrVal::Bool(false),
            },
        ],
    );
    push_start(&mut events, "intent-filter", vec![]);
    push_start(
        &mut events,
        "action",
        vec![XmlAttr {
            ns: Some(ANDROID_NS),
            name: "name",
            val: AttrVal::Str("android.net.VpnService".into()),
        }],
    );
    events.push(XmlEvent::EndElem { tag: "action" });
    events.push(XmlEvent::EndElem {
        tag: "intent-filter",
    });
    events.push(XmlEvent::EndElem { tag: "service" });
    events.push(XmlEvent::EndElem { tag: "application" });
    events.push(XmlEvent::EndElem { tag: "manifest" });

    // Intern strings na ordem correta (0..RES_ATTR_IDS.len() reservados aos IDs!)
    let mut pool = StringPool::new_with_res_attrs();
    let ns_prefix_idx = pool.intern("android");
    let ns_uri_idx = pool.intern(ANDROID_NS);
    for ev in &events {
        match ev {
            XmlEvent::StartElem { tag, attrs } => {
                pool.intern(tag);
                for a in attrs {
                    pool.intern(a.name);
                    if let AttrVal::Str(s) = &a.val {
                        pool.intern(s);
                    }
                }
            }
            XmlEvent::EndElem { tag } => {
                pool.intern(tag);
            }
        }
    }

    let mut body = Vec::new();
    body.extend_from_slice(&pool.encode_utf16_chunk());

    // Chunk Resource Map (`RES_XML_RESOURCE_MAP_TYPE`)
    let map_size = 8 + RES_ATTR_IDS.len() * 4;
    body.extend_from_slice(&RES_XML_RESOURCE_MAP_TYPE.to_le_bytes());
    body.extend_from_slice(&8u16.to_le_bytes());
    body.extend_from_slice(&(map_size as u32).to_le_bytes());
    for &(_, res_id) in RES_ATTR_IDS {
        body.extend_from_slice(&res_id.to_le_bytes());
    }

    let push_ns = |buf: &mut Vec<u8>, typ: u16, line: u32| {
        buf.extend_from_slice(&typ.to_le_bytes());
        buf.extend_from_slice(&16u16.to_le_bytes());
        buf.extend_from_slice(&24u32.to_le_bytes());
        buf.extend_from_slice(&line.to_le_bytes());
        buf.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // comment
        buf.extend_from_slice(&ns_prefix_idx.to_le_bytes());
        buf.extend_from_slice(&ns_uri_idx.to_le_bytes());
    };

    push_ns(&mut body, RES_XML_START_NAMESPACE_TYPE, 1);

    let mut line = 2u32;
    for ev in events {
        match ev {
            XmlEvent::StartElem { tag, attrs } => {
                let tag_idx = pool.intern(tag);
                let chunk_size = 36 + attrs.len() * 20;
                body.extend_from_slice(&RES_XML_START_ELEMENT_TYPE.to_le_bytes());
                body.extend_from_slice(&16u16.to_le_bytes());
                body.extend_from_slice(&(chunk_size as u32).to_le_bytes());
                body.extend_from_slice(&line.to_le_bytes());
                body.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
                body.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // element ns
                body.extend_from_slice(&tag_idx.to_le_bytes());
                body.extend_from_slice(&20u16.to_le_bytes()); // attributeStart
                body.extend_from_slice(&20u16.to_le_bytes()); // attributeSize
                body.extend_from_slice(&(attrs.len() as u16).to_le_bytes());
                body.extend_from_slice(&0u16.to_le_bytes()); // idIndex
                body.extend_from_slice(&0u16.to_le_bytes()); // classIndex
                body.extend_from_slice(&0u16.to_le_bytes()); // styleIndex

                for a in attrs {
                    let a_ns = if a.ns.is_some() { ns_uri_idx } else { 0xffff_ffff };
                    let a_name = pool.intern(a.name);
                    let (raw_str_idx, val_type, val_data) = match a.val {
                        AttrVal::Ref(r) => (0xffff_ffff, TYPE_REFERENCE, r),
                        AttrVal::Str(s) => {
                            let si = pool.intern(&s);
                            (si, TYPE_STRING, si)
                        }
                        AttrVal::IntDec(n) => (0xffff_ffff, TYPE_INT_DEC, n),
                        AttrVal::IntHex(n) => (0xffff_ffff, TYPE_INT_HEX, n),
                        AttrVal::Bool(b) => (0xffff_ffff, TYPE_INT_BOOLEAN, if b { 0xffff_ffff } else { 0 }),
                    };
                    body.extend_from_slice(&a_ns.to_le_bytes());
                    body.extend_from_slice(&a_name.to_le_bytes());
                    body.extend_from_slice(&raw_str_idx.to_le_bytes());
                    body.extend_from_slice(&8u16.to_le_bytes()); // Res_value.size
                    body.push(0); // res0
                    body.push(val_type);
                    body.extend_from_slice(&val_data.to_le_bytes());
                }
            }
            XmlEvent::EndElem { tag } => {
                let tag_idx = pool.intern(tag);
                body.extend_from_slice(&RES_XML_END_ELEMENT_TYPE.to_le_bytes());
                body.extend_from_slice(&16u16.to_le_bytes());
                body.extend_from_slice(&24u32.to_le_bytes());
                body.extend_from_slice(&line.to_le_bytes());
                body.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
                body.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
                body.extend_from_slice(&tag_idx.to_le_bytes());
            }
        }
        line += 1;
    }

    push_ns(&mut body, RES_XML_END_NAMESPACE_TYPE, line);

    let total_size = 8 + body.len() as u32;
    let mut out = Vec::with_capacity(total_size as usize);
    out.extend_from_slice(&RES_XML_TYPE.to_le_bytes());
    out.extend_from_slice(&8u16.to_le_bytes());
    out.extend_from_slice(&total_size.to_le_bytes());
    out.extend_from_slice(&body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn axml_structure_and_sorted_resource_attributes() {
        for debuggable in [false, true] {
            let axml = encode_android_manifest(10, "0.1.0", debuggable);
            assert_eq!(u16::from_le_bytes([axml[0], axml[1]]), RES_XML_TYPE);
            let total = u32::from_le_bytes([axml[4], axml[5], axml[6], axml[7]]) as usize;
            assert_eq!(total, axml.len());

            // Percorre chunks após cabeçalho raiz e valida mapa de recursos + ordenação de atributos
            let mut pos = 8usize;
            let mut res_ids = Vec::new();
            let mut elem_balance = 0i32;
            while pos < axml.len() {
                let typ = u16::from_le_bytes([axml[pos], axml[pos + 1]]);
                let size = u32::from_le_bytes([axml[pos + 4], axml[pos + 5], axml[pos + 6], axml[pos + 7]]) as usize;
                assert!(size >= 8 && pos + size <= axml.len());
                if typ == RES_XML_RESOURCE_MAP_TYPE {
                    for chunk in axml[pos + 8..pos + size].chunks_exact(4) {
                        res_ids.push(u32::from_le_bytes(chunk.try_into().unwrap()));
                    }
                } else if typ == RES_XML_START_ELEMENT_TYPE {
                    elem_balance += 1;
                    let attr_count = u16::from_le_bytes([axml[pos + 28], axml[pos + 29]]) as usize;
                    let mut prev_res_id = 0u32;
                    let mut saw_non_res = false;
                    for i in 0..attr_count {
                        let a_off = pos + 36 + i * 20;
                        let name_idx = u32::from_le_bytes(axml[a_off + 4..a_off + 8].try_into().unwrap()) as usize;
                        if let Some(&rid) = res_ids.get(name_idx) {
                            assert!(!saw_non_res, "atributos sem res_id devem ficar após atributos android:*");
                            assert!(rid >= prev_res_id, "atributos android:* fora de ordem");
                            prev_res_id = rid;
                        } else {
                            saw_non_res = true;
                        }
                    }
                } else if typ == RES_XML_END_ELEMENT_TYPE {
                    elem_balance -= 1;
                }
                pos += size;
            }
            assert_eq!(elem_balance, 0);
            assert_eq!(res_ids.len(), RES_ATTR_IDS.len());
            assert!(res_ids.contains(&0x010104ea)); // extractNativeLibs
            assert!(res_ids.contains(&0x010104ec)); // usesCleartextTraffic
        }
    }
}
