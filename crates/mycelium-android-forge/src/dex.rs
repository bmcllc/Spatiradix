use adler2::adler32_slice;
use sha1::{Digest, Sha1};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, thiserror::Error)]
pub enum DexError {
    #[error("DEX inválido: {0}")]
    Invalid(String),
}

const ACC_PUBLIC: u32 = 0x0001;
const ACC_PRIVATE: u32 = 0x0002;
const ACC_STATIC: u32 = 0x0008;
const ACC_CONSTRUCTOR: u32 = 0x1_0000;

const JS_IFACE_ANNOTATION: &str = "Landroid/webkit/JavascriptInterface;";

const BOOT_HTML: &str = r#"<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/><title>Spatiradix Rhizome</title><style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#060d0a;color:#e5f9ef;font-family:sans-serif;text-align:center;padding:24px}.card{max-width:360px;background:#0e1d16;border:1px solid #1d3c2d;border-radius:18px;padding:24px}.logo{font-size:44px;margin-bottom:10px}.bar{height:6px;background:#13281e;border-radius:99px;overflow:hidden;margin-top:16px}.fill{height:100%;width:45%;background:linear-gradient(90deg,#10b981,#06b6d4);animation:m 1.2s infinite ease-in-out}@keyframes m{0%{transform:translateX(-60%)}100%{transform:translateX(220%)}}p{color:#84ae99;font-size:14px;line-height:1.4}</style></head><body><div class="card"><div class="logo">🌿</div><h2>Spatiradix Rhizome</h2><p id="s">Despertando daemon P2P soberano (sem nuvem, sem Termux, sem Google)...</p><div class="bar"><div class="fill"></div></div></div><script>async function ping(){try{const r=await fetch('http://127.0.0.1:7474/rhizome/api/overview',{cache:'no-store'});if(r.ok){location.replace('http://127.0.0.1:7474/rhizome/');return;}}catch(e){}setTimeout(ping,400);}ping();</script></body></html>"#;

fn push_uleb128(out: &mut Vec<u8>, mut v: u32) {
    loop {
        let mut byte = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if v == 0 {
            break;
        }
    }
}

fn push_sleb128(out: &mut Vec<u8>, mut v: i32) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        let done = (v == 0 && (byte & 0x40) == 0) || (v == -1 && (byte & 0x40) != 0);
        if done {
            out.push(byte);
            break;
        } else {
            out.push(byte | 0x80);
        }
    }
}

fn read_uleb128(data: &[u8], pos: &mut usize) -> Result<u32, DexError> {
    let mut res = 0u32;
    let mut shift = 0u32;
    for _ in 0..5 {
        if *pos >= data.len() {
            return Err(DexError::Invalid("EOF no uleb128".into()));
        }
        let b = data[*pos];
        *pos += 1;
        res |= ((b & 0x7f) as u32) << shift;
        if b & 0x80 == 0 {
            return Ok(res);
        }
        shift += 7;
    }
    Err(DexError::Invalid("uleb128 excedeu 5 bytes".into()))
}

fn read_sleb128(data: &[u8], pos: &mut usize) -> Result<i32, DexError> {
    let mut res = 0i32;
    let mut shift = 0u32;
    for _ in 0..5 {
        if *pos >= data.len() {
            return Err(DexError::Invalid("EOF no sleb128".into()));
        }
        let b = data[*pos];
        *pos += 1;
        res |= ((b & 0x7f) as i32) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            if shift < 32 && (b & 0x40) != 0 {
                res |= !0i32 << shift;
            }
            return Ok(res);
        }
    }
    Err(DexError::Invalid("sleb128 excedeu 5 bytes".into()))
}

/// Encodes a Rust string into DEX Modified UTF-8 (MUTF-8).
fn encode_mutf8(out: &mut Vec<u8>, s: &str) {
    for cu in s.encode_utf16() {
        if cu == 0 {
            out.push(0xc0);
            out.push(0x80);
        } else if cu <= 0x007f {
            out.push(cu as u8);
        } else if cu <= 0x07ff {
            out.push(0xc0 | ((cu >> 6) as u8));
            out.push(0x80 | ((cu & 0x3f) as u8));
        } else {
            out.push(0xe0 | ((cu >> 12) as u8));
            out.push(0x80 | (((cu >> 6) & 0x3f) as u8));
            out.push(0x80 | ((cu & 0x3f) as u8));
        }
    }
}

/// Decodes MUTF-8 bytes (without trailing NUL) into UTF-16 code units, rejecting raw 4-byte UTF-8 (`0xF0+`).
fn decode_mutf8(bytes: &[u8]) -> Result<Vec<u16>, DexError> {
    let mut units = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        let b0 = bytes[i];
        if b0 >= 0xf0 {
            return Err(DexError::Invalid(format!(
                "Byte inicial MUTF-8 ilegal 0x{b0:02x} em string_data"
            )));
        } else if b0 < 0x80 {
            units.push(b0 as u16);
            i += 1;
        } else if (b0 & 0xe0) == 0xc0 {
            if i + 1 >= bytes.len() {
                return Err(DexError::Invalid("sequência MUTF-8 de 2 bytes truncada".into()));
            }
            let b1 = bytes[i + 1];
            if (b1 & 0xc0) != 0x80 {
                return Err(DexError::Invalid("byte de continuação MUTF-8 inválido".into()));
            }
            units.push((((b0 & 0x1f) as u16) << 6) | ((b1 & 0x3f) as u16));
            i += 2;
        } else if (b0 & 0xf0) == 0xe0 {
            if i + 2 >= bytes.len() {
                return Err(DexError::Invalid("sequência MUTF-8 de 3 bytes truncada".into()));
            }
            let b1 = bytes[i + 1];
            let b2 = bytes[i + 2];
            if (b1 & 0xc0) != 0x80 || (b2 & 0xc0) != 0x80 {
                return Err(DexError::Invalid("bytes de continuação MUTF-8 inválidos".into()));
            }
            units.push(
                (((b0 & 0x0f) as u16) << 12) | (((b1 & 0x3f) as u16) << 6) | ((b2 & 0x3f) as u16),
            );
            i += 3;
        } else {
            return Err(DexError::Invalid(format!(
                "Byte inicial MUTF-8 inesperado 0x{b0:02x}"
            )));
        }
    }
    Ok(units)
}

fn type_shorty(desc: &str) -> char {
    match desc.chars().next() {
        Some('V') => 'V',
        Some('Z') => 'Z',
        Some('B') => 'B',
        Some('S') => 'S',
        Some('C') => 'C',
        Some('I') => 'I',
        Some('J') => 'J',
        Some('F') => 'F',
        Some('D') => 'D',
        _ => 'L',
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct FieldSpec {
    class_desc: &'static str,
    name: &'static str,
    type_desc: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct MethodSpec {
    class_desc: &'static str,
    name: &'static str,
    params: Vec<&'static str>,
    ret_desc: &'static str,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
enum InsnOp {
    Move(u8, u8),
    MoveObj(u8, u8),
    MoveResult(u8),
    MoveResultObj(u8),
    MoveException(u8),
    ReturnVoid,
    Return(u8),
    ReturnObj(u8),
    Const4(u8, i8),
    Const16(u8, i16),
    Const32(u8, i32),
    ConstString(u8, String),
    ConstClass(u8, &'static str),
    CheckCast(u8, &'static str),
    ArrayLength(u8, u8),
    NewInstance(u8, &'static str),
    NewArray(u8, u8, &'static str),
    Goto16(&'static str),
    IfEq(u8, u8, &'static str),
    IfNe(u8, u8, &'static str),
    IfLt(u8, u8, &'static str),
    IfGe(u8, u8, &'static str),
    IfGt(u8, u8, &'static str),
    IfEqz(u8, &'static str),
    IfNez(u8, &'static str),
    IfLtz(u8, &'static str),
    IfGez(u8, &'static str),
    IfGtz(u8, &'static str),
    IfLez(u8, &'static str),
    AgetObj(u8, u8, u8),
    AputObj(u8, u8, u8),
    Iget(u8, u8, FieldSpec),
    IgetObj(u8, u8, FieldSpec),
    Iput(u8, u8, FieldSpec),
    IputObj(u8, u8, FieldSpec),
    Sget(u8, FieldSpec),
    SgetObj(u8, FieldSpec),
    Sput(u8, FieldSpec),
    SputObj(u8, FieldSpec),
    InvokeVirtual(Vec<u8>, MethodSpec),
    InvokeSuper(Vec<u8>, MethodSpec),
    InvokeDirect(Vec<u8>, MethodSpec),
    InvokeStatic(Vec<u8>, MethodSpec),
    InvokeInterface(Vec<u8>, MethodSpec),
    InvokeVirtualRange(u8, u8, MethodSpec),
    AddInt(u8, u8, u8),
    SubInt(u8, u8, u8),
    OrInt(u8, u8, u8),
    AndIntLit16(u8, u8, i16),
    AddIntLit8(u8, u8, i8),
    ShlIntLit8(u8, u8, i8),
    UshrIntLit8(u8, u8, i8),
    Label(&'static str),
}

struct MethodDef {
    spec: MethodSpec,
    access_flags: u32,
    registers_size: u16,
    ins_size: u16,
    outs_size: u16,
    ops: Vec<InsnOp>,
    try_block: Option<(&'static str, &'static str, &'static str)>,
    annotated_js: bool,
}

struct ClassDefInput {
    desc: &'static str,
    super_desc: &'static str,
    interfaces: Vec<&'static str>,
    access_flags: u32,
    static_fields: Vec<(FieldSpec, u32)>,
    instance_fields: Vec<(FieldSpec, u32)>,
    direct_methods: Vec<MethodDef>,
    virtual_methods: Vec<MethodDef>,
}

fn mspec(
    class_desc: &'static str,
    name: &'static str,
    params: Vec<&'static str>,
    ret_desc: &'static str,
) -> MethodSpec {
    MethodSpec {
        class_desc,
        name,
        params,
        ret_desc,
    }
}

fn fspec(class_desc: &'static str, name: &'static str, type_desc: &'static str) -> FieldSpec {
    FieldSpec {
        class_desc,
        name,
        type_desc,
    }
}

fn insn_width(op: &InsnOp) -> usize {
    match op {
        InsnOp::Label(_) => 0,
        InsnOp::Move(_, _)
        | InsnOp::MoveObj(_, _)
        | InsnOp::MoveResult(_)
        | InsnOp::MoveResultObj(_)
        | InsnOp::MoveException(_)
        | InsnOp::ReturnVoid
        | InsnOp::Return(_)
        | InsnOp::ReturnObj(_)
        | InsnOp::Const4(_, _)
        | InsnOp::ArrayLength(_, _) => 1,
        InsnOp::Const16(_, _)
        | InsnOp::ConstString(_, _)
        | InsnOp::ConstClass(_, _)
        | InsnOp::CheckCast(_, _)
        | InsnOp::NewInstance(_, _)
        | InsnOp::NewArray(_, _, _)
        | InsnOp::Goto16(_)
        | InsnOp::IfEq(_, _, _)
        | InsnOp::IfNe(_, _, _)
        | InsnOp::IfLt(_, _, _)
        | InsnOp::IfGe(_, _, _)
        | InsnOp::IfGt(_, _, _)
        | InsnOp::IfEqz(_, _)
        | InsnOp::IfNez(_, _)
        | InsnOp::IfLtz(_, _)
        | InsnOp::IfGez(_, _)
        | InsnOp::IfGtz(_, _)
        | InsnOp::IfLez(_, _)
        | InsnOp::AgetObj(_, _, _)
        | InsnOp::AputObj(_, _, _)
        | InsnOp::Iget(_, _, _)
        | InsnOp::IgetObj(_, _, _)
        | InsnOp::Iput(_, _, _)
        | InsnOp::IputObj(_, _, _)
        | InsnOp::Sget(_, _)
        | InsnOp::SgetObj(_, _)
        | InsnOp::Sput(_, _)
        | InsnOp::SputObj(_, _)
        | InsnOp::AddInt(_, _, _)
        | InsnOp::SubInt(_, _, _)
        | InsnOp::OrInt(_, _, _)
        | InsnOp::AndIntLit16(_, _, _)
        | InsnOp::AddIntLit8(_, _, _)
        | InsnOp::ShlIntLit8(_, _, _)
        | InsnOp::UshrIntLit8(_, _, _) => 2,
        InsnOp::Const32(_, _)
        | InsnOp::InvokeVirtual(_, _)
        | InsnOp::InvokeSuper(_, _)
        | InsnOp::InvokeDirect(_, _)
        | InsnOp::InvokeStatic(_, _)
        | InsnOp::InvokeInterface(_, _)
        | InsnOp::InvokeVirtualRange(_, _, _) => 3,
    }
}

fn collect_refs_from_op(
    op: &InsnOp,
    strings: &mut BTreeSet<String>,
    types: &mut BTreeSet<String>,
    fields: &mut BTreeSet<FieldSpec>,
    methods: &mut BTreeSet<MethodSpec>,
) {
    let add_method = |m: &MethodSpec,
                      strings: &mut BTreeSet<String>,
                      types: &mut BTreeSet<String>,
                      methods: &mut BTreeSet<MethodSpec>| {
        strings.insert(m.name.to_string());
        types.insert(m.class_desc.to_string());
        types.insert(m.ret_desc.to_string());
        let mut shorty = String::new();
        shorty.push(type_shorty(m.ret_desc));
        for p in &m.params {
            types.insert((*p).to_string());
            shorty.push(type_shorty(p));
        }
        strings.insert(shorty);
        methods.insert(m.clone());
    };
    let add_field = |f: &FieldSpec,
                     strings: &mut BTreeSet<String>,
                     types: &mut BTreeSet<String>,
                     fields: &mut BTreeSet<FieldSpec>| {
        types.insert(f.class_desc.to_string());
        types.insert(f.type_desc.to_string());
        strings.insert(f.name.to_string());
        fields.insert(f.clone());
    };
    match op {
        InsnOp::ConstString(_, s) => {
            strings.insert(s.clone());
        }
        InsnOp::ConstClass(_, t)
        | InsnOp::CheckCast(_, t)
        | InsnOp::NewInstance(_, t)
        | InsnOp::NewArray(_, _, t) => {
            types.insert((*t).to_string());
        }
        InsnOp::Iget(_, _, f)
        | InsnOp::IgetObj(_, _, f)
        | InsnOp::Iput(_, _, f)
        | InsnOp::IputObj(_, _, f)
        | InsnOp::Sget(_, f)
        | InsnOp::SgetObj(_, f)
        | InsnOp::Sput(_, f)
        | InsnOp::SputObj(_, f) => add_field(f, strings, types, fields),
        InsnOp::InvokeVirtual(_, m)
        | InsnOp::InvokeSuper(_, m)
        | InsnOp::InvokeDirect(_, m)
        | InsnOp::InvokeStatic(_, m)
        | InsnOp::InvokeInterface(_, m)
        | InsnOp::InvokeVirtualRange(_, _, m) => add_method(m, strings, types, methods),
        _ => {}
    }
}

fn encode_35c(opcode: u8, regs: &[u8], method_idx: u16) -> [u16; 3] {
    assert!(regs.len() <= 5);
    let a = regs.len() as u16;
    let c = regs.first().copied().unwrap_or(0) as u16;
    let d = regs.get(1).copied().unwrap_or(0) as u16;
    let e = regs.get(2).copied().unwrap_or(0) as u16;
    let f = regs.get(3).copied().unwrap_or(0) as u16;
    let g = regs.get(4).copied().unwrap_or(0) as u16;
    assert!(c < 16 && d < 16 && e < 16 && f < 16 && g < 16);
    [
        (opcode as u16) | (g << 8) | (a << 12),
        method_idx,
        c | (d << 4) | (e << 8) | (f << 12),
    ]
}

fn build_classes() -> Vec<ClassDefInput> {
    const CLS_WVC: &str = "Lnetwork/mycelium/rhizome/RhizomeWebViewClient;";
    const CLS_SVC: &str = "Lnetwork/mycelium/rhizome/MyceliumService;";
    const CLS_TUN_WORKER: &str = "Lnetwork/mycelium/rhizome/VeilTunWorker;";
    const CLS_VPN: &str = "Lnetwork/mycelium/rhizome/VeilVpnService;";
    const CLS_BRIDGE: &str = "Lnetwork/mycelium/rhizome/MyceliumBridge;";
    const CLS_ACT: &str = "Lnetwork/mycelium/rhizome/MainActivity;";

    // Shared field specs
    let fld_proc = fspec(CLS_SVC, "proc", "Ljava/lang/Process;");
    let fld_native_dir = fspec(
        "Landroid/content/pm/ApplicationInfo;",
        "nativeLibraryDir",
        "Ljava/lang/String;",
    );
    let fld_tw_dir = fspec(CLS_TUN_WORKER, "dir", "I");
    let fld_tw_in = fspec(CLS_TUN_WORKER, "in", "Ljava/io/InputStream;");
    let fld_tw_out = fspec(CLS_TUN_WORKER, "out", "Ljava/io/OutputStream;");

    let fld_vpn_active = fspec(CLS_VPN, "active", "I");
    let fld_vpn_pfd = fspec(CLS_VPN, "tunPfd", "Landroid/os/ParcelFileDescriptor;");
    let fld_vpn_sock = fspec(CLS_VPN, "bridgeSock", "Ljava/net/Socket;");

    let fld_br_act = fspec(CLS_BRIDGE, "act", CLS_ACT);

    let fld_act_wv = fspec(CLS_ACT, "webView", "Landroid/webkit/WebView;");
    let fld_act_nfc_write = fspec(CLS_ACT, "pendingNfcWriteUri", "Ljava/lang/String;");
    let fld_act_tun_port = fspec(CLS_ACT, "pendingTunPort", "I");

    let m_wvc_init = mspec("Landroid/webkit/WebViewClient;", "<init>", vec![], "V");
    let m_rhizome_wvc_init = mspec(CLS_WVC, "<init>", vec![], "V");
    let m_vpn_close = mspec(CLS_VPN, "closeActive", vec![], "V");
    let m_act_dispatch_js = mspec(
        CLS_ACT,
        "dispatchJs",
        vec!["Ljava/lang/String;", "Ljava/lang/String;"],
        "V",
    );
    let m_act_handle_intent = mspec(
        CLS_ACT,
        "handleIntent",
        vec!["Landroid/content/Intent;"],
        "V",
    );

    // =========================================================================
    // Class 1: RhizomeWebViewClient
    // =========================================================================
    let cls_wvc = ClassDefInput {
        desc: CLS_WVC,
        super_desc: "Landroid/webkit/WebViewClient;",
        interfaces: vec![],
        access_flags: ACC_PUBLIC,
        static_fields: vec![],
        instance_fields: vec![],
        direct_methods: vec![MethodDef {
            spec: m_rhizome_wvc_init.clone(),
            access_flags: ACC_PUBLIC | ACC_CONSTRUCTOR,
            registers_size: 1,
            ins_size: 1,
            outs_size: 1,
            ops: vec![
                InsnOp::InvokeDirect(vec![0], m_wvc_init),
                InsnOp::ReturnVoid,
            ],
            try_block: None,
            annotated_js: false,
        }],
        virtual_methods: vec![MethodDef {
            spec: mspec(
                CLS_WVC,
                "shouldOverrideUrlLoading",
                vec!["Landroid/webkit/WebView;", "Ljava/lang/String;"],
                "Z",
            ),
            access_flags: ACC_PUBLIC,
            registers_size: 4,
            ins_size: 3,
            outs_size: 0,
            ops: vec![InsnOp::Const4(0, 0), InsnOp::Return(0)],
            try_block: None,
            annotated_js: false,
        }],
    };

    // =========================================================================
    // Class 2: MyceliumService (executa libmycelium_daemon.so estático)
    // =========================================================================
    let cls_svc = ClassDefInput {
        desc: CLS_SVC,
        super_desc: "Landroid/app/Service;",
        interfaces: vec![],
        access_flags: ACC_PUBLIC,
        static_fields: vec![],
        instance_fields: vec![(fld_proc.clone(), ACC_PRIVATE)],
        direct_methods: vec![MethodDef {
            spec: mspec(CLS_SVC, "<init>", vec![], "V"),
            access_flags: ACC_PUBLIC | ACC_CONSTRUCTOR,
            registers_size: 1,
            ins_size: 1,
            outs_size: 1,
            ops: vec![
                InsnOp::InvokeDirect(
                    vec![0],
                    mspec("Landroid/app/Service;", "<init>", vec![], "V"),
                ),
                InsnOp::ReturnVoid,
            ],
            try_block: None,
            annotated_js: false,
        }],
        virtual_methods: vec![
            MethodDef {
                spec: mspec(
                    CLS_SVC,
                    "onBind",
                    vec!["Landroid/content/Intent;"],
                    "Landroid/os/IBinder;",
                ),
                access_flags: ACC_PUBLIC,
                registers_size: 3,
                ins_size: 2,
                outs_size: 0,
                ops: vec![InsnOp::Const4(0, 0), InsnOp::ReturnObj(0)],
                try_block: None,
                annotated_js: false,
            },
            MethodDef {
                spec: mspec(CLS_SVC, "onDestroy", vec![], "V"),
                access_flags: ACC_PUBLIC,
                registers_size: 3,
                ins_size: 1,
                outs_size: 1,
                ops: vec![
                    InsnOp::InvokeSuper(
                        vec![2],
                        mspec("Landroid/app/Service;", "onDestroy", vec![], "V"),
                    ),
                    InsnOp::IgetObj(0, 2, fld_proc.clone()),
                    InsnOp::IfEqz(0, "done"),
                    InsnOp::InvokeVirtual(
                        vec![0],
                        mspec("Ljava/lang/Process;", "destroy", vec![], "V"),
                    ),
                    InsnOp::Const4(1, 0),
                    InsnOp::IputObj(1, 2, fld_proc.clone()),
                    InsnOp::Label("done"),
                    InsnOp::ReturnVoid,
                ],
                try_block: None,
                annotated_js: false,
            },
            MethodDef {
                spec: mspec(
                    CLS_SVC,
                    "onStartCommand",
                    vec!["Landroid/content/Intent;", "I", "I"],
                    "I",
                ),
                access_flags: ACC_PUBLIC,
                registers_size: 14,
                ins_size: 4, // v10=this, v11=intent, v12=flags, v13=startId
                outs_size: 3,
                ops: vec![
                    InsnOp::IgetObj(0, 10, fld_proc.clone()),
                    InsnOp::IfNez(0, "ret_sticky"),
                    InsnOp::Label("try_start"),
                    InsnOp::InvokeVirtual(
                        vec![10],
                        mspec("Landroid/content/Context;", "getFilesDir", vec![], "Ljava/io/File;"),
                    ),
                    InsnOp::MoveResultObj(0),
                    InsnOp::NewInstance(9, "Ljava/io/File;"),
                    InsnOp::ConstString(2, "mycelium".into()),
                    InsnOp::InvokeDirect(
                        vec![9, 0, 2],
                        mspec(
                            "Ljava/io/File;",
                            "<init>",
                            vec!["Ljava/io/File;", "Ljava/lang/String;"],
                            "V",
                        ),
                    ),
                    InsnOp::InvokeVirtual(vec![9], mspec("Ljava/io/File;", "mkdirs", vec![], "Z")),
                    InsnOp::InvokeVirtual(
                        vec![9],
                        mspec("Ljava/io/File;", "getAbsolutePath", vec![], "Ljava/lang/String;"),
                    ),
                    InsnOp::MoveResultObj(1),
                    InsnOp::InvokeVirtual(
                        vec![10],
                        mspec(
                            "Landroid/content/Context;",
                            "getApplicationInfo",
                            vec![],
                            "Landroid/content/pm/ApplicationInfo;",
                        ),
                    ),
                    InsnOp::MoveResultObj(0),
                    InsnOp::IgetObj(0, 0, fld_native_dir),
                    InsnOp::NewInstance(2, "Ljava/lang/StringBuilder;"),
                    InsnOp::InvokeDirect(
                        vec![2],
                        mspec("Ljava/lang/StringBuilder;", "<init>", vec![], "V"),
                    ),
                    InsnOp::InvokeVirtual(
                        vec![2, 0],
                        mspec(
                            "Ljava/lang/StringBuilder;",
                            "append",
                            vec!["Ljava/lang/String;"],
                            "Ljava/lang/StringBuilder;",
                        ),
                    ),
                    InsnOp::ConstString(3, "/libmycelium_daemon.so".into()),
                    InsnOp::InvokeVirtual(
                        vec![2, 3],
                        mspec(
                            "Ljava/lang/StringBuilder;",
                            "append",
                            vec!["Ljava/lang/String;"],
                            "Ljava/lang/StringBuilder;",
                        ),
                    ),
                    InsnOp::InvokeVirtual(
                        vec![2],
                        mspec("Ljava/lang/StringBuilder;", "toString", vec![], "Ljava/lang/String;"),
                    ),
                    InsnOp::MoveResultObj(2),
                    InsnOp::ConstString(7, "MyceliumService".into()),
                    InsnOp::InvokeStatic(
                        vec![7, 2],
                        mspec(
                            "Landroid/util/Log;",
                            "i",
                            vec!["Ljava/lang/String;", "Ljava/lang/String;"],
                            "I",
                        ),
                    ),
                    InsnOp::Const4(4, 6),
                    InsnOp::NewArray(3, 4, "[Ljava/lang/String;"),
                    InsnOp::Const4(4, 0),
                    InsnOp::AputObj(2, 3, 4),
                    InsnOp::Const4(4, 1),
                    InsnOp::ConstString(5, "--home".into()),
                    InsnOp::AputObj(5, 3, 4),
                    InsnOp::Const4(4, 2),
                    InsnOp::AputObj(1, 3, 4),
                    InsnOp::Const4(4, 3),
                    InsnOp::ConstString(5, "daemon".into()),
                    InsnOp::AputObj(5, 3, 4),
                    InsnOp::Const4(4, 4),
                    InsnOp::ConstString(5, "--horizon-port".into()),
                    InsnOp::AputObj(5, 3, 4),
                    InsnOp::Const4(4, 5),
                    InsnOp::ConstString(5, "7474".into()),
                    InsnOp::AputObj(5, 3, 4),
                    InsnOp::InvokeStatic(
                        vec![3],
                        mspec(
                            "Ljava/util/Arrays;",
                            "asList",
                            vec!["[Ljava/lang/Object;"],
                            "Ljava/util/List;",
                        ),
                    ),
                    InsnOp::MoveResultObj(4),
                    InsnOp::NewInstance(5, "Ljava/lang/ProcessBuilder;"),
                    InsnOp::InvokeDirect(
                        vec![5, 4],
                        mspec(
                            "Ljava/lang/ProcessBuilder;",
                            "<init>",
                            vec!["Ljava/util/List;"],
                            "V",
                        ),
                    ),
                    InsnOp::InvokeVirtual(
                        vec![5],
                        mspec(
                            "Ljava/lang/ProcessBuilder;",
                            "environment",
                            vec![],
                            "Ljava/util/Map;",
                        ),
                    ),
                    InsnOp::MoveResultObj(6),
                    InsnOp::ConstString(7, "MYCELIUM_ANDROID".into()),
                    InsnOp::ConstString(8, "1".into()),
                    InsnOp::InvokeInterface(
                        vec![6, 7, 8],
                        mspec(
                            "Ljava/util/Map;",
                            "put",
                            vec!["Ljava/lang/Object;", "Ljava/lang/Object;"],
                            "Ljava/lang/Object;",
                        ),
                    ),
                    InsnOp::ConstString(7, "MYCELIUM_HOME".into()),
                    InsnOp::InvokeInterface(
                        vec![6, 7, 1],
                        mspec(
                            "Ljava/util/Map;",
                            "put",
                            vec!["Ljava/lang/Object;", "Ljava/lang/Object;"],
                            "Ljava/lang/Object;",
                        ),
                    ),
                    InsnOp::ConstString(7, "HOME".into()),
                    InsnOp::InvokeInterface(
                        vec![6, 7, 1],
                        mspec(
                            "Ljava/util/Map;",
                            "put",
                            vec!["Ljava/lang/Object;", "Ljava/lang/Object;"],
                            "Ljava/lang/Object;",
                        ),
                    ),
                    InsnOp::Const4(7, 1),
                    InsnOp::InvokeVirtual(
                        vec![5, 7],
                        mspec(
                            "Ljava/lang/ProcessBuilder;",
                            "redirectErrorStream",
                            vec!["Z"],
                            "Ljava/lang/ProcessBuilder;",
                        ),
                    ),
                    InsnOp::NewInstance(7, "Ljava/io/File;"),
                    InsnOp::ConstString(8, "daemon.log".into()),
                    InsnOp::InvokeDirect(
                        vec![7, 9, 8],
                        mspec(
                            "Ljava/io/File;",
                            "<init>",
                            vec!["Ljava/io/File;", "Ljava/lang/String;"],
                            "V",
                        ),
                    ),
                    InsnOp::InvokeVirtual(
                        vec![5, 7],
                        mspec(
                            "Ljava/lang/ProcessBuilder;",
                            "redirectOutput",
                            vec!["Ljava/io/File;"],
                            "Ljava/lang/ProcessBuilder;",
                        ),
                    ),
                    InsnOp::InvokeVirtual(
                        vec![5],
                        mspec(
                            "Ljava/lang/ProcessBuilder;",
                            "start",
                            vec![],
                            "Ljava/lang/Process;",
                        ),
                    ),
                    InsnOp::MoveResultObj(0),
                    InsnOp::IputObj(0, 10, fld_proc),
                    InsnOp::Label("try_end"),
                    InsnOp::Label("ret_sticky"),
                    InsnOp::Const4(0, 1),
                    InsnOp::Return(0),
                    InsnOp::Label("catch_all"),
                    InsnOp::MoveException(0),
                    InsnOp::ConstString(1, "MyceliumService".into()),
                    InsnOp::ConstString(2, "daemon launch failed".into()),
                    InsnOp::InvokeStatic(
                        vec![1, 2, 0],
                        mspec(
                            "Landroid/util/Log;",
                            "e",
                            vec!["Ljava/lang/String;", "Ljava/lang/String;", "Ljava/lang/Throwable;"],
                            "I",
                        ),
                    ),
                    InsnOp::Const4(0, 1),
                    InsnOp::Return(0),
                ],
                try_block: Some(("try_start", "try_end", "catch_all")),
                annotated_js: false,
            },
        ],
    };

    // =========================================================================
    // Class 3: VeilTunWorker implements Runnable (bombeia IPv4 TUN <-> TCP loopback)
    // =========================================================================
    let m_tw_init = mspec(
        CLS_TUN_WORKER,
        "<init>",
        vec!["I", "Ljava/io/InputStream;", "Ljava/io/OutputStream;"],
        "V",
    );
    let cls_tun_worker = ClassDefInput {
        desc: CLS_TUN_WORKER,
        super_desc: "Ljava/lang/Object;",
        interfaces: vec!["Ljava/lang/Runnable;"],
        access_flags: ACC_PUBLIC,
        static_fields: vec![],
        instance_fields: vec![
            (fld_tw_dir.clone(), ACC_PRIVATE),
            (fld_tw_in.clone(), ACC_PRIVATE),
            (fld_tw_out.clone(), ACC_PRIVATE),
        ],
        direct_methods: vec![MethodDef {
            spec: m_tw_init.clone(),
            access_flags: ACC_PUBLIC | ACC_CONSTRUCTOR,
            registers_size: 4,
            ins_size: 4, // v0=this, v1=dir, v2=in, v3=out
            outs_size: 1,
            ops: vec![
                InsnOp::InvokeDirect(vec![0], mspec("Ljava/lang/Object;", "<init>", vec![], "V")),
                InsnOp::Iput(1, 0, fld_tw_dir.clone()),
                InsnOp::IputObj(2, 0, fld_tw_in.clone()),
                InsnOp::IputObj(3, 0, fld_tw_out.clone()),
                InsnOp::ReturnVoid,
            ],
            try_block: None,
            annotated_js: false,
        }],
        virtual_methods: vec![MethodDef {
            spec: mspec(CLS_TUN_WORKER, "run", vec![], "V"),
            access_flags: ACC_PUBLIC,
            registers_size: 9,
            ins_size: 1, // v8 = this
            outs_size: 4,
            ops: vec![
                InsnOp::Label("try_start"),
                InsnOp::IgetObj(0, 8, fld_tw_in),
                InsnOp::IgetObj(1, 8, fld_tw_out),
                InsnOp::Iget(2, 8, fld_tw_dir),
                InsnOp::Const16(3, 4096),
                InsnOp::NewArray(4, 3, "[B"),
                InsnOp::IfNez(2, "downlink"),
                // Uplink (dir == 0): TUN -> [u16_be len][pkt] -> daemon TCP
                InsnOp::Label("up_loop"),
                InsnOp::InvokeVirtual(
                    vec![0, 4],
                    mspec("Ljava/io/InputStream;", "read", vec!["[B"], "I"),
                ),
                InsnOp::MoveResult(5),
                InsnOp::IfLez(5, "done"),
                InsnOp::UshrIntLit8(6, 5, 8),
                InsnOp::AndIntLit16(6, 6, 0xff),
                InsnOp::InvokeVirtual(
                    vec![1, 6],
                    mspec("Ljava/io/OutputStream;", "write", vec!["I"], "V"),
                ),
                InsnOp::AndIntLit16(6, 5, 0xff),
                InsnOp::InvokeVirtual(
                    vec![1, 6],
                    mspec("Ljava/io/OutputStream;", "write", vec!["I"], "V"),
                ),
                InsnOp::Const4(6, 0),
                InsnOp::InvokeVirtual(
                    vec![1, 4, 6, 5],
                    mspec("Ljava/io/OutputStream;", "write", vec!["[B", "I", "I"], "V"),
                ),
                InsnOp::InvokeVirtual(
                    vec![1],
                    mspec("Ljava/io/OutputStream;", "flush", vec![], "V"),
                ),
                InsnOp::Goto16("up_loop"),
                // Downlink (dir == 1): daemon TCP [u16_be len][pkt] -> TUN
                InsnOp::Label("downlink"),
                InsnOp::InvokeVirtual(vec![0], mspec("Ljava/io/InputStream;", "read", vec![], "I")),
                InsnOp::MoveResult(5),
                InsnOp::IfLtz(5, "done"),
                InsnOp::InvokeVirtual(vec![0], mspec("Ljava/io/InputStream;", "read", vec![], "I")),
                InsnOp::MoveResult(6),
                InsnOp::IfLtz(6, "done"),
                InsnOp::ShlIntLit8(5, 5, 8),
                InsnOp::OrInt(5, 5, 6), // v5 = pkt_len
                InsnOp::IfLez(5, "downlink"),
                InsnOp::IfGt(5, 3, "done"), // > 4096
                InsnOp::Const4(6, 0),       // v6 = off
                InsnOp::Label("dl_read"),
                InsnOp::IfGe(6, 5, "dl_write"),
                InsnOp::SubInt(7, 5, 6),
                InsnOp::InvokeVirtual(
                    vec![0, 4, 6, 7],
                    mspec("Ljava/io/InputStream;", "read", vec!["[B", "I", "I"], "I"),
                ),
                InsnOp::MoveResult(7),
                InsnOp::IfLez(7, "done"),
                InsnOp::AddInt(6, 6, 7),
                InsnOp::Goto16("dl_read"),
                InsnOp::Label("dl_write"),
                InsnOp::Const4(6, 0),
                InsnOp::InvokeVirtual(
                    vec![1, 4, 6, 5],
                    mspec("Ljava/io/OutputStream;", "write", vec!["[B", "I", "I"], "V"),
                ),
                InsnOp::Goto16("downlink"),
                InsnOp::Label("done"),
                InsnOp::Label("try_end"),
                InsnOp::ReturnVoid,
                InsnOp::Label("catch_all"),
                InsnOp::MoveException(0),
                InsnOp::ReturnVoid,
            ],
            try_block: Some(("try_start", "try_end", "catch_all")),
            annotated_js: false,
        }],
    };

    // =========================================================================
    // Class 4: VeilVpnService extends android.net.VpnService
    // =========================================================================
    let cls_vpn = ClassDefInput {
        desc: CLS_VPN,
        super_desc: "Landroid/net/VpnService;",
        interfaces: vec![],
        access_flags: ACC_PUBLIC,
        static_fields: vec![
            (fld_vpn_active.clone(), ACC_PUBLIC | ACC_STATIC),
            (fld_vpn_pfd.clone(), ACC_PUBLIC | ACC_STATIC),
            (fld_vpn_sock.clone(), ACC_PUBLIC | ACC_STATIC),
        ],
        instance_fields: vec![],
        direct_methods: vec![
            MethodDef {
                spec: mspec(CLS_VPN, "<init>", vec![], "V"),
                access_flags: ACC_PUBLIC | ACC_CONSTRUCTOR,
                registers_size: 1,
                ins_size: 1,
                outs_size: 1,
                ops: vec![
                    InsnOp::InvokeDirect(
                        vec![0],
                        mspec("Landroid/net/VpnService;", "<init>", vec![], "V"),
                    ),
                    InsnOp::ReturnVoid,
                ],
                try_block: None,
                annotated_js: false,
            },
            MethodDef {
                spec: m_vpn_close.clone(),
                access_flags: ACC_PUBLIC | ACC_STATIC,
                registers_size: 2,
                ins_size: 0,
                outs_size: 1,
                ops: vec![
                    InsnOp::Const4(0, 0),
                    InsnOp::Sput(0, fld_vpn_active.clone()),
                    InsnOp::Label("try_start"),
                    InsnOp::SgetObj(0, fld_vpn_sock.clone()),
                    InsnOp::IfEqz(0, "c_tun"),
                    InsnOp::InvokeVirtual(vec![0], mspec("Ljava/net/Socket;", "close", vec![], "V")),
                    InsnOp::Const4(1, 0),
                    InsnOp::SputObj(1, fld_vpn_sock.clone()),
                    InsnOp::Label("c_tun"),
                    InsnOp::SgetObj(0, fld_vpn_pfd.clone()),
                    InsnOp::IfEqz(0, "c_end"),
                    InsnOp::InvokeVirtual(
                        vec![0],
                        mspec("Landroid/os/ParcelFileDescriptor;", "close", vec![], "V"),
                    ),
                    InsnOp::Const4(1, 0),
                    InsnOp::SputObj(1, fld_vpn_pfd.clone()),
                    InsnOp::Label("c_end"),
                    InsnOp::Label("try_end"),
                    InsnOp::ReturnVoid,
                    InsnOp::Label("catch_all"),
                    InsnOp::MoveException(0),
                    InsnOp::ReturnVoid,
                ],
                try_block: Some(("try_start", "try_end", "catch_all")),
                annotated_js: false,
            },
        ],
        virtual_methods: vec![
            MethodDef {
                spec: mspec(CLS_VPN, "onDestroy", vec![], "V"),
                access_flags: ACC_PUBLIC,
                registers_size: 2,
                ins_size: 1, // v1 = this
                outs_size: 1,
                ops: vec![
                    InsnOp::InvokeStatic(vec![], m_vpn_close.clone()),
                    InsnOp::InvokeSuper(
                        vec![1],
                        mspec("Landroid/net/VpnService;", "onDestroy", vec![], "V"),
                    ),
                    InsnOp::ReturnVoid,
                ],
                try_block: None,
                annotated_js: false,
            },
            MethodDef {
                spec: mspec(
                    CLS_VPN,
                    "onStartCommand",
                    vec!["Landroid/content/Intent;", "I", "I"],
                    "I",
                ),
                access_flags: ACC_PUBLIC,
                registers_size: 12,
                ins_size: 4, // v8=this, v9=intent, v10=flags, v11=startId
                outs_size: 4,
                ops: vec![
                    InsnOp::InvokeStatic(vec![], m_vpn_close.clone()),
                    InsnOp::IfEqz(9, "stop_now"),
                    InsnOp::ConstString(0, "tun_port".into()),
                    InsnOp::Const4(1, 0),
                    InsnOp::InvokeVirtual(
                        vec![9, 0, 1],
                        mspec("Landroid/content/Intent;", "getIntExtra", vec!["Ljava/lang/String;", "I"], "I"),
                    ),
                    InsnOp::MoveResult(0), // v0 = tun_port
                    InsnOp::IfLez(0, "stop_now"),
                    InsnOp::Label("try_start"),
                    InsnOp::NewInstance(1, "Landroid/net/VpnService$Builder;"),
                    InsnOp::InvokeDirect(
                        vec![1, 8],
                        mspec(
                            "Landroid/net/VpnService$Builder;",
                            "<init>",
                            vec!["Landroid/net/VpnService;"],
                            "V",
                        ),
                    ),
                    InsnOp::ConstString(2, "VEIL Post-Quantum VPN".into()),
                    InsnOp::InvokeVirtual(
                        vec![1, 2],
                        mspec(
                            "Landroid/net/VpnService$Builder;",
                            "setSession",
                            vec!["Ljava/lang/String;"],
                            "Landroid/net/VpnService$Builder;",
                        ),
                    ),
                    InsnOp::ConstString(2, "10.240.0.2".into()),
                    InsnOp::Const16(3, 32),
                    InsnOp::InvokeVirtual(
                        vec![1, 2, 3],
                        mspec(
                            "Landroid/net/VpnService$Builder;",
                            "addAddress",
                            vec!["Ljava/lang/String;", "I"],
                            "Landroid/net/VpnService$Builder;",
                        ),
                    ),
                    InsnOp::ConstString(2, "0.0.0.0".into()),
                    InsnOp::Const4(3, 0),
                    InsnOp::InvokeVirtual(
                        vec![1, 2, 3],
                        mspec(
                            "Landroid/net/VpnService$Builder;",
                            "addRoute",
                            vec!["Ljava/lang/String;", "I"],
                            "Landroid/net/VpnService$Builder;",
                        ),
                    ),
                    InsnOp::ConstString(2, "9.9.9.9".into()),
                    InsnOp::InvokeVirtual(
                        vec![1, 2],
                        mspec(
                            "Landroid/net/VpnService$Builder;",
                            "addDnsServer",
                            vec!["Ljava/lang/String;"],
                            "Landroid/net/VpnService$Builder;",
                        ),
                    ),
                    InsnOp::Const16(2, 1500),
                    InsnOp::InvokeVirtual(
                        vec![1, 2],
                        mspec(
                            "Landroid/net/VpnService$Builder;",
                            "setMtu",
                            vec!["I"],
                            "Landroid/net/VpnService$Builder;",
                        ),
                    ),
                    InsnOp::ConstString(2, "network.mycelium.rhizome".into()),
                    InsnOp::InvokeVirtual(
                        vec![1, 2],
                        mspec(
                            "Landroid/net/VpnService$Builder;",
                            "addDisallowedApplication",
                            vec!["Ljava/lang/String;"],
                            "Landroid/net/VpnService$Builder;",
                        ),
                    ),
                    InsnOp::InvokeVirtual(
                        vec![1],
                        mspec(
                            "Landroid/net/VpnService$Builder;",
                            "establish",
                            vec![],
                            "Landroid/os/ParcelFileDescriptor;",
                        ),
                    ),
                    InsnOp::MoveResultObj(2), // v2 = pfd
                    InsnOp::IfEqz(2, "stop_now"),
                    InsnOp::NewInstance(3, "Ljava/net/Socket;"),
                    InsnOp::ConstString(4, "127.0.0.1".into()),
                    InsnOp::InvokeDirect(
                        vec![3, 4, 0],
                        mspec("Ljava/net/Socket;", "<init>", vec!["Ljava/lang/String;", "I"], "V"),
                    ),
                    InsnOp::SputObj(2, fld_vpn_pfd),
                    InsnOp::SputObj(3, fld_vpn_sock),
                    InsnOp::Const4(4, 1),
                    InsnOp::Sput(4, fld_vpn_active.clone()),
                    InsnOp::InvokeVirtual(
                        vec![2],
                        mspec(
                            "Landroid/os/ParcelFileDescriptor;",
                            "getFileDescriptor",
                            vec![],
                            "Ljava/io/FileDescriptor;",
                        ),
                    ),
                    InsnOp::MoveResultObj(2),
                    InsnOp::NewInstance(4, "Ljava/io/FileInputStream;"),
                    InsnOp::InvokeDirect(
                        vec![4, 2],
                        mspec("Ljava/io/FileInputStream;", "<init>", vec!["Ljava/io/FileDescriptor;"], "V"),
                    ),
                    InsnOp::NewInstance(5, "Ljava/io/FileOutputStream;"),
                    InsnOp::InvokeDirect(
                        vec![5, 2],
                        mspec("Ljava/io/FileOutputStream;", "<init>", vec!["Ljava/io/FileDescriptor;"], "V"),
                    ),
                    InsnOp::InvokeVirtual(
                        vec![3],
                        mspec("Ljava/net/Socket;", "getInputStream", vec![], "Ljava/io/InputStream;"),
                    ),
                    InsnOp::MoveResultObj(6),
                    InsnOp::InvokeVirtual(
                        vec![3],
                        mspec("Ljava/net/Socket;", "getOutputStream", vec![], "Ljava/io/OutputStream;"),
                    ),
                    InsnOp::MoveResultObj(7),
                    // Thread Uplink (dir=0): tunIn (v4) -> sockOut (v7)
                    InsnOp::NewInstance(1, CLS_TUN_WORKER),
                    InsnOp::Const4(2, 0),
                    InsnOp::InvokeDirect(vec![1, 2, 4, 7], m_tw_init.clone()),
                    InsnOp::NewInstance(2, "Ljava/lang/Thread;"),
                    InsnOp::InvokeDirect(
                        vec![2, 1],
                        mspec("Ljava/lang/Thread;", "<init>", vec!["Ljava/lang/Runnable;"], "V"),
                    ),
                    InsnOp::InvokeVirtual(vec![2], mspec("Ljava/lang/Thread;", "start", vec![], "V")),
                    // Thread Downlink (dir=1): sockIn (v6) -> tunOut (v5)
                    InsnOp::NewInstance(1, CLS_TUN_WORKER),
                    InsnOp::Const4(2, 1),
                    InsnOp::InvokeDirect(vec![1, 2, 6, 5], m_tw_init),
                    InsnOp::NewInstance(2, "Ljava/lang/Thread;"),
                    InsnOp::InvokeDirect(
                        vec![2, 1],
                        mspec("Ljava/lang/Thread;", "<init>", vec!["Ljava/lang/Runnable;"], "V"),
                    ),
                    InsnOp::InvokeVirtual(vec![2], mspec("Ljava/lang/Thread;", "start", vec![], "V")),
                    InsnOp::Const4(0, 1),
                    InsnOp::Return(0),
                    InsnOp::Label("try_end"),
                    InsnOp::Label("stop_now"),
                    InsnOp::InvokeVirtual(vec![8], mspec("Landroid/app/Service;", "stopSelf", vec![], "V")),
                    InsnOp::Const4(0, 2),
                    InsnOp::Return(0),
                    InsnOp::Label("catch_all"),
                    InsnOp::MoveException(0),
                    InsnOp::ConstString(1, "VeilVpnService".into()),
                    InsnOp::ConstString(2, "VPN tunnel error".into()),
                    InsnOp::InvokeStatic(
                        vec![1, 2, 0],
                        mspec(
                            "Landroid/util/Log;",
                            "e",
                            vec!["Ljava/lang/String;", "Ljava/lang/String;", "Ljava/lang/Throwable;"],
                            "I",
                        ),
                    ),
                    InsnOp::InvokeStatic(vec![], m_vpn_close),
                    InsnOp::Const4(0, 2),
                    InsnOp::Return(0),
                ],
                try_block: Some(("try_start", "try_end", "catch_all")),
                annotated_js: false,
            },
        ],
    };

    // =========================================================================
    // Class 5: MyceliumBridge (@JavascriptInterface exposto como window.MyceliumNative)
    // =========================================================================
    let m_bridge_init = mspec(CLS_BRIDGE, "<init>", vec![CLS_ACT], "V");
    let cls_bridge = ClassDefInput {
        desc: CLS_BRIDGE,
        super_desc: "Ljava/lang/Object;",
        interfaces: vec![],
        access_flags: ACC_PUBLIC,
        static_fields: vec![],
        instance_fields: vec![(fld_br_act.clone(), ACC_PRIVATE)],
        direct_methods: vec![MethodDef {
            spec: m_bridge_init.clone(),
            access_flags: ACC_PUBLIC | ACC_CONSTRUCTOR,
            registers_size: 2,
            ins_size: 2, // v0=this, v1=act
            outs_size: 1,
            ops: vec![
                InsnOp::InvokeDirect(vec![0], mspec("Ljava/lang/Object;", "<init>", vec![], "V")),
                InsnOp::IputObj(1, 0, fld_br_act.clone()),
                InsnOp::ReturnVoid,
            ],
            try_block: None,
            annotated_js: false,
        }],
        virtual_methods: vec![
            // 1. isNfcAvailable()Z
            MethodDef {
                spec: mspec(CLS_BRIDGE, "isNfcAvailable", vec![], "Z"),
                access_flags: ACC_PUBLIC,
                registers_size: 3,
                ins_size: 1, // v2=this
                outs_size: 1,
                ops: vec![
                    InsnOp::Label("try_start"),
                    InsnOp::IgetObj(0, 2, fld_br_act.clone()),
                    InsnOp::InvokeStatic(
                        vec![0],
                        mspec(
                            "Landroid/nfc/NfcAdapter;",
                            "getDefaultAdapter",
                            vec!["Landroid/content/Context;"],
                            "Landroid/nfc/NfcAdapter;",
                        ),
                    ),
                    InsnOp::MoveResultObj(0),
                    InsnOp::IfEqz(0, "ret_false"),
                    InsnOp::Const4(0, 1),
                    InsnOp::Return(0),
                    InsnOp::Label("try_end"),
                    InsnOp::Label("catch_all"),
                    InsnOp::MoveException(0),
                    InsnOp::Label("ret_false"),
                    InsnOp::Const4(0, 0),
                    InsnOp::Return(0),
                ],
                try_block: Some(("try_start", "try_end", "catch_all")),
                annotated_js: true,
            },
            // 2. isNfcEnabled()Z
            MethodDef {
                spec: mspec(CLS_BRIDGE, "isNfcEnabled", vec![], "Z"),
                access_flags: ACC_PUBLIC,
                registers_size: 3,
                ins_size: 1, // v2=this
                outs_size: 1,
                ops: vec![
                    InsnOp::Label("try_start"),
                    InsnOp::IgetObj(0, 2, fld_br_act.clone()),
                    InsnOp::InvokeStatic(
                        vec![0],
                        mspec(
                            "Landroid/nfc/NfcAdapter;",
                            "getDefaultAdapter",
                            vec!["Landroid/content/Context;"],
                            "Landroid/nfc/NfcAdapter;",
                        ),
                    ),
                    InsnOp::MoveResultObj(0),
                    InsnOp::IfEqz(0, "ret_false"),
                    InsnOp::InvokeVirtual(
                        vec![0],
                        mspec("Landroid/nfc/NfcAdapter;", "isEnabled", vec![], "Z"),
                    ),
                    InsnOp::MoveResult(0),
                    InsnOp::Return(0),
                    InsnOp::Label("try_end"),
                    InsnOp::Label("catch_all"),
                    InsnOp::MoveException(0),
                    InsnOp::Label("ret_false"),
                    InsnOp::Const4(0, 0),
                    InsnOp::Return(0),
                ],
                try_block: Some(("try_start", "try_end", "catch_all")),
                annotated_js: true,
            },
            // 3. isVpnActive()Z
            MethodDef {
                spec: mspec(CLS_BRIDGE, "isVpnActive", vec![], "Z"),
                access_flags: ACC_PUBLIC,
                registers_size: 2,
                ins_size: 1, // v1=this
                outs_size: 0,
                ops: vec![
                    InsnOp::Sget(0, fld_vpn_active),
                    InsnOp::IfEqz(0, "ret_false"),
                    InsnOp::Const4(0, 1),
                    InsnOp::Return(0),
                    InsnOp::Label("ret_false"),
                    InsnOp::Const4(0, 0),
                    InsnOp::Return(0),
                ],
                try_block: None,
                annotated_js: true,
            },
            // 4. armNfcWrite(String uri)Z
            MethodDef {
                spec: mspec(CLS_BRIDGE, "armNfcWrite", vec!["Ljava/lang/String;"], "Z"),
                access_flags: ACC_PUBLIC,
                registers_size: 4,
                ins_size: 2, // v2=this, v3=uri
                outs_size: 0,
                ops: vec![
                    InsnOp::IgetObj(0, 2, fld_br_act.clone()),
                    InsnOp::IputObj(3, 0, fld_act_nfc_write.clone()),
                    InsnOp::Const4(0, 1),
                    InsnOp::Return(0),
                ],
                try_block: None,
                annotated_js: true,
            },
            // 5. cancelNfcWrite()V
            MethodDef {
                spec: mspec(CLS_BRIDGE, "cancelNfcWrite", vec![], "V"),
                access_flags: ACC_PUBLIC,
                registers_size: 3,
                ins_size: 1, // v2=this
                outs_size: 0,
                ops: vec![
                    InsnOp::IgetObj(0, 2, fld_br_act.clone()),
                    InsnOp::Const4(1, 0),
                    InsnOp::IputObj(1, 0, fld_act_nfc_write.clone()),
                    InsnOp::ReturnVoid,
                ],
                try_block: None,
                annotated_js: true,
            },
            // 6. startSystemVpn(int tunPort)String
            MethodDef {
                spec: mspec(CLS_BRIDGE, "startSystemVpn", vec!["I"], "Ljava/lang/String;"),
                access_flags: ACC_PUBLIC,
                registers_size: 7,
                ins_size: 2, // v5=this, v6=tunPort
                outs_size: 3,
                ops: vec![
                    InsnOp::Label("try_start"),
                    InsnOp::IgetObj(0, 5, fld_br_act.clone()), // v0 = act
                    InsnOp::Iput(6, 0, fld_act_tun_port.clone()),
                    InsnOp::InvokeStatic(
                        vec![0],
                        mspec(
                            "Landroid/net/VpnService;",
                            "prepare",
                            vec!["Landroid/content/Context;"],
                            "Landroid/content/Intent;",
                        ),
                    ),
                    InsnOp::MoveResultObj(1), // v1 = prepIntent
                    InsnOp::IfEqz(1, "already_ok"),
                    InsnOp::Const16(2, 7474),
                    InsnOp::InvokeVirtual(
                        vec![0, 1, 2],
                        mspec(
                            "Landroid/app/Activity;",
                            "startActivityForResult",
                            vec!["Landroid/content/Intent;", "I"],
                            "V",
                        ),
                    ),
                    InsnOp::ConstString(0, "consent_requested".into()),
                    InsnOp::ReturnObj(0),
                    InsnOp::Label("already_ok"),
                    InsnOp::NewInstance(1, "Landroid/content/Intent;"),
                    InsnOp::ConstClass(2, CLS_VPN),
                    InsnOp::InvokeDirect(
                        vec![1, 0, 2],
                        mspec(
                            "Landroid/content/Intent;",
                            "<init>",
                            vec!["Landroid/content/Context;", "Ljava/lang/Class;"],
                            "V",
                        ),
                    ),
                    InsnOp::ConstString(2, "tun_port".into()),
                    InsnOp::InvokeVirtual(
                        vec![1, 2, 6],
                        mspec(
                            "Landroid/content/Intent;",
                            "putExtra",
                            vec!["Ljava/lang/String;", "I"],
                            "Landroid/content/Intent;",
                        ),
                    ),
                    InsnOp::InvokeVirtual(
                        vec![0, 1],
                        mspec(
                            "Landroid/content/Context;",
                            "startService",
                            vec!["Landroid/content/Intent;"],
                            "Landroid/content/ComponentName;",
                        ),
                    ),
                    InsnOp::ConstString(0, "started".into()),
                    InsnOp::ReturnObj(0),
                    InsnOp::Label("try_end"),
                    InsnOp::Label("catch_all"),
                    InsnOp::MoveException(0),
                    InsnOp::InvokeVirtual(
                        vec![0],
                        mspec("Ljava/lang/Throwable;", "toString", vec![], "Ljava/lang/String;"),
                    ),
                    InsnOp::MoveResultObj(0),
                    InsnOp::ReturnObj(0),
                ],
                try_block: Some(("try_start", "try_end", "catch_all")),
                annotated_js: true,
            },
            // 7. stopSystemVpn()Z
            MethodDef {
                spec: mspec(CLS_BRIDGE, "stopSystemVpn", vec![], "Z"),
                access_flags: ACC_PUBLIC,
                registers_size: 5,
                ins_size: 1, // v4=this
                outs_size: 3,
                ops: vec![
                    InsnOp::Label("try_start"),
                    InsnOp::IgetObj(0, 4, fld_br_act.clone()),
                    InsnOp::NewInstance(1, "Landroid/content/Intent;"),
                    InsnOp::ConstClass(2, CLS_VPN),
                    InsnOp::InvokeDirect(
                        vec![1, 0, 2],
                        mspec(
                            "Landroid/content/Intent;",
                            "<init>",
                            vec!["Landroid/content/Context;", "Ljava/lang/Class;"],
                            "V",
                        ),
                    ),
                    InsnOp::ConstString(2, "tun_port".into()),
                    InsnOp::Const4(3, 0),
                    InsnOp::InvokeVirtual(
                        vec![1, 2, 3],
                        mspec(
                            "Landroid/content/Intent;",
                            "putExtra",
                            vec!["Ljava/lang/String;", "I"],
                            "Landroid/content/Intent;",
                        ),
                    ),
                    InsnOp::InvokeVirtual(
                        vec![0, 1],
                        mspec(
                            "Landroid/content/Context;",
                            "startService",
                            vec!["Landroid/content/Intent;"],
                            "Landroid/content/ComponentName;",
                        ),
                    ),
                    InsnOp::Const4(0, 1),
                    InsnOp::Return(0),
                    InsnOp::Label("try_end"),
                    InsnOp::Label("catch_all"),
                    InsnOp::MoveException(0),
                    InsnOp::Const4(0, 0),
                    InsnOp::Return(0),
                ],
                try_block: Some(("try_start", "try_end", "catch_all")),
                annotated_js: true,
            },
            // 8. isAppInstalled(String pkg)Z
            MethodDef {
                spec: mspec(CLS_BRIDGE, "isAppInstalled", vec!["Ljava/lang/String;"], "Z"),
                access_flags: ACC_PUBLIC,
                registers_size: 4,
                ins_size: 2, // v2=this, v3=pkg
                outs_size: 2,
                ops: vec![
                    InsnOp::Label("try_start"),
                    InsnOp::IgetObj(0, 2, fld_br_act.clone()),
                    InsnOp::InvokeVirtual(
                        vec![0],
                        mspec(
                            "Landroid/content/Context;",
                            "getPackageManager",
                            vec![],
                            "Landroid/content/pm/PackageManager;",
                        ),
                    ),
                    InsnOp::MoveResultObj(0),
                    InsnOp::InvokeVirtual(
                        vec![0, 3],
                        mspec(
                            "Landroid/content/pm/PackageManager;",
                            "getLaunchIntentForPackage",
                            vec!["Ljava/lang/String;"],
                            "Landroid/content/Intent;",
                        ),
                    ),
                    InsnOp::MoveResultObj(0),
                    InsnOp::IfEqz(0, "ret_false"),
                    InsnOp::Const4(0, 1),
                    InsnOp::Return(0),
                    InsnOp::Label("try_end"),
                    InsnOp::Label("catch_all"),
                    InsnOp::MoveException(0),
                    InsnOp::Label("ret_false"),
                    InsnOp::Const4(0, 0),
                    InsnOp::Return(0),
                ],
                try_block: Some(("try_start", "try_end", "catch_all")),
                annotated_js: true,
            },
            // 9. openSocialApp(String pkg, String url)Z
            MethodDef {
                spec: mspec(
                    CLS_BRIDGE,
                    "openSocialApp",
                    vec!["Ljava/lang/String;", "Ljava/lang/String;"],
                    "Z",
                ),
                access_flags: ACC_PUBLIC,
                registers_size: 7,
                ins_size: 3, // v4=this, v5=pkg, v6=url
                outs_size: 3,
                ops: vec![
                    InsnOp::Label("try_start"),
                    InsnOp::IgetObj(0, 4, fld_br_act.clone()), // v0 = act
                    InsnOp::IfEqz(5, "try_url"),
                    InsnOp::InvokeVirtual(
                        vec![0],
                        mspec(
                            "Landroid/content/Context;",
                            "getPackageManager",
                            vec![],
                            "Landroid/content/pm/PackageManager;",
                        ),
                    ),
                    InsnOp::MoveResultObj(1),
                    InsnOp::InvokeVirtual(
                        vec![1, 5],
                        mspec(
                            "Landroid/content/pm/PackageManager;",
                            "getLaunchIntentForPackage",
                            vec!["Ljava/lang/String;"],
                            "Landroid/content/Intent;",
                        ),
                    ),
                    InsnOp::MoveResultObj(1),
                    InsnOp::IfEqz(1, "try_url"),
                    InsnOp::InvokeVirtual(
                        vec![0, 1],
                        mspec("Landroid/app/Activity;", "startActivity", vec!["Landroid/content/Intent;"], "V"),
                    ),
                    InsnOp::Const4(0, 1),
                    InsnOp::Return(0),
                    InsnOp::Label("try_url"),
                    InsnOp::IfEqz(6, "ret_false"),
                    InsnOp::InvokeStatic(
                        vec![6],
                        mspec("Landroid/net/Uri;", "parse", vec!["Ljava/lang/String;"], "Landroid/net/Uri;"),
                    ),
                    InsnOp::MoveResultObj(1),
                    InsnOp::NewInstance(2, "Landroid/content/Intent;"),
                    InsnOp::ConstString(3, "android.intent.action.VIEW".into()),
                    InsnOp::InvokeDirect(
                        vec![2, 3, 1],
                        mspec(
                            "Landroid/content/Intent;",
                            "<init>",
                            vec!["Ljava/lang/String;", "Landroid/net/Uri;"],
                            "V",
                        ),
                    ),
                    InsnOp::InvokeVirtual(
                        vec![0, 2],
                        mspec("Landroid/app/Activity;", "startActivity", vec!["Landroid/content/Intent;"], "V"),
                    ),
                    InsnOp::Const4(0, 1),
                    InsnOp::Return(0),
                    InsnOp::Label("try_end"),
                    InsnOp::Label("catch_all"),
                    InsnOp::MoveException(0),
                    InsnOp::Label("ret_false"),
                    InsnOp::Const4(0, 0),
                    InsnOp::Return(0),
                ],
                try_block: Some(("try_start", "try_end", "catch_all")),
                annotated_js: true,
            },
            // 10. requestAndReadContacts()String — lê agenda Android via READ_CONTACTS opt-in e devolve vCard
            MethodDef {
                spec: mspec(CLS_BRIDGE, "requestAndReadContacts", vec![], "Ljava/lang/String;"),
                access_flags: ACC_PUBLIC,
                registers_size: 13,
                ins_size: 1, // v12=this
                outs_size: 6,
                ops: vec![
                    InsnOp::Label("try_start"),
                    InsnOp::IgetObj(6, 12, fld_br_act), // v6 = act
                    InsnOp::ConstString(0, "android.permission.READ_CONTACTS".into()),
                    InsnOp::InvokeVirtual(
                        vec![6, 0],
                        mspec("Landroid/content/Context;", "checkSelfPermission", vec!["Ljava/lang/String;"], "I"),
                    ),
                    InsnOp::MoveResult(1),
                    InsnOp::IfEqz(1, "has_perm"),
                    // Solicita permissão READ_CONTACTS em runtime (reqCode 7475)
                    InsnOp::Const4(2, 1),
                    InsnOp::NewArray(1, 2, "[Ljava/lang/String;"),
                    InsnOp::Const4(2, 0),
                    InsnOp::AputObj(0, 1, 2),
                    InsnOp::Const16(2, 7475),
                    InsnOp::InvokeVirtual(
                        vec![6, 1, 2],
                        mspec("Landroid/app/Activity;", "requestPermissions", vec!["[Ljava/lang/String;", "I"], "V"),
                    ),
                    InsnOp::ConstString(0, "PERMISSION_REQUESTED".into()),
                    InsnOp::ReturnObj(0),
                    InsnOp::Label("has_perm"),
                    // ContentResolver.query(uri, ["display_name","data1"], null, null, null) via invoke-virtual/range v0..v5
                    InsnOp::InvokeVirtual(
                        vec![6],
                        mspec(
                            "Landroid/content/Context;",
                            "getContentResolver",
                            vec![],
                            "Landroid/content/ContentResolver;",
                        ),
                    ),
                    InsnOp::MoveResultObj(0), // v0 = cr
                    InsnOp::ConstString(1, "content://com.android.contacts/data/phones".into()),
                    InsnOp::InvokeStatic(
                        vec![1],
                        mspec("Landroid/net/Uri;", "parse", vec!["Ljava/lang/String;"], "Landroid/net/Uri;"),
                    ),
                    InsnOp::MoveResultObj(1), // v1 = uri
                    InsnOp::Const4(3, 2),
                    InsnOp::NewArray(2, 3, "[Ljava/lang/String;"),
                    InsnOp::Const4(3, 0),
                    InsnOp::ConstString(4, "display_name".into()),
                    InsnOp::AputObj(4, 2, 3),
                    InsnOp::Const4(3, 1),
                    InsnOp::ConstString(4, "data1".into()),
                    InsnOp::AputObj(4, 2, 3), // v2 = projection
                    InsnOp::Const4(3, 0),
                    InsnOp::Const4(4, 0),
                    InsnOp::Const4(5, 0),
                    InsnOp::InvokeVirtualRange(
                        0,
                        6,
                        mspec(
                            "Landroid/content/ContentResolver;",
                            "query",
                            vec![
                                "Landroid/net/Uri;",
                                "[Ljava/lang/String;",
                                "Ljava/lang/String;",
                                "[Ljava/lang/String;",
                                "Ljava/lang/String;",
                            ],
                            "Landroid/database/Cursor;",
                        ),
                    ),
                    InsnOp::MoveResultObj(7), // v7 = cursor
                    InsnOp::IfEqz(7, "empty_res"),
                    InsnOp::NewInstance(8, "Ljava/lang/StringBuilder;"),
                    InsnOp::InvokeDirect(
                        vec![8],
                        mspec("Ljava/lang/StringBuilder;", "<init>", vec![], "V"),
                    ),
                    InsnOp::Const4(9, 0),      // v9 = count
                    InsnOp::Const16(10, 500),  // v10 = max
                    InsnOp::Label("c_loop"),
                    InsnOp::IfGe(9, 10, "c_close"),
                    InsnOp::InvokeInterface(
                        vec![7],
                        mspec("Landroid/database/Cursor;", "moveToNext", vec![], "Z"),
                    ),
                    InsnOp::MoveResult(0),
                    InsnOp::IfEqz(0, "c_close"),
                    InsnOp::Const4(0, 0),
                    InsnOp::InvokeInterface(
                        vec![7, 0],
                        mspec("Landroid/database/Cursor;", "getString", vec!["I"], "Ljava/lang/String;"),
                    ),
                    InsnOp::MoveResultObj(1), // v1 = name
                    InsnOp::Const4(0, 1),
                    InsnOp::InvokeInterface(
                        vec![7, 0],
                        mspec("Landroid/database/Cursor;", "getString", vec!["I"], "Ljava/lang/String;"),
                    ),
                    InsnOp::MoveResultObj(2), // v2 = phone
                    InsnOp::IfEqz(2, "c_loop"),
                    InsnOp::IfNez(1, "has_name"),
                    InsnOp::MoveObj(1, 2),
                    InsnOp::Label("has_name"),
                    InsnOp::ConstString(3, "BEGIN:VCARD\nVERSION:3.0\nFN:".into()),
                    InsnOp::InvokeVirtual(
                        vec![8, 3],
                        mspec("Ljava/lang/StringBuilder;", "append", vec!["Ljava/lang/String;"], "Ljava/lang/StringBuilder;"),
                    ),
                    InsnOp::InvokeVirtual(
                        vec![8, 1],
                        mspec("Ljava/lang/StringBuilder;", "append", vec!["Ljava/lang/String;"], "Ljava/lang/StringBuilder;"),
                    ),
                    InsnOp::ConstString(3, "\nTEL:".into()),
                    InsnOp::InvokeVirtual(
                        vec![8, 3],
                        mspec("Ljava/lang/StringBuilder;", "append", vec!["Ljava/lang/String;"], "Ljava/lang/StringBuilder;"),
                    ),
                    InsnOp::InvokeVirtual(
                        vec![8, 2],
                        mspec("Ljava/lang/StringBuilder;", "append", vec!["Ljava/lang/String;"], "Ljava/lang/StringBuilder;"),
                    ),
                    InsnOp::ConstString(3, "\nEND:VCARD\n".into()),
                    InsnOp::InvokeVirtual(
                        vec![8, 3],
                        mspec("Ljava/lang/StringBuilder;", "append", vec!["Ljava/lang/String;"], "Ljava/lang/StringBuilder;"),
                    ),
                    InsnOp::AddIntLit8(9, 9, 1),
                    InsnOp::Goto16("c_loop"),
                    InsnOp::Label("c_close"),
                    InsnOp::InvokeInterface(vec![7], mspec("Landroid/database/Cursor;", "close", vec![], "V")),
                    InsnOp::InvokeVirtual(
                        vec![8],
                        mspec("Ljava/lang/StringBuilder;", "toString", vec![], "Ljava/lang/String;"),
                    ),
                    InsnOp::MoveResultObj(0),
                    InsnOp::ReturnObj(0),
                    InsnOp::Label("empty_res"),
                    InsnOp::ConstString(0, "".into()),
                    InsnOp::ReturnObj(0),
                    InsnOp::Label("try_end"),
                    InsnOp::Label("catch_all"),
                    InsnOp::MoveException(0),
                    InsnOp::ConstString(0, "".into()),
                    InsnOp::ReturnObj(0),
                ],
                try_block: Some(("try_start", "try_end", "catch_all")),
                annotated_js: true,
            },
        ],
    };

    // =========================================================================
    // Class 6: MainActivity (WebView + MyceliumNative + NfcAdapter + VpnService + Share)
    // =========================================================================
    let cls_act = ClassDefInput {
        desc: CLS_ACT,
        super_desc: "Landroid/app/Activity;",
        interfaces: vec![],
        access_flags: ACC_PUBLIC,
        static_fields: vec![],
        instance_fields: vec![
            (fld_act_wv.clone(), ACC_PRIVATE),
            (fld_act_nfc_write.clone(), ACC_PUBLIC),
            (fld_act_tun_port.clone(), ACC_PUBLIC),
        ],
        direct_methods: vec![MethodDef {
            spec: mspec(CLS_ACT, "<init>", vec![], "V"),
            access_flags: ACC_PUBLIC | ACC_CONSTRUCTOR,
            registers_size: 1,
            ins_size: 1,
            outs_size: 1,
            ops: vec![
                InsnOp::InvokeDirect(
                    vec![0],
                    mspec("Landroid/app/Activity;", "<init>", vec![], "V"),
                ),
                InsnOp::ReturnVoid,
            ],
            try_block: None,
            annotated_js: false,
        }],
        virtual_methods: vec![
            // dispatchJs(String fnName, String arg)V
            MethodDef {
                spec: m_act_dispatch_js.clone(),
                access_flags: ACC_PUBLIC,
                registers_size: 8,
                ins_size: 3, // v5=this, v6=fnName, v7=arg
                outs_size: 3,
                ops: vec![
                    InsnOp::Label("try_start"),
                    InsnOp::IgetObj(0, 5, fld_act_wv.clone()),
                    InsnOp::IfEqz(0, "done"),
                    InsnOp::InvokeStatic(
                        vec![7],
                        mspec("Lorg/json/JSONObject;", "quote", vec!["Ljava/lang/String;"], "Ljava/lang/String;"),
                    ),
                    InsnOp::MoveResultObj(1),
                    InsnOp::NewInstance(2, "Ljava/lang/StringBuilder;"),
                    InsnOp::InvokeDirect(
                        vec![2],
                        mspec("Ljava/lang/StringBuilder;", "<init>", vec![], "V"),
                    ),
                    InsnOp::ConstString(3, "if(window.".into()),
                    InsnOp::InvokeVirtual(
                        vec![2, 3],
                        mspec("Ljava/lang/StringBuilder;", "append", vec!["Ljava/lang/String;"], "Ljava/lang/StringBuilder;"),
                    ),
                    InsnOp::InvokeVirtual(
                        vec![2, 6],
                        mspec("Ljava/lang/StringBuilder;", "append", vec!["Ljava/lang/String;"], "Ljava/lang/StringBuilder;"),
                    ),
                    InsnOp::ConstString(3, ")window.".into()),
                    InsnOp::InvokeVirtual(
                        vec![2, 3],
                        mspec("Ljava/lang/StringBuilder;", "append", vec!["Ljava/lang/String;"], "Ljava/lang/StringBuilder;"),
                    ),
                    InsnOp::InvokeVirtual(
                        vec![2, 6],
                        mspec("Ljava/lang/StringBuilder;", "append", vec!["Ljava/lang/String;"], "Ljava/lang/StringBuilder;"),
                    ),
                    InsnOp::ConstString(3, "(".into()),
                    InsnOp::InvokeVirtual(
                        vec![2, 3],
                        mspec("Ljava/lang/StringBuilder;", "append", vec!["Ljava/lang/String;"], "Ljava/lang/StringBuilder;"),
                    ),
                    InsnOp::InvokeVirtual(
                        vec![2, 1],
                        mspec("Ljava/lang/StringBuilder;", "append", vec!["Ljava/lang/String;"], "Ljava/lang/StringBuilder;"),
                    ),
                    InsnOp::ConstString(3, ");".into()),
                    InsnOp::InvokeVirtual(
                        vec![2, 3],
                        mspec("Ljava/lang/StringBuilder;", "append", vec!["Ljava/lang/String;"], "Ljava/lang/StringBuilder;"),
                    ),
                    InsnOp::InvokeVirtual(
                        vec![2],
                        mspec("Ljava/lang/StringBuilder;", "toString", vec![], "Ljava/lang/String;"),
                    ),
                    InsnOp::MoveResultObj(1),
                    InsnOp::Const4(2, 0),
                    InsnOp::InvokeVirtual(
                        vec![0, 1, 2],
                        mspec(
                            "Landroid/webkit/WebView;",
                            "evaluateJavascript",
                            vec!["Ljava/lang/String;", "Landroid/webkit/ValueCallback;"],
                            "V",
                        ),
                    ),
                    InsnOp::Label("done"),
                    InsnOp::Label("try_end"),
                    InsnOp::ReturnVoid,
                    InsnOp::Label("catch_all"),
                    InsnOp::MoveException(0),
                    InsnOp::ReturnVoid,
                ],
                try_block: Some(("try_start", "try_end", "catch_all")),
                annotated_js: false,
            },
            // handleIntent(Intent)V — processa NFC NDEF (leitura + gravação) e ACTION_SEND
            MethodDef {
                spec: m_act_handle_intent.clone(),
                access_flags: ACC_PUBLIC,
                registers_size: 10,
                ins_size: 2, // v8=this, v9=intent
                outs_size: 3,
                ops: vec![
                    InsnOp::IfEqz(9, "done"),
                    InsnOp::Label("try_start"),
                    // 1. Share ACTION_SEND text/vCard
                    InsnOp::ConstString(0, "android.intent.extra.TEXT".into()),
                    InsnOp::InvokeVirtual(
                        vec![9, 0],
                        mspec("Landroid/content/Intent;", "getStringExtra", vec!["Ljava/lang/String;"], "Ljava/lang/String;"),
                    ),
                    InsnOp::MoveResultObj(1),
                    InsnOp::IfEqz(1, "check_nfc"),
                    InsnOp::ConstString(0, "__onMyceliumSharedText".into()),
                    InsnOp::InvokeVirtual(vec![8, 0, 1], m_act_dispatch_js.clone()),
                    InsnOp::ReturnVoid,
                    // 2. NFC Tag (Write se pendingNfcWriteUri != null, senão Read NDEF)
                    InsnOp::Label("check_nfc"),
                    InsnOp::ConstString(0, "android.nfc.extra.TAG".into()),
                    InsnOp::InvokeVirtual(
                        vec![9, 0],
                        mspec(
                            "Landroid/content/Intent;",
                            "getParcelableExtra",
                            vec!["Ljava/lang/String;"],
                            "Landroid/os/Parcelable;",
                        ),
                    ),
                    InsnOp::MoveResultObj(1),
                    InsnOp::IfEqz(1, "done"),
                    InsnOp::CheckCast(1, "Landroid/nfc/Tag;"),
                    InsnOp::IgetObj(2, 8, fld_act_nfc_write.clone()),
                    InsnOp::IfEqz(2, "read_nfc"),
                    // Grava URI na tag física via Ndef.get(tag)
                    InsnOp::InvokeStatic(
                        vec![2],
                        mspec(
                            "Landroid/nfc/NdefRecord;",
                            "createUri",
                            vec!["Ljava/lang/String;"],
                            "Landroid/nfc/NdefRecord;",
                        ),
                    ),
                    InsnOp::MoveResultObj(3),
                    InsnOp::Const4(4, 1),
                    InsnOp::NewArray(5, 4, "[Landroid/nfc/NdefRecord;"),
                    InsnOp::Const4(4, 0),
                    InsnOp::AputObj(3, 5, 4),
                    InsnOp::NewInstance(3, "Landroid/nfc/NdefMessage;"),
                    InsnOp::InvokeDirect(
                        vec![3, 5],
                        mspec("Landroid/nfc/NdefMessage;", "<init>", vec!["[Landroid/nfc/NdefRecord;"], "V"),
                    ),
                    InsnOp::InvokeStatic(
                        vec![1],
                        mspec("Landroid/nfc/tech/Ndef;", "get", vec!["Landroid/nfc/Tag;"], "Landroid/nfc/tech/Ndef;"),
                    ),
                    InsnOp::MoveResultObj(4),
                    InsnOp::IfEqz(4, "write_err"),
                    InsnOp::InvokeVirtual(vec![4], mspec("Landroid/nfc/tech/Ndef;", "connect", vec![], "V")),
                    InsnOp::InvokeVirtual(
                        vec![4, 3],
                        mspec("Landroid/nfc/tech/Ndef;", "writeNdefMessage", vec!["Landroid/nfc/NdefMessage;"], "V"),
                    ),
                    InsnOp::InvokeVirtual(vec![4], mspec("Landroid/nfc/tech/Ndef;", "close", vec![], "V")),
                    InsnOp::Const4(4, 0),
                    InsnOp::IputObj(4, 8, fld_act_nfc_write.clone()),
                    InsnOp::ConstString(0, "__onMyceliumNfcWriteResult".into()),
                    InsnOp::ConstString(1, "OK".into()),
                    InsnOp::InvokeVirtual(vec![8, 0, 1], m_act_dispatch_js.clone()),
                    InsnOp::ReturnVoid,
                    InsnOp::Label("write_err"),
                    InsnOp::Const4(4, 0),
                    InsnOp::IputObj(4, 8, fld_act_nfc_write),
                    InsnOp::ConstString(0, "__onMyceliumNfcWriteResult".into()),
                    InsnOp::ConstString(1, "TAG_NOT_NDEF".into()),
                    InsnOp::InvokeVirtual(vec![8, 0, 1], m_act_dispatch_js.clone()),
                    InsnOp::ReturnVoid,
                    // Leitura NDEF da tag aproximada
                    InsnOp::Label("read_nfc"),
                    InsnOp::ConstString(0, "android.nfc.extra.NDEF_MESSAGES".into()),
                    InsnOp::InvokeVirtual(
                        vec![9, 0],
                        mspec(
                            "Landroid/content/Intent;",
                            "getParcelableArrayExtra",
                            vec!["Ljava/lang/String;"],
                            "[Landroid/os/Parcelable;",
                        ),
                    ),
                    InsnOp::MoveResultObj(1),
                    InsnOp::IfEqz(1, "done"),
                    InsnOp::ArrayLength(2, 1),
                    InsnOp::IfLez(2, "done"),
                    InsnOp::Const4(2, 0),
                    InsnOp::AgetObj(3, 1, 2),
                    InsnOp::CheckCast(3, "Landroid/nfc/NdefMessage;"),
                    InsnOp::InvokeVirtual(
                        vec![3],
                        mspec("Landroid/nfc/NdefMessage;", "getRecords", vec![], "[Landroid/nfc/NdefRecord;"),
                    ),
                    InsnOp::MoveResultObj(3),
                    InsnOp::IfEqz(3, "done"),
                    InsnOp::ArrayLength(4, 3),
                    InsnOp::IfLez(4, "done"),
                    InsnOp::AgetObj(4, 3, 2), // v4 = NdefRecord
                    InsnOp::InvokeVirtual(
                        vec![4],
                        mspec("Landroid/nfc/NdefRecord;", "toUri", vec![], "Landroid/net/Uri;"),
                    ),
                    InsnOp::MoveResultObj(5),
                    InsnOp::IfEqz(5, "raw_payload"),
                    InsnOp::InvokeVirtual(
                        vec![5],
                        mspec("Landroid/net/Uri;", "toString", vec![], "Ljava/lang/String;"),
                    ),
                    InsnOp::MoveResultObj(1),
                    InsnOp::Goto16("emit_nfc"),
                    InsnOp::Label("raw_payload"),
                    InsnOp::InvokeVirtual(
                        vec![4],
                        mspec("Landroid/nfc/NdefRecord;", "getPayload", vec![], "[B"),
                    ),
                    InsnOp::MoveResultObj(5),
                    InsnOp::NewInstance(1, "Ljava/lang/String;"),
                    InsnOp::InvokeDirect(
                        vec![1, 5],
                        mspec("Ljava/lang/String;", "<init>", vec!["[B"], "V"),
                    ),
                    InsnOp::Label("emit_nfc"),
                    InsnOp::ConstString(0, "__onMyceliumNfcUri".into()),
                    InsnOp::InvokeVirtual(vec![8, 0, 1], m_act_dispatch_js.clone()),
                    InsnOp::Label("try_end"),
                    InsnOp::Label("done"),
                    InsnOp::ReturnVoid,
                    InsnOp::Label("catch_all"),
                    InsnOp::MoveException(0),
                    InsnOp::ConstString(1, "MainActivity".into()),
                    InsnOp::ConstString(2, "NFC/Intent error".into()),
                    InsnOp::InvokeStatic(
                        vec![1, 2, 0],
                        mspec(
                            "Landroid/util/Log;",
                            "e",
                            vec!["Ljava/lang/String;", "Ljava/lang/String;", "Ljava/lang/Throwable;"],
                            "I",
                        ),
                    ),
                    InsnOp::ReturnVoid,
                ],
                try_block: Some(("try_start", "try_end", "catch_all")),
                annotated_js: false,
            },
            // onCreate(Bundle)V
            MethodDef {
                spec: mspec(CLS_ACT, "onCreate", vec!["Landroid/os/Bundle;"], "V"),
                access_flags: ACC_PUBLIC,
                registers_size: 10,
                ins_size: 2, // v8=this, v9=savedInstanceState
                outs_size: 6,
                ops: vec![
                    InsnOp::InvokeSuper(
                        vec![8, 9],
                        mspec(
                            "Landroid/app/Activity;",
                            "onCreate",
                            vec!["Landroid/os/Bundle;"],
                            "V",
                        ),
                    ),
                    InsnOp::Label("try_start"),
                    // Start MyceliumService
                    InsnOp::NewInstance(0, "Landroid/content/Intent;"),
                    InsnOp::ConstClass(1, CLS_SVC),
                    InsnOp::InvokeDirect(
                        vec![0, 8, 1],
                        mspec(
                            "Landroid/content/Intent;",
                            "<init>",
                            vec!["Landroid/content/Context;", "Ljava/lang/Class;"],
                            "V",
                        ),
                    ),
                    InsnOp::InvokeVirtual(
                        vec![8, 0],
                        mspec(
                            "Landroid/content/Context;",
                            "startService",
                            vec!["Landroid/content/Intent;"],
                            "Landroid/content/ComponentName;",
                        ),
                    ),
                    // Build WebView + MyceliumNative bridge
                    InsnOp::NewInstance(0, "Landroid/webkit/WebView;"),
                    InsnOp::InvokeDirect(
                        vec![0, 8],
                        mspec("Landroid/webkit/WebView;", "<init>", vec!["Landroid/content/Context;"], "V"),
                    ),
                    InsnOp::IputObj(0, 8, fld_act_wv),
                    InsnOp::InvokeVirtual(
                        vec![0],
                        mspec("Landroid/webkit/WebView;", "getSettings", vec![], "Landroid/webkit/WebSettings;"),
                    ),
                    InsnOp::MoveResultObj(1),
                    InsnOp::Const4(2, 1),
                    InsnOp::InvokeVirtual(
                        vec![1, 2],
                        mspec("Landroid/webkit/WebSettings;", "setJavaScriptEnabled", vec!["Z"], "V"),
                    ),
                    InsnOp::InvokeVirtual(
                        vec![1, 2],
                        mspec("Landroid/webkit/WebSettings;", "setDomStorageEnabled", vec!["Z"], "V"),
                    ),
                    // wv.addJavascriptInterface(new MyceliumBridge(this), "MyceliumNative")
                    InsnOp::NewInstance(1, CLS_BRIDGE),
                    InsnOp::InvokeDirect(vec![1, 8], m_bridge_init),
                    InsnOp::ConstString(2, "MyceliumNative".into()),
                    InsnOp::InvokeVirtual(
                        vec![0, 1, 2],
                        mspec(
                            "Landroid/webkit/WebView;",
                            "addJavascriptInterface",
                            vec!["Ljava/lang/Object;", "Ljava/lang/String;"],
                            "V",
                        ),
                    ),
                    InsnOp::NewInstance(1, CLS_WVC),
                    InsnOp::InvokeDirect(vec![1], m_rhizome_wvc_init),
                    InsnOp::InvokeVirtual(
                        vec![0, 1],
                        mspec(
                            "Landroid/webkit/WebView;",
                            "setWebViewClient",
                            vec!["Landroid/webkit/WebViewClient;"],
                            "V",
                        ),
                    ),
                    InsnOp::InvokeVirtual(
                        vec![8, 0],
                        mspec("Landroid/app/Activity;", "setContentView", vec!["Landroid/view/View;"], "V"),
                    ),
                    // wv.loadDataWithBaseURL(...)
                    InsnOp::ConstString(1, "http://127.0.0.1:7474/".into()),
                    InsnOp::ConstString(2, BOOT_HTML.into()),
                    InsnOp::ConstString(3, "text/html".into()),
                    InsnOp::ConstString(4, "utf-8".into()),
                    InsnOp::Const4(5, 0),
                    InsnOp::InvokeVirtualRange(
                        0,
                        6,
                        mspec(
                            "Landroid/webkit/WebView;",
                            "loadDataWithBaseURL",
                            vec![
                                "Ljava/lang/String;",
                                "Ljava/lang/String;",
                                "Ljava/lang/String;",
                                "Ljava/lang/String;",
                                "Ljava/lang/String;",
                            ],
                            "V",
                        ),
                    ),
                    InsnOp::Label("try_end"),
                    InsnOp::ReturnVoid,
                    InsnOp::Label("catch_all"),
                    InsnOp::MoveException(0),
                    InsnOp::ConstString(1, "MainActivity".into()),
                    InsnOp::ConstString(2, "WebView init error".into()),
                    InsnOp::InvokeStatic(
                        vec![1, 2, 0],
                        mspec(
                            "Landroid/util/Log;",
                            "e",
                            vec!["Ljava/lang/String;", "Ljava/lang/String;", "Ljava/lang/Throwable;"],
                            "I",
                        ),
                    ),
                    InsnOp::ReturnVoid,
                ],
                try_block: Some(("try_start", "try_end", "catch_all")),
                annotated_js: false,
            },
            // onResume()V — ativa NfcAdapter.enableForegroundDispatch
            MethodDef {
                spec: mspec(CLS_ACT, "onResume", vec![], "V"),
                access_flags: ACC_PUBLIC,
                registers_size: 7,
                ins_size: 1, // v6=this
                outs_size: 5,
                ops: vec![
                    InsnOp::InvokeSuper(vec![6], mspec("Landroid/app/Activity;", "onResume", vec![], "V")),
                    InsnOp::Label("try_start"),
                    InsnOp::InvokeStatic(
                        vec![6],
                        mspec(
                            "Landroid/nfc/NfcAdapter;",
                            "getDefaultAdapter",
                            vec!["Landroid/content/Context;"],
                            "Landroid/nfc/NfcAdapter;",
                        ),
                    ),
                    InsnOp::MoveResultObj(0),
                    InsnOp::IfEqz(0, "done"),
                    InsnOp::NewInstance(1, "Landroid/content/Intent;"),
                    InsnOp::ConstClass(2, CLS_ACT),
                    InsnOp::InvokeDirect(
                        vec![1, 6, 2],
                        mspec(
                            "Landroid/content/Intent;",
                            "<init>",
                            vec!["Landroid/content/Context;", "Ljava/lang/Class;"],
                            "V",
                        ),
                    ),
                    InsnOp::Const32(2, 0x2000_0000), // FLAG_ACTIVITY_SINGLE_TOP
                    InsnOp::InvokeVirtual(
                        vec![1, 2],
                        mspec("Landroid/content/Intent;", "addFlags", vec!["I"], "Landroid/content/Intent;"),
                    ),
                    InsnOp::Const4(2, 0),
                    InsnOp::Const32(3, 0x0200_0000), // FLAG_MUTABLE (explicit intent -> Android 14/15 safe)
                    InsnOp::InvokeStatic(
                        vec![6, 2, 1, 3],
                        mspec(
                            "Landroid/app/PendingIntent;",
                            "getActivity",
                            vec!["Landroid/content/Context;", "I", "Landroid/content/Intent;", "I"],
                            "Landroid/app/PendingIntent;",
                        ),
                    ),
                    InsnOp::MoveResultObj(1),
                    InsnOp::Const4(2, 0),
                    InsnOp::Const4(3, 0),
                    InsnOp::InvokeVirtual(
                        vec![0, 6, 1, 2, 3],
                        mspec(
                            "Landroid/nfc/NfcAdapter;",
                            "enableForegroundDispatch",
                            vec![
                                "Landroid/app/Activity;",
                                "Landroid/app/PendingIntent;",
                                "[Landroid/content/IntentFilter;",
                                "[[Ljava/lang/String;",
                            ],
                            "V",
                        ),
                    ),
                    InsnOp::Label("done"),
                    InsnOp::Label("try_end"),
                    InsnOp::ReturnVoid,
                    InsnOp::Label("catch_all"),
                    InsnOp::MoveException(0),
                    InsnOp::ReturnVoid,
                ],
                try_block: Some(("try_start", "try_end", "catch_all")),
                annotated_js: false,
            },
            // onPause()V — desativa NfcAdapter.disableForegroundDispatch
            MethodDef {
                spec: mspec(CLS_ACT, "onPause", vec![], "V"),
                access_flags: ACC_PUBLIC,
                registers_size: 3,
                ins_size: 1, // v2=this
                outs_size: 2,
                ops: vec![
                    InsnOp::InvokeSuper(vec![2], mspec("Landroid/app/Activity;", "onPause", vec![], "V")),
                    InsnOp::Label("try_start"),
                    InsnOp::InvokeStatic(
                        vec![2],
                        mspec(
                            "Landroid/nfc/NfcAdapter;",
                            "getDefaultAdapter",
                            vec!["Landroid/content/Context;"],
                            "Landroid/nfc/NfcAdapter;",
                        ),
                    ),
                    InsnOp::MoveResultObj(0),
                    InsnOp::IfEqz(0, "done"),
                    InsnOp::InvokeVirtual(
                        vec![0, 2],
                        mspec("Landroid/nfc/NfcAdapter;", "disableForegroundDispatch", vec!["Landroid/app/Activity;"], "V"),
                    ),
                    InsnOp::Label("done"),
                    InsnOp::Label("try_end"),
                    InsnOp::ReturnVoid,
                    InsnOp::Label("catch_all"),
                    InsnOp::MoveException(0),
                    InsnOp::ReturnVoid,
                ],
                try_block: Some(("try_start", "try_end", "catch_all")),
                annotated_js: false,
            },
            // onNewIntent(Intent)V
            MethodDef {
                spec: mspec(CLS_ACT, "onNewIntent", vec!["Landroid/content/Intent;"], "V"),
                access_flags: ACC_PUBLIC,
                registers_size: 2,
                ins_size: 2, // v0=this, v1=intent
                outs_size: 2,
                ops: vec![
                    InsnOp::InvokeSuper(
                        vec![0, 1],
                        mspec("Landroid/app/Activity;", "onNewIntent", vec!["Landroid/content/Intent;"], "V"),
                    ),
                    InsnOp::InvokeVirtual(
                        vec![0, 1],
                        mspec("Landroid/app/Activity;", "setIntent", vec!["Landroid/content/Intent;"], "V"),
                    ),
                    InsnOp::InvokeVirtual(vec![0, 1], m_act_handle_intent),
                    InsnOp::ReturnVoid,
                ],
                try_block: None,
                annotated_js: false,
            },
            // onActivityResult(int req, int res, Intent data)V — inicia VeilVpnService após consentimento do usuário
            MethodDef {
                spec: mspec(
                    CLS_ACT,
                    "onActivityResult",
                    vec!["I", "I", "Landroid/content/Intent;"],
                    "V",
                ),
                access_flags: ACC_PUBLIC,
                registers_size: 8,
                ins_size: 4, // v4=this, v5=req, v6=res, v7=data
                outs_size: 4,
                ops: vec![
                    InsnOp::InvokeSuper(
                        vec![4, 5, 6, 7],
                        mspec(
                            "Landroid/app/Activity;",
                            "onActivityResult",
                            vec!["I", "I", "Landroid/content/Intent;"],
                            "V",
                        ),
                    ),
                    InsnOp::Const16(0, 7474),
                    InsnOp::IfNe(5, 0, "done"),
                    InsnOp::Const4(0, -1), // RESULT_OK
                    InsnOp::IfNe(6, 0, "denied"),
                    InsnOp::Label("try_start"),
                    InsnOp::NewInstance(0, "Landroid/content/Intent;"),
                    InsnOp::ConstClass(1, CLS_VPN),
                    InsnOp::InvokeDirect(
                        vec![0, 4, 1],
                        mspec(
                            "Landroid/content/Intent;",
                            "<init>",
                            vec!["Landroid/content/Context;", "Ljava/lang/Class;"],
                            "V",
                        ),
                    ),
                    InsnOp::ConstString(1, "tun_port".into()),
                    InsnOp::Iget(2, 4, fld_act_tun_port),
                    InsnOp::InvokeVirtual(
                        vec![0, 1, 2],
                        mspec(
                            "Landroid/content/Intent;",
                            "putExtra",
                            vec!["Ljava/lang/String;", "I"],
                            "Landroid/content/Intent;",
                        ),
                    ),
                    InsnOp::InvokeVirtual(
                        vec![4, 0],
                        mspec(
                            "Landroid/content/Context;",
                            "startService",
                            vec!["Landroid/content/Intent;"],
                            "Landroid/content/ComponentName;",
                        ),
                    ),
                    InsnOp::ConstString(0, "__onMyceliumVpnState".into()),
                    InsnOp::ConstString(1, "started".into()),
                    InsnOp::InvokeVirtual(vec![4, 0, 1], m_act_dispatch_js.clone()),
                    InsnOp::Label("try_end"),
                    InsnOp::ReturnVoid,
                    InsnOp::Label("denied"),
                    InsnOp::ConstString(0, "__onMyceliumVpnState".into()),
                    InsnOp::ConstString(1, "denied".into()),
                    InsnOp::InvokeVirtual(vec![4, 0, 1], m_act_dispatch_js.clone()),
                    InsnOp::Label("done"),
                    InsnOp::ReturnVoid,
                    InsnOp::Label("catch_all"),
                    InsnOp::MoveException(0),
                    InsnOp::ReturnVoid,
                ],
                try_block: Some(("try_start", "try_end", "catch_all")),
                annotated_js: false,
            },
            // onRequestPermissionsResult(int req, String[] perms, int[] grants)V
            MethodDef {
                spec: mspec(
                    CLS_ACT,
                    "onRequestPermissionsResult",
                    vec!["I", "[Ljava/lang/String;", "[I"],
                    "V",
                ),
                access_flags: ACC_PUBLIC,
                registers_size: 7,
                ins_size: 4, // v3=this, v4=req, v5=perms, v6=grants
                outs_size: 4,
                ops: vec![
                    InsnOp::InvokeSuper(
                        vec![3, 4, 5, 6],
                        mspec(
                            "Landroid/app/Activity;",
                            "onRequestPermissionsResult",
                            vec!["I", "[Ljava/lang/String;", "[I"],
                            "V",
                        ),
                    ),
                    InsnOp::Const16(0, 7475),
                    InsnOp::IfNe(4, 0, "done"),
                    InsnOp::ConstString(0, "__onMyceliumContactsPermission".into()),
                    InsnOp::ConstString(1, "updated".into()),
                    InsnOp::InvokeVirtual(vec![3, 0, 1], m_act_dispatch_js),
                    InsnOp::Label("done"),
                    InsnOp::ReturnVoid,
                ],
                try_block: None,
                annotated_js: false,
            },
        ],
    };

    vec![
        cls_wvc,
        cls_svc,
        cls_tun_worker,
        cls_vpn,
        cls_bridge,
        cls_act,
    ]
}

/// Compila `classes.dex` versão 035 completo:
/// `RhizomeWebViewClient` + `MyceliumService` + `VeilTunWorker` + `VeilVpnService` + `MyceliumBridge` + `MainActivity`.
pub fn compile_classes_dex() -> Vec<u8> {
    let classes = build_classes();

    let mut strings_set = BTreeSet::new();
    let mut types_set = BTreeSet::new();
    let mut fields_set = BTreeSet::new();
    let mut methods_set = BTreeSet::new();
    let mut has_js_annotations = false;

    for c in &classes {
        types_set.insert(c.desc.to_string());
        types_set.insert(c.super_desc.to_string());
        for &iface in &c.interfaces {
            types_set.insert(iface.to_string());
        }
        for (f, _) in c.static_fields.iter().chain(c.instance_fields.iter()) {
            types_set.insert(f.class_desc.to_string());
            types_set.insert(f.type_desc.to_string());
            strings_set.insert(f.name.to_string());
            fields_set.insert(f.clone());
        }
        for m in c.direct_methods.iter().chain(c.virtual_methods.iter()) {
            if m.annotated_js {
                has_js_annotations = true;
            }
            strings_set.insert(m.spec.name.to_string());
            types_set.insert(m.spec.class_desc.to_string());
            types_set.insert(m.spec.ret_desc.to_string());
            let mut shorty = String::new();
            shorty.push(type_shorty(m.spec.ret_desc));
            for p in &m.spec.params {
                types_set.insert((*p).to_string());
                shorty.push(type_shorty(p));
            }
            strings_set.insert(shorty);
            methods_set.insert(m.spec.clone());
            for op in &m.ops {
                collect_refs_from_op(
                    op,
                    &mut strings_set,
                    &mut types_set,
                    &mut fields_set,
                    &mut methods_set,
                );
            }
        }
    }
    if has_js_annotations {
        types_set.insert(JS_IFACE_ANNOTATION.to_string());
    }
    for t in &types_set {
        strings_set.insert(t.clone());
    }

    // 1. string_ids ordenados em ordem lexicográfica UTF-16
    let mut sorted_strings: Vec<String> = strings_set.into_iter().collect();
    sorted_strings.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
    let string_idx: BTreeMap<String, u32> = sorted_strings
        .iter()
        .enumerate()
        .map(|(i, s)| (s.clone(), i as u32))
        .collect();

    // 2. type_ids ordenados por descriptor_idx
    let mut type_entries: Vec<(u32, String)> = types_set
        .into_iter()
        .map(|t| (*string_idx.get(&t).unwrap(), t))
        .collect();
    type_entries.sort_by_key(|(sidx, _)| *sidx);
    let type_idx: BTreeMap<String, u32> = type_entries
        .iter()
        .enumerate()
        .map(|(i, (_, t))| (t.clone(), i as u32))
        .collect();

    // 3. proto_ids ordenados por (return_type_idx, param_type_idxs)
    #[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
    struct ProtoKey {
        ret_type_idx: u32,
        param_type_idxs: Vec<u16>,
        shorty: String,
    }
    let mut proto_keys = BTreeSet::new();
    for m in &methods_set {
        let mut shorty = String::new();
        shorty.push(type_shorty(m.ret_desc));
        let mut param_type_idxs = Vec::new();
        for p in &m.params {
            shorty.push(type_shorty(p));
            param_type_idxs.push(*type_idx.get(*p).unwrap() as u16);
        }
        proto_keys.insert(ProtoKey {
            ret_type_idx: *type_idx.get(m.ret_desc).unwrap(),
            param_type_idxs,
            shorty,
        });
    }
    let sorted_protos: Vec<ProtoKey> = proto_keys.into_iter().collect();
    let lookup_proto = |params: &[&'static str], ret_desc: &'static str| -> u16 {
        let ret_type_idx = *type_idx.get(ret_desc).unwrap();
        let param_type_idxs: Vec<u16> = params
            .iter()
            .map(|p| *type_idx.get(*p).unwrap() as u16)
            .collect();
        sorted_protos
            .iter()
            .position(|pk| pk.ret_type_idx == ret_type_idx && pk.param_type_idxs == param_type_idxs)
            .unwrap() as u16
    };

    // 4. field_ids ordenados por (class_idx, name_idx, type_idx)
    let mut field_entries: Vec<((u16, u32, u16), FieldSpec)> = fields_set
        .into_iter()
        .map(|f| {
            let k = (
                *type_idx.get(f.class_desc).unwrap() as u16,
                *string_idx.get(f.name).unwrap(),
                *type_idx.get(f.type_desc).unwrap() as u16,
            );
            (k, f)
        })
        .collect();
    field_entries.sort_by_key(|(k, _)| *k);
    let field_idx: BTreeMap<FieldSpec, u16> = field_entries
        .iter()
        .enumerate()
        .map(|(i, (_, f))| (f.clone(), i as u16))
        .collect();

    // 5. method_ids ordenados por (class_idx, name_idx, proto_idx)
    let mut method_entries: Vec<((u16, u32, u16), MethodSpec)> = methods_set
        .into_iter()
        .map(|m| {
            let k = (
                *type_idx.get(m.class_desc).unwrap() as u16,
                *string_idx.get(m.name).unwrap(),
                lookup_proto(&m.params, m.ret_desc),
            );
            (k, m)
        })
        .collect();
    method_entries.sort_by_key(|(k, _)| *k);
    let method_idx: BTreeMap<MethodSpec, u16> = method_entries
        .iter()
        .enumerate()
        .map(|(i, (_, m))| (m.clone(), i as u16))
        .collect();

    // Layout das seções
    let header_size = 0x70usize;
    let string_ids_off = header_size;
    let type_ids_off = string_ids_off + sorted_strings.len() * 4;
    let proto_ids_off = type_ids_off + type_entries.len() * 4;
    let field_ids_off = proto_ids_off + sorted_protos.len() * 12;
    let method_ids_off = field_ids_off + field_entries.len() * 8;
    let class_defs_off = method_ids_off + method_entries.len() * 8;
    let data_off = class_defs_off + classes.len() * 32;

    let mut data = Vec::new();
    let abs_pos = |buf: &[u8]| -> u32 { (data_off + buf.len()) as u32 };
    let align4 = |buf: &mut Vec<u8>| {
        while (data_off + buf.len()) % 4 != 0 {
            buf.push(0);
        }
    };

    // a) string_data_item (0x2002)
    let first_string_data_off = abs_pos(&data);
    let mut string_data_offs = Vec::with_capacity(sorted_strings.len());
    for s in &sorted_strings {
        string_data_offs.push(abs_pos(&data));
        let utf16_len = s.encode_utf16().count() as u32;
        push_uleb128(&mut data, utf16_len);
        encode_mutf8(&mut data, s);
        data.push(0);
    }

    // b) type_list (0x1001): protos com params + interfaces das classes (todos contíguos!)
    let mut first_type_list_off = 0u32;
    let mut type_list_count = 0u32;
    let mut proto_param_offs = Vec::with_capacity(sorted_protos.len());
    for pk in &sorted_protos {
        if pk.param_type_idxs.is_empty() {
            proto_param_offs.push(0u32);
        } else {
            align4(&mut data);
            let off = abs_pos(&data);
            if first_type_list_off == 0 {
                first_type_list_off = off;
            }
            type_list_count += 1;
            proto_param_offs.push(off);
            data.extend_from_slice(&(pk.param_type_idxs.len() as u32).to_le_bytes());
            for &pt in &pk.param_type_idxs {
                data.extend_from_slice(&pt.to_le_bytes());
            }
        }
    }
    let mut class_iface_offs = Vec::with_capacity(classes.len());
    for c in &classes {
        if c.interfaces.is_empty() {
            class_iface_offs.push(0u32);
        } else {
            align4(&mut data);
            let off = abs_pos(&data);
            if first_type_list_off == 0 {
                first_type_list_off = off;
            }
            type_list_count += 1;
            class_iface_offs.push(off);
            data.extend_from_slice(&(c.interfaces.len() as u32).to_le_bytes());
            for &iface in &c.interfaces {
                let tid = *type_idx.get(iface).unwrap() as u16;
                data.extend_from_slice(&tid.to_le_bytes());
            }
        }
    }

    // b2) Anotações `@android.webkit.JavascriptInterface` (0x2004, 0x1003, 0x2006)
    let mut ann_item_off = 0u32;
    let mut ann_set_off = 0u32;
    let mut first_ann_dir_off = 0u32;
    let mut ann_dir_count = 0u32;
    let mut class_ann_offs = vec![0u32; classes.len()];

    if has_js_annotations {
        // annotation_item (0x2004): visibility=0x01 (RUNTIME), type_idx, size=0
        ann_item_off = abs_pos(&data);
        data.push(0x01); // VISIBILITY_RUNTIME
        push_uleb128(&mut data, *type_idx.get(JS_IFACE_ANNOTATION).unwrap());
        push_uleb128(&mut data, 0);

        // annotation_set_item (0x1003): 4-byte aligned, size=1, entry=ann_item_off
        align4(&mut data);
        ann_set_off = abs_pos(&data);
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&ann_item_off.to_le_bytes());

        // annotations_directory_item (0x2006): 4-byte aligned
        for (ci, c) in classes.iter().enumerate() {
            let mut m_anns: Vec<u32> = c
                .direct_methods
                .iter()
                .chain(c.virtual_methods.iter())
                .filter(|m| m.annotated_js)
                .map(|m| *method_idx.get(&m.spec).unwrap() as u32)
                .collect();
            if m_anns.is_empty() {
                continue;
            }
            m_anns.sort_unstable();
            align4(&mut data);
            let dir_off = abs_pos(&data);
            if first_ann_dir_off == 0 {
                first_ann_dir_off = dir_off;
            }
            ann_dir_count += 1;
            class_ann_offs[ci] = dir_off;
            data.extend_from_slice(&0u32.to_le_bytes()); // class_annotations_off
            data.extend_from_slice(&0u32.to_le_bytes()); // fields_size
            data.extend_from_slice(&(m_anns.len() as u32).to_le_bytes()); // annotated_methods_size
            data.extend_from_slice(&0u32.to_le_bytes()); // annotated_parameters_size
            for midx in m_anns {
                data.extend_from_slice(&midx.to_le_bytes());
                data.extend_from_slice(&ann_set_off.to_le_bytes());
            }
        }
    }

    // c) code_items (0x2001)
    let compile_method_code = |m: &MethodDef, buf: &mut Vec<u8>| -> u32 {
        let mut labels = BTreeMap::new();
        let mut pc = 0usize;
        for op in &m.ops {
            if let InsnOp::Label(lbl) = op {
                labels.insert(*lbl, pc);
            } else {
                pc += insn_width(op);
            }
        }

        let mut insns = Vec::<u16>::with_capacity(pc);
        let mut cur_pc = 0usize;
        for op in &m.ops {
            match op {
                InsnOp::Label(_) => continue,
                InsnOp::Move(a, b) => {
                    assert!(*a < 16 && *b < 16);
                    insns.push(0x0001 | ((*a as u16) << 8) | ((*b as u16) << 12));
                }
                InsnOp::MoveObj(a, b) => {
                    assert!(*a < 16 && *b < 16);
                    insns.push(0x0007 | ((*a as u16) << 8) | ((*b as u16) << 12));
                }
                InsnOp::MoveResult(r) => insns.push(0x000a | ((*r as u16) << 8)),
                InsnOp::MoveResultObj(r) => insns.push(0x000c | ((*r as u16) << 8)),
                InsnOp::MoveException(r) => insns.push(0x000d | ((*r as u16) << 8)),
                InsnOp::ReturnVoid => insns.push(0x000e),
                InsnOp::Return(r) => insns.push(0x000f | ((*r as u16) << 8)),
                InsnOp::ReturnObj(r) => insns.push(0x0011 | ((*r as u16) << 8)),
                InsnOp::Const4(r, val) => {
                    assert!(*r < 16);
                    insns.push(0x0012 | ((*r as u16) << 8) | (((*val as u8 & 0x0f) as u16) << 12));
                }
                InsnOp::Const16(r, val) => {
                    insns.push(0x0013 | ((*r as u16) << 8));
                    insns.push(*val as u16);
                }
                InsnOp::Const32(r, val) => {
                    let u = *val as u32;
                    insns.push(0x0014 | ((*r as u16) << 8));
                    insns.push((u & 0xffff) as u16);
                    insns.push((u >> 16) as u16);
                }
                InsnOp::ConstString(r, s) => {
                    let sidx = *string_idx.get(s).unwrap();
                    assert!(sidx <= u16::MAX as u32);
                    insns.push(0x001a | ((*r as u16) << 8));
                    insns.push(sidx as u16);
                }
                InsnOp::ConstClass(r, t) => {
                    let tidx = *type_idx.get(*t).unwrap() as u16;
                    insns.push(0x001c | ((*r as u16) << 8));
                    insns.push(tidx);
                }
                InsnOp::CheckCast(r, t) => {
                    let tidx = *type_idx.get(*t).unwrap() as u16;
                    insns.push(0x001f | ((*r as u16) << 8));
                    insns.push(tidx);
                }
                InsnOp::ArrayLength(dest, arr) => {
                    assert!(*dest < 16 && *arr < 16);
                    insns.push(0x0021 | ((*dest as u16) << 8) | ((*arr as u16) << 12));
                }
                InsnOp::NewInstance(r, t) => {
                    let tidx = *type_idx.get(*t).unwrap() as u16;
                    insns.push(0x0022 | ((*r as u16) << 8));
                    insns.push(tidx);
                }
                InsnOp::NewArray(dest, len_reg, t) => {
                    assert!(*dest < 16 && *len_reg < 16);
                    let tidx = *type_idx.get(*t).unwrap() as u16;
                    insns.push(0x0023 | ((*dest as u16) << 8) | ((*len_reg as u16) << 12));
                    insns.push(tidx);
                }
                InsnOp::Goto16(lbl) => {
                    let target = *labels.get(*lbl).unwrap() as isize;
                    let delta = (target - cur_pc as isize) as i16;
                    insns.push(0x0029);
                    insns.push(delta as u16);
                }
                InsnOp::IfEq(a, b, lbl) => {
                    assert!(*a < 16 && *b < 16);
                    let delta = (*labels.get(*lbl).unwrap() as isize - cur_pc as isize) as i16;
                    insns.push(0x0032 | ((*a as u16) << 8) | ((*b as u16) << 12));
                    insns.push(delta as u16);
                }
                InsnOp::IfNe(a, b, lbl) => {
                    assert!(*a < 16 && *b < 16);
                    let delta = (*labels.get(*lbl).unwrap() as isize - cur_pc as isize) as i16;
                    insns.push(0x0033 | ((*a as u16) << 8) | ((*b as u16) << 12));
                    insns.push(delta as u16);
                }
                InsnOp::IfLt(a, b, lbl) => {
                    assert!(*a < 16 && *b < 16);
                    let delta = (*labels.get(*lbl).unwrap() as isize - cur_pc as isize) as i16;
                    insns.push(0x0034 | ((*a as u16) << 8) | ((*b as u16) << 12));
                    insns.push(delta as u16);
                }
                InsnOp::IfGe(a, b, lbl) => {
                    assert!(*a < 16 && *b < 16);
                    let delta = (*labels.get(*lbl).unwrap() as isize - cur_pc as isize) as i16;
                    insns.push(0x0035 | ((*a as u16) << 8) | ((*b as u16) << 12));
                    insns.push(delta as u16);
                }
                InsnOp::IfGt(a, b, lbl) => {
                    assert!(*a < 16 && *b < 16);
                    let delta = (*labels.get(*lbl).unwrap() as isize - cur_pc as isize) as i16;
                    insns.push(0x0036 | ((*a as u16) << 8) | ((*b as u16) << 12));
                    insns.push(delta as u16);
                }
                InsnOp::IfEqz(r, lbl) => {
                    let delta = (*labels.get(*lbl).unwrap() as isize - cur_pc as isize) as i16;
                    insns.push(0x0038 | ((*r as u16) << 8));
                    insns.push(delta as u16);
                }
                InsnOp::IfNez(r, lbl) => {
                    let delta = (*labels.get(*lbl).unwrap() as isize - cur_pc as isize) as i16;
                    insns.push(0x0039 | ((*r as u16) << 8));
                    insns.push(delta as u16);
                }
                InsnOp::IfLtz(r, lbl) => {
                    let delta = (*labels.get(*lbl).unwrap() as isize - cur_pc as isize) as i16;
                    insns.push(0x003a | ((*r as u16) << 8));
                    insns.push(delta as u16);
                }
                InsnOp::IfGez(r, lbl) => {
                    let delta = (*labels.get(*lbl).unwrap() as isize - cur_pc as isize) as i16;
                    insns.push(0x003b | ((*r as u16) << 8));
                    insns.push(delta as u16);
                }
                InsnOp::IfGtz(r, lbl) => {
                    let delta = (*labels.get(*lbl).unwrap() as isize - cur_pc as isize) as i16;
                    insns.push(0x003c | ((*r as u16) << 8));
                    insns.push(delta as u16);
                }
                InsnOp::IfLez(r, lbl) => {
                    let delta = (*labels.get(*lbl).unwrap() as isize - cur_pc as isize) as i16;
                    insns.push(0x003d | ((*r as u16) << 8));
                    insns.push(delta as u16);
                }
                InsnOp::AgetObj(dest, arr, idx) => {
                    insns.push(0x0046 | ((*dest as u16) << 8));
                    insns.push((*arr as u16) | ((*idx as u16) << 8));
                }
                InsnOp::AputObj(val_r, arr_r, idx_r) => {
                    insns.push(0x004d | ((*val_r as u16) << 8));
                    insns.push((*arr_r as u16) | ((*idx_r as u16) << 8));
                }
                InsnOp::Iget(dest, obj, f) => {
                    assert!(*dest < 16 && *obj < 16);
                    let fidx = *field_idx.get(f).unwrap();
                    insns.push(0x0052 | ((*dest as u16) << 8) | ((*obj as u16) << 12));
                    insns.push(fidx);
                }
                InsnOp::IgetObj(dest, obj, f) => {
                    assert!(*dest < 16 && *obj < 16);
                    let fidx = *field_idx.get(f).unwrap();
                    insns.push(0x0054 | ((*dest as u16) << 8) | ((*obj as u16) << 12));
                    insns.push(fidx);
                }
                InsnOp::Iput(val_r, obj, f) => {
                    assert!(*val_r < 16 && *obj < 16);
                    let fidx = *field_idx.get(f).unwrap();
                    insns.push(0x0059 | ((*val_r as u16) << 8) | ((*obj as u16) << 12));
                    insns.push(fidx);
                }
                InsnOp::IputObj(val_r, obj, f) => {
                    assert!(*val_r < 16 && *obj < 16);
                    let fidx = *field_idx.get(f).unwrap();
                    insns.push(0x005b | ((*val_r as u16) << 8) | ((*obj as u16) << 12));
                    insns.push(fidx);
                }
                InsnOp::Sget(dest, f) => {
                    insns.push(0x0060 | ((*dest as u16) << 8));
                    insns.push(*field_idx.get(f).unwrap());
                }
                InsnOp::SgetObj(dest, f) => {
                    insns.push(0x0062 | ((*dest as u16) << 8));
                    insns.push(*field_idx.get(f).unwrap());
                }
                InsnOp::Sput(val_r, f) => {
                    insns.push(0x0067 | ((*val_r as u16) << 8));
                    insns.push(*field_idx.get(f).unwrap());
                }
                InsnOp::SputObj(val_r, f) => {
                    insns.push(0x0069 | ((*val_r as u16) << 8));
                    insns.push(*field_idx.get(f).unwrap());
                }
                InsnOp::InvokeVirtual(regs, ms) => {
                    insns.extend_from_slice(&encode_35c(0x6e, regs, *method_idx.get(ms).unwrap()));
                }
                InsnOp::InvokeSuper(regs, ms) => {
                    insns.extend_from_slice(&encode_35c(0x6f, regs, *method_idx.get(ms).unwrap()));
                }
                InsnOp::InvokeDirect(regs, ms) => {
                    insns.extend_from_slice(&encode_35c(0x70, regs, *method_idx.get(ms).unwrap()));
                }
                InsnOp::InvokeStatic(regs, ms) => {
                    insns.extend_from_slice(&encode_35c(0x71, regs, *method_idx.get(ms).unwrap()));
                }
                InsnOp::InvokeInterface(regs, ms) => {
                    insns.extend_from_slice(&encode_35c(0x72, regs, *method_idx.get(ms).unwrap()));
                }
                InsnOp::InvokeVirtualRange(start_r, count, ms) => {
                    insns.push(0x0074 | ((*count as u16) << 8));
                    insns.push(*method_idx.get(ms).unwrap());
                    insns.push(*start_r as u16);
                }
                InsnOp::AddInt(d, a, b) => {
                    insns.push(0x0090 | ((*d as u16) << 8));
                    insns.push((*a as u16) | ((*b as u16) << 8));
                }
                InsnOp::SubInt(d, a, b) => {
                    insns.push(0x0091 | ((*d as u16) << 8));
                    insns.push((*a as u16) | ((*b as u16) << 8));
                }
                InsnOp::OrInt(d, a, b) => {
                    insns.push(0x0096 | ((*d as u16) << 8));
                    insns.push((*a as u16) | ((*b as u16) << 8));
                }
                InsnOp::AndIntLit16(d, a, lit) => {
                    assert!(*d < 16 && *a < 16);
                    insns.push(0x00d5 | ((*d as u16) << 8) | ((*a as u16) << 12));
                    insns.push(*lit as u16);
                }
                InsnOp::AddIntLit8(d, a, lit) => {
                    insns.push(0x00d8 | ((*d as u16) << 8));
                    insns.push((*a as u16) | (((*lit as u8) as u16) << 8));
                }
                InsnOp::ShlIntLit8(d, a, lit) => {
                    insns.push(0x00e0 | ((*d as u16) << 8));
                    insns.push((*a as u16) | (((*lit as u8) as u16) << 8));
                }
                InsnOp::UshrIntLit8(d, a, lit) => {
                    insns.push(0x00e2 | ((*d as u16) << 8));
                    insns.push((*a as u16) | (((*lit as u8) as u16) << 8));
                }
            }
            cur_pc += insn_width(op);
        }

        align4(buf);
        let code_off = (data_off + buf.len()) as u32;
        let tries_size = if m.try_block.is_some() { 1u16 } else { 0u16 };
        buf.extend_from_slice(&m.registers_size.to_le_bytes());
        buf.extend_from_slice(&m.ins_size.to_le_bytes());
        buf.extend_from_slice(&m.outs_size.to_le_bytes());
        buf.extend_from_slice(&tries_size.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes()); // debug_info_off
        buf.extend_from_slice(&(insns.len() as u32).to_le_bytes());
        for w in &insns {
            buf.extend_from_slice(&w.to_le_bytes());
        }
        if let Some((start_lbl, end_lbl, catch_lbl)) = m.try_block {
            if insns.len() % 2 == 1 {
                buf.extend_from_slice(&0u16.to_le_bytes());
            }
            let s_pc = *labels.get(start_lbl).unwrap() as u32;
            let e_pc = *labels.get(end_lbl).unwrap() as u32;
            let c_pc = *labels.get(catch_lbl).unwrap() as u32;
            buf.extend_from_slice(&s_pc.to_le_bytes());
            buf.extend_from_slice(&((e_pc - s_pc) as u16).to_le_bytes());
            buf.extend_from_slice(&1u16.to_le_bytes());
            push_uleb128(buf, 1);
            push_sleb128(buf, 0);
            push_uleb128(buf, c_pc);
        }
        code_off
    };

    let mut first_code_off = 0u32;
    let mut code_items_count = 0u32;
    struct CompiledClass {
        sflds: Vec<(u32, u32)>,
        iflds: Vec<(u32, u32)>,
        dir: Vec<(u32, u32, u32)>,
        vir: Vec<(u32, u32, u32)>,
    }
    let mut compiled_classes = Vec::with_capacity(classes.len());
    for c in &classes {
        let mut dir: Vec<(u32, u32, u32)> = c
            .direct_methods
            .iter()
            .map(|m| {
                let code_off = compile_method_code(m, &mut data);
                if first_code_off == 0 {
                    first_code_off = code_off;
                }
                code_items_count += 1;
                (*method_idx.get(&m.spec).unwrap() as u32, m.access_flags, code_off)
            })
            .collect();
        dir.sort_by_key(|(idx, _, _)| *idx);

        let mut vir: Vec<(u32, u32, u32)> = c
            .virtual_methods
            .iter()
            .map(|m| {
                let code_off = compile_method_code(m, &mut data);
                if first_code_off == 0 {
                    first_code_off = code_off;
                }
                code_items_count += 1;
                (*method_idx.get(&m.spec).unwrap() as u32, m.access_flags, code_off)
            })
            .collect();
        vir.sort_by_key(|(idx, _, _)| *idx);

        let mut sflds: Vec<(u32, u32)> = c
            .static_fields
            .iter()
            .map(|(f, fl)| (*field_idx.get(f).unwrap() as u32, *fl))
            .collect();
        sflds.sort_by_key(|(idx, _)| *idx);

        let mut iflds: Vec<(u32, u32)> = c
            .instance_fields
            .iter()
            .map(|(f, fl)| (*field_idx.get(f).unwrap() as u32, *fl))
            .collect();
        iflds.sort_by_key(|(idx, _)| *idx);

        compiled_classes.push(CompiledClass {
            sflds,
            iflds,
            dir,
            vir,
        });
    }

    // d) class_data_items (0x2000)
    let first_class_data_off = abs_pos(&data);
    let mut class_data_offs = Vec::with_capacity(compiled_classes.len());
    for cc in compiled_classes {
        class_data_offs.push(abs_pos(&data));
        push_uleb128(&mut data, cc.sflds.len() as u32);
        push_uleb128(&mut data, cc.iflds.len() as u32);
        push_uleb128(&mut data, cc.dir.len() as u32);
        push_uleb128(&mut data, cc.vir.len() as u32);

        let mut prev = 0u32;
        for (fidx, flags) in cc.sflds {
            push_uleb128(&mut data, fidx - prev);
            push_uleb128(&mut data, flags);
            prev = fidx;
        }
        let mut prev = 0u32;
        for (fidx, flags) in cc.iflds {
            push_uleb128(&mut data, fidx - prev);
            push_uleb128(&mut data, flags);
            prev = fidx;
        }
        let mut prev = 0u32;
        for (midx, flags, coff) in cc.dir {
            push_uleb128(&mut data, midx - prev);
            push_uleb128(&mut data, flags);
            push_uleb128(&mut data, coff);
            prev = midx;
        }
        let mut prev = 0u32;
        for (midx, flags, coff) in cc.vir {
            push_uleb128(&mut data, midx - prev);
            push_uleb128(&mut data, flags);
            push_uleb128(&mut data, coff);
            prev = midx;
        }
    }

    // e) map_list (0x1000)
    align4(&mut data);
    let map_off = abs_pos(&data);
    let mut map_items: Vec<(u16, u32, u32)> = vec![
        (0x0000, 1, 0),
        (0x0001, sorted_strings.len() as u32, string_ids_off as u32),
        (0x0002, type_entries.len() as u32, type_ids_off as u32),
        (0x0003, sorted_protos.len() as u32, proto_ids_off as u32),
        (0x0004, field_entries.len() as u32, field_ids_off as u32),
        (0x0005, method_entries.len() as u32, method_ids_off as u32),
        (0x0006, classes.len() as u32, class_defs_off as u32),
        (0x2002, sorted_strings.len() as u32, first_string_data_off),
    ];
    if type_list_count > 0 {
        map_items.push((0x1001, type_list_count, first_type_list_off));
    }
    if ann_item_off > 0 {
        map_items.push((0x2004, 1, ann_item_off));
        map_items.push((0x1003, 1, ann_set_off));
    }
    if ann_dir_count > 0 {
        map_items.push((0x2006, ann_dir_count, first_ann_dir_off));
    }
    if code_items_count > 0 {
        map_items.push((0x2001, code_items_count, first_code_off));
    }
    map_items.push((0x2000, classes.len() as u32, first_class_data_off));
    map_items.push((0x1000, 1, map_off));
    map_items.retain(|&(_, count, _)| count > 0);
    map_items.sort_by_key(|&(_, _, off)| off);

    data.extend_from_slice(&(map_items.len() as u32).to_le_bytes());
    for (item_type, count, off) in &map_items {
        data.extend_from_slice(&item_type.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&count.to_le_bytes());
        data.extend_from_slice(&off.to_le_bytes());
    }

    let data_size = data.len() as u32;
    let file_size = data_off as u32 + data_size;

    let mut dex = Vec::with_capacity(file_size as usize);
    dex.extend_from_slice(b"dex\n035\0");
    dex.extend_from_slice(&0u32.to_le_bytes());
    dex.extend_from_slice(&[0u8; 20]);
    dex.extend_from_slice(&file_size.to_le_bytes());
    dex.extend_from_slice(&(header_size as u32).to_le_bytes());
    dex.extend_from_slice(&0x1234_5678u32.to_le_bytes());
    dex.extend_from_slice(&0u32.to_le_bytes());
    dex.extend_from_slice(&0u32.to_le_bytes());
    dex.extend_from_slice(&map_off.to_le_bytes());
    dex.extend_from_slice(&(sorted_strings.len() as u32).to_le_bytes());
    dex.extend_from_slice(&(string_ids_off as u32).to_le_bytes());
    dex.extend_from_slice(&(type_entries.len() as u32).to_le_bytes());
    dex.extend_from_slice(&(type_ids_off as u32).to_le_bytes());
    dex.extend_from_slice(&(sorted_protos.len() as u32).to_le_bytes());
    dex.extend_from_slice(&(proto_ids_off as u32).to_le_bytes());
    dex.extend_from_slice(&(field_entries.len() as u32).to_le_bytes());
    dex.extend_from_slice(&(field_ids_off as u32).to_le_bytes());
    dex.extend_from_slice(&(method_entries.len() as u32).to_le_bytes());
    dex.extend_from_slice(&(method_ids_off as u32).to_le_bytes());
    dex.extend_from_slice(&(classes.len() as u32).to_le_bytes());
    dex.extend_from_slice(&(class_defs_off as u32).to_le_bytes());
    dex.extend_from_slice(&data_size.to_le_bytes());
    dex.extend_from_slice(&(data_off as u32).to_le_bytes());
    assert_eq!(dex.len(), header_size);

    for off in &string_data_offs {
        dex.extend_from_slice(&off.to_le_bytes());
    }
    for (sidx, _) in &type_entries {
        dex.extend_from_slice(&sidx.to_le_bytes());
    }
    for (i, pk) in sorted_protos.iter().enumerate() {
        let sh_idx = *string_idx.get(&pk.shorty).unwrap();
        dex.extend_from_slice(&sh_idx.to_le_bytes());
        dex.extend_from_slice(&pk.ret_type_idx.to_le_bytes());
        dex.extend_from_slice(&proto_param_offs[i].to_le_bytes());
    }
    for ((cidx, nidx, tidx), _) in &field_entries {
        dex.extend_from_slice(&cidx.to_le_bytes());
        dex.extend_from_slice(&tidx.to_le_bytes());
        dex.extend_from_slice(&nidx.to_le_bytes());
    }
    for ((cidx, nidx, pidx), _) in &method_entries {
        dex.extend_from_slice(&cidx.to_le_bytes());
        dex.extend_from_slice(&pidx.to_le_bytes());
        dex.extend_from_slice(&nidx.to_le_bytes());
    }
    for (i, c) in classes.iter().enumerate() {
        let cidx = *type_idx.get(c.desc).unwrap();
        let sidx = *type_idx.get(c.super_desc).unwrap();
        dex.extend_from_slice(&cidx.to_le_bytes());
        dex.extend_from_slice(&c.access_flags.to_le_bytes());
        dex.extend_from_slice(&sidx.to_le_bytes());
        dex.extend_from_slice(&class_iface_offs[i].to_le_bytes());
        dex.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
        dex.extend_from_slice(&class_ann_offs[i].to_le_bytes());
        dex.extend_from_slice(&class_data_offs[i].to_le_bytes());
        dex.extend_from_slice(&0u32.to_le_bytes());
    }
    assert_eq!(dex.len(), data_off);
    dex.extend_from_slice(&data);

    let sha1 = Sha1::digest(&dex[32..]);
    dex[12..32].copy_from_slice(&sha1);
    let adler = adler32_slice(&dex[12..]);
    dex[8..12].copy_from_slice(&adler.to_le_bytes());
    dex
}

/// Verificador independente de DEX v035: valida magic, checksums, tabelas ordenadas,
/// `map_list`, anotações `@JavascriptInterface`, alinhamento `code_item` e todos os opcodes emitidos.
pub fn verify_dex(dex: &[u8]) -> Result<(), DexError> {
    if dex.len() < 0x70 || &dex[..8] != b"dex\n035\0" {
        return Err(DexError::Invalid("magic DEX 035 inválido".into()));
    }
    let u32_at = |off: usize| -> u32 { u32::from_le_bytes(dex[off..off + 4].try_into().unwrap()) };
    let u16_at = |off: usize| -> u16 { u16::from_le_bytes([dex[off], dex[off + 1]]) };

    let file_size = u32_at(32) as usize;
    if file_size != dex.len() || u32_at(36) != 0x70 || u32_at(40) != 0x1234_5678 {
        return Err(DexError::Invalid("cabeçalho DEX inconsistente".into()));
    }
    let expected_adler = u32_at(8);
    if adler32_slice(&dex[12..]) != expected_adler {
        return Err(DexError::Invalid("checksum Adler-32 DEX inválido".into()));
    }
    if Sha1::digest(&dex[32..]).as_slice() != &dex[12..32] {
        return Err(DexError::Invalid("assinatura SHA-1 DEX inválida".into()));
    }

    let map_off = u32_at(52) as usize;
    let data_off_hdr = u32_at(108) as usize;
    if map_off == 0 || map_off % 4 != 0 || map_off < data_off_hdr || map_off + 4 > dex.len() {
        return Err(DexError::Invalid("map_off inválido para Android ART".into()));
    }
    let map_count = u32_at(map_off) as usize;
    if map_count == 0 || map_off + 4 + map_count * 12 > dex.len() {
        return Err(DexError::Invalid("map_list excede tamanho do DEX".into()));
    }
    let mut prev_map_off = None;
    let mut saw_map_list_item = false;
    let mut saw_ann_dir = false;
    for i in 0..map_count {
        let base = map_off + 4 + i * 12;
        let typ = u16_at(base);
        let cnt = u32_at(base + 4);
        let off = u32_at(base + 8);
        if cnt == 0 {
            return Err(DexError::Invalid("map_item com tamanho zero".into()));
        }
        if let Some(p) = prev_map_off {
            if off <= p {
                return Err(DexError::Invalid("map_list fora de ordem de offset".into()));
            }
        }
        prev_map_off = Some(off);
        if i == 0 && (typ != 0x0000 || off != 0) {
            return Err(DexError::Invalid("primeiro map_item deve ser header_item em 0".into()));
        }
        if typ == 0x1000 && off == map_off as u32 && cnt == 1 {
            saw_map_list_item = true;
        }
        if typ == 0x2006 {
            saw_ann_dir = true;
        }
    }
    if !saw_map_list_item {
        return Err(DexError::Invalid("map_list não contém entrada TYPE_MAP_LIST".into()));
    }
    if !saw_ann_dir {
        return Err(DexError::Invalid("anotações @JavascriptInterface ausentes no map_list".into()));
    }

    let str_n = u32_at(56) as usize;
    let str_off = u32_at(60) as usize;
    let typ_n = u32_at(64) as usize;
    let typ_off = u32_at(68) as usize;
    let prt_n = u32_at(72) as usize;
    let prt_off = u32_at(76) as usize;
    let fld_n = u32_at(80) as usize;
    let fld_off = u32_at(84) as usize;
    let mth_n = u32_at(88) as usize;
    let mth_off = u32_at(92) as usize;
    let cls_n = u32_at(96) as usize;
    let cls_off = u32_at(100) as usize;

    let mut strings: Vec<String> = Vec::with_capacity(str_n);
    let mut prev_utf16: Option<Vec<u16>> = None;
    for i in 0..str_n {
        let mut p = u32_at(str_off + i * 4) as usize;
        let u16_len = read_uleb128(dex, &mut p)?;
        let nul = dex[p..]
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| DexError::Invalid("string DEX sem terminador NUL".into()))?;
        let units = decode_mutf8(&dex[p..p + nul])?;
        if units.len() != u16_len as usize {
            return Err(DexError::Invalid(format!(
                "string_data utf16_size divergente: header={u16_len}, decoded={}",
                units.len()
            )));
        }
        if let Some(prev) = &prev_utf16 {
            if prev.as_slice() >= units.as_slice() {
                return Err(DexError::Invalid("string_ids fora de ordem UTF-16".into()));
            }
        }
        prev_utf16 = Some(units.clone());
        strings.push(String::from_utf16_lossy(&units));
    }

    let mut types = Vec::with_capacity(typ_n);
    for i in 0..typ_n {
        let sidx = u32_at(typ_off + i * 4) as usize;
        if let Some(&prev) = types.last() {
            if prev >= sidx {
                return Err(DexError::Invalid("type_ids fora de ordem".into()));
            }
        }
        types.push(sidx);
    }

    let mut protos = Vec::with_capacity(prt_n);
    for i in 0..prt_n {
        let base = prt_off + i * 12;
        let ret = u32_at(base + 4);
        let p_off = u32_at(base + 8) as usize;
        let mut params = Vec::new();
        if p_off != 0 {
            if p_off % 4 != 0 {
                return Err(DexError::Invalid("type_list não alinhada em 4 bytes".into()));
            }
            let cnt = u32_at(p_off) as usize;
            for j in 0..cnt {
                params.push(u16_at(p_off + 4 + j * 2));
            }
        }
        let key = (ret, params);
        if let Some(prev) = protos.last() {
            if prev >= &key {
                return Err(DexError::Invalid("proto_ids fora de ordem".into()));
            }
        }
        protos.push(key);
    }

    let mut prev_fld = None;
    for i in 0..fld_n {
        let base = fld_off + i * 8;
        let k = (u16_at(base), u32_at(base + 4), u16_at(base + 2));
        if let Some(p) = prev_fld {
            if p >= k {
                return Err(DexError::Invalid("field_ids fora de ordem".into()));
            }
        }
        prev_fld = Some(k);
    }

    let mut method_names = Vec::with_capacity(mth_n);
    let mut prev_mth = None;
    for i in 0..mth_n {
        let base = mth_off + i * 8;
        let cidx = u16_at(base);
        let pidx = u16_at(base + 2);
        let nidx = u32_at(base + 4);
        let k = (cidx, nidx, pidx);
        if let Some(p) = prev_mth {
            if p >= k {
                return Err(DexError::Invalid("method_ids fora de ordem".into()));
            }
        }
        prev_mth = Some(k);
        method_names.push((strings[types[cidx as usize]].as_str(), strings[nidx as usize].as_str()));
    }

    let mut saw_map_put_iface = false;
    let mut saw_load_data_range = false;
    let mut saw_js_bridge_reg = false;
    let mut saw_vpn_establish = false;
    let mut saw_nfc_dispatch = false;

    for i in 0..cls_n {
        let base = cls_off + i * 32;
        let iface_off = u32_at(base + 12) as usize;
        if iface_off != 0 && iface_off % 4 != 0 {
            return Err(DexError::Invalid("interfaces_off desalinhado".into()));
        }
        let ann_off = u32_at(base + 20) as usize;
        if ann_off != 0 {
            if ann_off % 4 != 0 || ann_off + 16 > dex.len() {
                return Err(DexError::Invalid("annotations_directory_item inválido".into()));
            }
            let m_ann_cnt = u32_at(ann_off + 8) as usize;
            let mut prev_m = None;
            for j in 0..m_ann_cnt {
                let mid = u32_at(ann_off + 16 + j * 8);
                if let Some(pm) = prev_m {
                    if mid <= pm {
                        return Err(DexError::Invalid("method_annotations fora de ordem".into()));
                    }
                }
                prev_m = Some(mid);
            }
        }
        let cd_off = u32_at(base + 24) as usize;
        let mut p = cd_off;
        let sf = read_uleb128(dex, &mut p)?;
        let inf = read_uleb128(dex, &mut p)?;
        let dm = read_uleb128(dex, &mut p)?;
        let vm = read_uleb128(dex, &mut p)?;
        for _ in 0..(sf + inf) {
            let _ = read_uleb128(dex, &mut p)?;
            let _ = read_uleb128(dex, &mut p)?;
        }
        for count in [dm, vm] {
            let mut _m_acc = 0u32;
            for _ in 0..count {
                _m_acc += read_uleb128(dex, &mut p)?;
                let _flags = read_uleb128(dex, &mut p)?;
                let coff = read_uleb128(dex, &mut p)? as usize;
                if coff == 0 {
                    continue;
                }
                if coff % 4 != 0 || coff + 16 > dex.len() {
                    return Err(DexError::Invalid("code_item desalinhado ou fora do arquivo".into()));
                }
                let regs = u16_at(coff);
                let ins = u16_at(coff + 2);
                let tries = u16_at(coff + 6);
                let insns_size = u32_at(coff + 12) as usize;
                if ins > regs {
                    return Err(DexError::Invalid("ins_size > registers_size".into()));
                }
                let insns_byte_off = coff + 16;
                if insns_byte_off + insns_size * 2 > dex.len() {
                    return Err(DexError::Invalid("insns truncadas".into()));
                }
                let mut pc = 0usize;
                while pc < insns_size {
                    let w0 = u16_at(insns_byte_off + pc * 2);
                    let op = (w0 & 0xff) as u8;
                    let w = match op {
                        0x00 | 0x0e => 1,
                        0x01 | 0x07 | 0x21 => {
                            let a = (w0 >> 8) & 0x0f;
                            let b = (w0 >> 12) & 0x0f;
                            if a >= regs || b >= regs {
                                return Err(DexError::Invalid("registrador 12x fora dos limites".into()));
                            }
                            1
                        }
                        0x0a | 0x0c | 0x0d | 0x0f | 0x11 => {
                            let r = (w0 >> 8) as u16;
                            if r >= regs {
                                return Err(DexError::Invalid("registrador 11x fora dos limites".into()));
                            }
                            1
                        }
                        0x12 => {
                            let r = (w0 >> 8) & 0x0f;
                            if r >= regs {
                                return Err(DexError::Invalid("registrador 11n fora dos limites".into()));
                            }
                            1
                        }
                        0x13 | 0x1a | 0x1c | 0x1f | 0x22 | 0x23 | 0x29 | 0x32 | 0x33 | 0x34
                        | 0x35 | 0x36 | 0x38 | 0x39 | 0x3a | 0x3b | 0x3c | 0x3d | 0x46 | 0x4d
                        | 0x52 | 0x54 | 0x59 | 0x5b | 0x60 | 0x62 | 0x67 | 0x69 | 0x90 | 0x91
                        | 0x96 | 0xd5 | 0xd8 | 0xe0 | 0xe2 => 2,
                        0x14 => 3,
                        0x6e | 0x6f | 0x70 | 0x71 | 0x72 => {
                            let midx = u16_at(insns_byte_off + (pc + 1) * 2) as usize;
                            let (c, mname) = method_names[midx];
                            if mname == "<init>" && op != 0x70 {
                                return Err(DexError::Invalid(format!(
                                    "{c}.<init> deve usar invoke-direct (0x70), não 0x{op:02x}"
                                )));
                            }
                            if c == "Ljava/util/Map;" && mname == "put" {
                                if op != 0x72 {
                                    return Err(DexError::Invalid("Map.put deve usar invoke-interface (0x72)".into()));
                                }
                                saw_map_put_iface = true;
                            }
                            if c == "Landroid/webkit/WebView;" && mname == "addJavascriptInterface" {
                                saw_js_bridge_reg = true;
                            }
                            if c == "Landroid/net/VpnService$Builder;" && mname == "establish" {
                                saw_vpn_establish = true;
                            }
                            if c == "Landroid/nfc/NfcAdapter;" && mname == "enableForegroundDispatch" {
                                saw_nfc_dispatch = true;
                            }
                            3
                        }
                        0x74 => {
                            let midx = u16_at(insns_byte_off + (pc + 1) * 2) as usize;
                            let count = (w0 >> 8) as u16;
                            let start_r = u16_at(insns_byte_off + (pc + 2) * 2);
                            if start_r + count > regs {
                                return Err(DexError::Invalid("invoke-virtual/range excede registers_size".into()));
                            }
                            let (c, mname) = method_names[midx];
                            if mname == "<init>" {
                                return Err(DexError::Invalid(format!(
                                    "{c}.<init> não pode usar invoke-virtual/range"
                                )));
                            }
                            if c == "Landroid/webkit/WebView;" && mname == "loadDataWithBaseURL" {
                                saw_load_data_range = true;
                            }
                            3
                        }
                        other => return Err(DexError::Invalid(format!("opcode DEX desconhecido 0x{other:02x}"))),
                    };
                    pc += w;
                }
                if pc != insns_size {
                    return Err(DexError::Invalid("instruções não alinham com insns_size".into()));
                }
                if tries > 0 {
                    let tries_off =
                        insns_byte_off + insns_size * 2 + if insns_size % 2 == 1 { 2 } else { 0 };
                    if tries_off + tries as usize * 8 > dex.len() {
                        return Err(DexError::Invalid("try_item fora do arquivo".into()));
                    }
                    let start_addr = u32_at(tries_off) as usize;
                    let insn_cnt = u16_at(tries_off + 4) as usize;
                    let h_off = u16_at(tries_off + 6) as usize;
                    if start_addr + insn_cnt > insns_size {
                        return Err(DexError::Invalid("try_item excede insns_size".into()));
                    }
                    let handlers_base = tries_off + tries as usize * 8;
                    let mut hp = handlers_base + h_off;
                    let h_size = read_sleb128(dex, &mut hp)?;
                    if h_size > 0 {
                        for _ in 0..h_size {
                            let _t = read_uleb128(dex, &mut hp)?;
                            let _a = read_uleb128(dex, &mut hp)?;
                        }
                    } else {
                        for _ in 0..h_size.unsigned_abs() {
                            let _t = read_uleb128(dex, &mut hp)?;
                            let _a = read_uleb128(dex, &mut hp)?;
                        }
                        let catch_all = read_uleb128(dex, &mut hp)? as usize;
                        if catch_all >= insns_size {
                            return Err(DexError::Invalid("catch_all_addr excede insns_size".into()));
                        }
                    }
                }
            }
        }
    }

    if !saw_map_put_iface {
        return Err(DexError::Invalid("Map.put invoke-interface ausente".into()));
    }
    if !saw_load_data_range {
        return Err(DexError::Invalid("loadDataWithBaseURL invoke-virtual/range ausente".into()));
    }
    if !saw_js_bridge_reg {
        return Err(DexError::Invalid("WebView.addJavascriptInterface ausente".into()));
    }
    if !saw_vpn_establish {
        return Err(DexError::Invalid("VpnService.Builder.establish ausente".into()));
    }
    if !saw_nfc_dispatch {
        return Err(DexError::Invalid("NfcAdapter.enableForegroundDispatch ausente".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiles_and_independently_verifies_dex_035() {
        let dex = compile_classes_dex();
        verify_dex(&dex).expect("DEX compilado deve passar todas as verificações Dalvik/ART");
        assert!(dex.len() > 3500);
        let mut tampered = dex.clone();
        tampered[dex.len() - 1] ^= 0xff;
        assert!(verify_dex(&tampered).is_err());
    }

    #[test]
    fn mutf8_encodes_and_rejects_raw_4byte_utf8() {
        let mut enc = Vec::new();
        encode_mutf8(&mut enc, "🌿ok");
        assert!(!enc.iter().any(|&b| b >= 0xf0));
        let dec = decode_mutf8(&enc).expect("MUTF-8 válido");
        assert_eq!(String::from_utf16_lossy(&dec), "🌿ok");
        assert!(decode_mutf8("🌿".as_bytes()).is_err());
    }
}
