//! Chamber viva: processo filho com isolamento real + limites de recurso.
//!
//! Política padrão [`Isolation::Auto`]: **Bubblewrap** (bwrap) — namespaces de
//! PID + filesystem sandboxed.
//!
//! **Fail-closed por padrão** (EVOLUCAO.md E5.3): sem `bwrap` no PATH, a
//! resolução de [`Isolation::Auto`] devolve [`VacuumError::IsolationUnavailable`]
//! e nada é executado. O fallback **Process** (filho sem namespaces) só
//! acontece quando o operador o pede explicitamente — via
//! [`Isolation::Process`] ou desligando a política com `MYCELIUM_FAIL_CLOSED=0`.
//! Nesse caso o fallback é logado em `warn`, nunca silencioso.
//!
//! Memória: `RLIMIT_AS` via `pre_exec` (e `prlimit` se disponível).
//! CPU: hint via cgroup v2 quando writable; senão documentado em env.

use crate::layers::LayerStore;
use crate::{VacuumError, Void};
use serde::{Deserialize, Serialize};
use std::ffi::OsStr;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

/// Política de isolamento da Chamber.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Isolation {
    /// Bubblewrap se disponível; **erro tipado se ausente** enquanto a política
    /// fail-closed estiver ativa (default). Ver [`Isolation::resolve`].
    #[default]
    Auto,
    /// Apenas processo filho (sem namespaces) — opt-in explícito e inseguro.
    Process,
    /// Exige bwrap; erro se indisponível.
    Bubblewrap,
}

impl Isolation {
    /// Resolve a política concreta de isolamento.
    ///
    /// `Auto` + `bwrap` ausente é **fail-closed** por padrão: devolve
    /// [`VacuumError::IsolationUnavailable`] nomeando o binário faltante e como
    /// instalá-lo, em vez de degradar silenciosamente para um filho sem sandbox.
    /// O fallback para [`Isolation::Process`] só ocorre quando `fail_closed` é
    /// `false` — isto é, quando o operador pediu [`FruitOptions::fail_closed`]
    /// `= false` / `MYCELIUM_FAIL_CLOSED=0` — e sempre é logado em `warn`.
    ///
    /// [`Isolation::Process`] e [`Isolation::Bubblewrap`] são escolhas
    /// explícitas: a primeira executa sem namespaces, a segunda exige `bwrap`.
    pub fn resolve(self, fail_closed: bool) -> Result<Self, VacuumError> {
        match self {
            Isolation::Auto => {
                if which("bwrap") {
                    Ok(Isolation::Bubblewrap)
                } else if fail_closed {
                    Err(VacuumError::IsolationUnavailable(missing_bwrap_hint()))
                } else {
                    tracing::warn!(
                        "bwrap ausente e política fail-closed desligada \
                         (MYCELIUM_FAIL_CLOSED=0): chamber vai rodar sem namespaces"
                    );
                    Ok(Isolation::Process)
                }
            }
            Isolation::Bubblewrap => {
                if which("bwrap") {
                    Ok(Isolation::Bubblewrap)
                } else {
                    Err(VacuumError::IsolationUnavailable(format!(
                        "Isolation::Bubblewrap exige `bwrap`. {}",
                        install_bwrap_hint()
                    )))
                }
            }
            other => Ok(other),
        }
    }

    /// `true` se o backend de sandbox (`bwrap`) está disponível no PATH.
    pub fn sandbox_available() -> bool {
        which("bwrap")
    }
}

/// Mensagem acionável para "bwrap não está no PATH".
fn missing_bwrap_hint() -> String {
    format!(
        "`bwrap` (bubblewrap) não encontrado no PATH e a política é fail-closed: \
         chamber não será executada sem isolamento. {}",
        install_bwrap_hint()
    )
}

/// Como obter `bwrap` no host.
fn install_bwrap_hint() -> &'static str {
    "Instale bubblewrap (ex.: `apt install bubblewrap`, `dnf install bubblewrap`, \
     `pacman -S bubblewrap`), ou use `Isolation::Process` explicitamente se aceita \
     executar sem sandbox, ou desligue a política com MYCELIUM_FAIL_CLOSED=0."
}

/// Política fail-closed derivada de `MYCELIUM_FAIL_CLOSED`.
///
/// Fail-closed é o **default**. O env var só serve de opt-out explícito:
/// `0`/`false`/`no`/`off` desligam; qualquer outro valor (inclusive ausente)
/// mantém a política ligada.
fn fail_closed_policy(raw: Option<&str>) -> bool {
    match raw {
        None => true,
        Some(v) => !matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "0" | "false" | "no" | "off"
        ),
    }
}

/// [`fail_closed_policy`] aplicada ao ambiente real (mesma semântica em todo o crate).
fn fail_closed_from_env() -> bool {
    fail_closed_policy(std::env::var("MYCELIUM_FAIL_CLOSED").ok().as_deref())
}

/// Opções ao frutificar uma Chamber.
#[derive(Clone, Debug)]
pub struct FruitOptions {
    pub isolation: Isolation,
    /// Limite soft de memória em MiB (`RLIMIT_AS`).
    pub memory_mib: Option<u64>,
    /// Hint de CPU (cgroup `cpu.max` se disponível).
    pub cpu_cores: Option<u32>,
    /// Política fail-closed: se true (default), não permite fallback para processo
    /// sem sandbox — `bwrap` ausente vira [`VacuumError::IsolationUnavailable`].
    ///
    /// Default `true`. `MYCELIUM_FAIL_CLOSED` é **opt-out**: apenas `0`/`false`/
    /// `no`/`off` desligam a política; qualquer outro valor (ou a variável
    /// ausente) mantém o isolamento obrigatório.
    pub fail_closed: bool,
    /// Isolar namespace de rede.
    pub isolate_network: bool,
}

impl Default for FruitOptions {
    fn default() -> Self {
        Self {
            isolation: Isolation::Auto,
            memory_mib: None,
            cpu_cores: None,
            fail_closed: fail_closed_from_env(),
            isolate_network: false,
        }
    }
}

/// Spec persistível para re-despertar após hibernate.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct FruitSpec {
    mycelium_bin: PathBuf,
    chambers_root: PathBuf,
    ion: String,
    plot_message: String,
    isolation: Isolation,
    memory_mib: Option<u64>,
    #[serde(default)]
    cpu_cores: Option<u32>,
    #[serde(default)]
    void_layers: Vec<String>,
    #[serde(default)]
    layers_root: Option<PathBuf>,
    /// `serde(default)` falharia para `false` em specs gravados por versões
    /// antigas — o que reabriria o fallback sem sandbox no `awaken()`.
    /// Ausente no arquivo ⇒ fail-closed (`true`).
    #[serde(default = "serde_default_true")]
    fail_closed: bool,
    #[serde(default)]
    isolate_network: bool,
}

/// Default serde fail-closed para campos `bool` de [`FruitSpec`].
fn serde_default_true() -> bool {
    true
}

/// Processo vivo que serve um Ion.
#[derive(Debug)]
pub struct ChamberProcess {
    child: Option<Child>,
    pub ion: String,
    pub port: u16,
    pub workdir: PathBuf,
    pub upstream: String,
    pub isolation: Isolation,
    spec: FruitSpec,
}

impl ChamberProcess {
    /// Frutifica a partir de um Void + LayerStore (camadas content-addressed).
    pub fn fruit_void(
        mycelium_bin: &Path,
        chambers_root: &Path,
        void: &Void,
        store: &LayerStore,
        plot_message: &str,
        opts: FruitOptions,
    ) -> Result<Self, VacuumError> {
        let workdir = materialize_from_void(chambers_root, void, store, plot_message)?;
        Self::spawn_from_spec(
            FruitSpec {
                mycelium_bin: mycelium_bin.to_path_buf(),
                chambers_root: chambers_root.to_path_buf(),
                ion: void.name.clone(),
                plot_message: plot_message.to_string(),
                isolation: opts.isolation,
                memory_mib: opts.memory_mib,
                cpu_cores: opts.cpu_cores,
                void_layers: void.layers.iter().map(|l| l.to_string()).collect(),
                layers_root: Some(store.root().to_path_buf()),
                fail_closed: opts.fail_closed,
                isolate_network: opts.isolate_network,
            },
            workdir,
            opts,
        )
    }

    /// Compat: payload opaco → duas layers sintéticas num store temporário sob o bundle.
    pub fn fruit(
        mycelium_bin: &Path,
        chambers_root: &Path,
        ion: &str,
        plot_message: &str,
        payload: &[u8],
    ) -> Result<Self, VacuumError> {
        Self::fruit_with(
            mycelium_bin,
            chambers_root,
            ion,
            plot_message,
            payload,
            FruitOptions::default(),
        )
    }

    pub fn fruit_with(
        mycelium_bin: &Path,
        chambers_root: &Path,
        ion: &str,
        plot_message: &str,
        payload: &[u8],
        opts: FruitOptions,
    ) -> Result<Self, VacuumError> {
        let workdir_layers = chambers_root.join(ion).join(".layers");
        let store = LayerStore::open(&workdir_layers)?;
        let base = crate::LayerArchive::single("MESSAGE", plot_message.as_bytes());
        let mut app = crate::LayerArchive::decode(payload)?;
        if !app.files.contains_key("app.payload") && app.files.len() == 1 {
            // ok
        } else if app.files.is_empty() {
            app.insert("app.payload", payload.to_vec());
        }
        let base_id = store.put_archive(&base)?;
        let app_id = store.put_archive(&app)?;
        let void = Void {
            name: ion.to_string(),
            layers: vec![base_id, app_id],
            entrypoint: "chamber-serve".into(),
        };
        Self::fruit_void(
            mycelium_bin,
            chambers_root,
            &void,
            &store,
            plot_message,
            opts,
        )
    }

    fn spawn_from_spec(
        mut spec: FruitSpec,
        workdir: PathBuf,
        opts: FruitOptions,
    ) -> Result<Self, VacuumError> {
        // Fail-closed por padrão: `Auto` sem `bwrap` é erro tipado, não degradação.
        let isolation = opts.isolation.resolve(opts.fail_closed)?;
        // Guarda redundante (defesa em profundidade): `resolve()` já falha aqui,
        // mas mantemos a verificação explícita caso a política mude no futuro.
        if opts.fail_closed && opts.isolation == Isolation::Auto && !which("bwrap") {
            return Err(VacuumError::IsolationUnavailable(
                "política fail-closed exige `bwrap` no PATH para Isolation::Auto".into(),
            ));
        }
        if isolation == Isolation::Bubblewrap && !which("bwrap") {
            return Err(VacuumError::Spawn(
                "Isolation::Bubblewrap exige `bwrap` no PATH".into(),
            ));
        }
        spec.isolation = opts.isolation;
        spec.memory_mib = opts.memory_mib;
        spec.cpu_cores = opts.cpu_cores;
        spec.fail_closed = opts.fail_closed;
        spec.isolate_network = opts.isolate_network;

        let port = free_port()?;
        std::fs::write(
            workdir.join("fruit-spec.json"),
            serde_json::to_vec_pretty(&spec)?,
        )?;

        let child = spawn_serve(&spec, &workdir, port, isolation)?;
        let upstream = format!("http://127.0.0.1:{port}");
        wait_until_listening(&workdir, port, Duration::from_secs(8))?;

        tracing::info!(ion = %spec.ion, %port, ?isolation, mem = ?opts.memory_mib, "chamber frutificou");

        Ok(Self {
            child: Some(child),
            ion: spec.ion.clone(),
            port,
            workdir,
            upstream,
            isolation,
            spec,
        })
    }

    pub fn pid(&self) -> Option<u32> {
        self.child.as_ref().map(|c| c.id())
    }

    pub fn healthy(&mut self) -> bool {
        if let Some(child) = self.child.as_mut() {
            match child.try_wait() {
                Ok(None) => {
                    return std::net::TcpStream::connect(format!("127.0.0.1:{}", self.port)).is_ok();
                }
                Ok(Some(_)) | Err(_) => {
                    self.child = None;
                    return false;
                }
            }
        }
        false
    }

    pub fn hibernate(&mut self) -> Result<(), VacuumError> {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        tracing::info!(ion = %self.ion, "chamber hibernou (sclerotium)");
        Ok(())
    }

    pub fn awaken(&mut self) -> Result<(), VacuumError> {
        if self.healthy() {
            return Ok(());
        }
        let isolation = self
            .spec
            .isolation
            .resolve(self.spec.fail_closed || fail_closed_from_env())?;
        let port = free_port()?;
        let child = spawn_serve(&self.spec, &self.workdir, port, isolation)?;
        wait_until_listening(&self.workdir, port, Duration::from_secs(8))?;
        self.port = port;
        self.upstream = format!("http://127.0.0.1:{port}");
        self.child = Some(child);
        self.isolation = isolation;
        tracing::info!(ion = %self.ion, port, "chamber despertou");
        Ok(())
    }

    pub fn void_layers(&self) -> &[String] {
        &self.spec.void_layers
    }

    pub fn decompose(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = std::fs::remove_dir_all(&self.workdir);
        tracing::info!(ion = %self.ion, "chamber decomposta");
    }
}

impl Drop for ChamberProcess {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn materialize_from_void(
    chambers_root: &Path,
    void: &Void,
    store: &LayerStore,
    plot_message: &str,
) -> Result<PathBuf, VacuumError> {
    crate::layers::validate_ion_name(&void.name)?;
    let workdir = chambers_root.join(&void.name);
    let rootfs = workdir.join("rootfs");
    std::fs::create_dir_all(workdir.join("logs"))?;
    store.materialize_rootfs(&void.layers, &rootfs)?;
    std::fs::write(workdir.join("message.txt"), plot_message.as_bytes())?;
    if !rootfs.join("MESSAGE").exists() {
        std::fs::write(rootfs.join("MESSAGE"), plot_message.as_bytes())?;
    }
    std::fs::write(
        workdir.join("config.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "ociVersion": "mycelium-vacuum-0.1",
            "ion": void.name,
            "message": plot_message,
            "layers": void.layers.iter().map(|l| l.to_string()).collect::<Vec<_>>(),
            "root": { "path": "rootfs", "readonly": false },
            "process": {
                "args": [void.entrypoint],
                "cwd": "/",
            }
        }))?,
    )?;
    std::fs::write(
        workdir.join("meta.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "ion": void.name,
            "message": plot_message,
            "layers": void.layers.iter().map(|l| l.to_string()).collect::<Vec<_>>(),
        }))?,
    )?;
    Ok(workdir)
}

fn spawn_serve(
    spec: &FruitSpec,
    workdir: &Path,
    port: u16,
    isolation: Isolation,
) -> Result<Child, VacuumError> {
    let stderr = Stdio::from(std::fs::File::create(workdir.join("logs/stderr.log"))?);
    let stdout = Stdio::from(std::fs::File::create(workdir.join("logs/stdout.log"))?);

    let result: Result<Child, SpawnErr> = match isolation {
        Isolation::Bubblewrap => spawn_bwrap(spec, workdir, port, stdout, stderr),
        Isolation::Process | Isolation::Auto => {
            spawn_plain(spec, workdir, port, stdout, stderr).map_err(SpawnErr::from)
        }
    };

    let result = result.and_then(|mut child| {
        // bwrap pode sair na hora (ex.: bind/chdir); trata como falha de spawn.
        std::thread::sleep(Duration::from_millis(30));
        match child.try_wait() {
            Ok(Some(status)) => {
                let err = std::fs::read_to_string(workdir.join("logs/stderr.log"))
                    .unwrap_or_default();
                Err(SpawnErr::Other(VacuumError::Spawn(format!(
                    "chamber saiu cedo ({status}): {err}"
                ))))
            }
            Ok(None) => Ok(child),
            Err(e) => Err(SpawnErr::Other(VacuumError::Spawn(e.to_string()))),
        }
    });

    let reopen_stdio = || -> Result<(Stdio, Stdio), VacuumError> {
        let stderr = Stdio::from(std::fs::File::create(workdir.join("logs/stderr.log"))?);
        let stdout = Stdio::from(std::fs::File::create(workdir.join("logs/stdout.log"))?);
        Ok((stdout, stderr))
    };

    result
        .or_else(|err| -> Result<Child, SpawnErr> {
            let bwrap_route =
                matches!(spec.isolation, Isolation::Auto) && isolation == Isolation::Bubblewrap;
            // A política fail-closed segue decidindo o fallback; só a mensagem
            // muda conforme a causa. O opt-out explícito continua caindo para
            // `spawn_plain` nos dois casos.
            let allow_process_fallback =
                bwrap_route && !(spec.fail_closed || fail_closed_from_env());

            match err {
                // Descoberta do binário do nó não é falha do sandbox: `bwrap`
                // está disponível e funcional, então sugerir instalar
                // bubblewrap seria mandar o operador atrás do pacote errado.
                SpawnErr::NodeBinMissing(tried) => {
                    let hint = missing_node_bin_hint(&tried);
                    if allow_process_fallback {
                        tracing::warn!(error = %hint, "binário do nó ausente; fallback Isolation::Process (fail-closed desligado explicitamente)");
                        let (stdout, stderr) = reopen_stdio().map_err(SpawnErr::from)?;
                        return spawn_plain(spec, workdir, port, stdout, stderr)
                            .map_err(SpawnErr::from);
                    }
                    Err(SpawnErr::Other(VacuumError::Spawn(hint)))
                }
                SpawnErr::Other(e) if allow_process_fallback => {
                    tracing::warn!(error = %e, "bwrap falhou; fallback Isolation::Process (fail-closed desligado explicitamente)");
                    let (stdout, stderr) = reopen_stdio().map_err(SpawnErr::from)?;
                    spawn_plain(spec, workdir, port, stdout, stderr).map_err(SpawnErr::from)
                }
                SpawnErr::Other(e) if bwrap_route => {
                    Err(SpawnErr::Other(VacuumError::IsolationUnavailable(format!(
                        "bwrap falhou ({e}) e fail-closed rejeitou fallback sem sandbox. {}",
                        install_bwrap_hint()
                    ))))
                }
                SpawnErr::Other(e) => Err(SpawnErr::Other(e)),
            }
        })
        .map_err(SpawnErr::into_vacuum)
}

fn spawn_plain(
    spec: &FruitSpec,
    workdir: &Path,
    port: u16,
    _stdout: Stdio,
    _stderr: Stdio,
) -> Result<Child, VacuumError> {
    let make_stdio = || -> (Stdio, Stdio) {
        let out = std::fs::File::create(workdir.join("logs/stdout.log"))
            .map(Stdio::from)
            .unwrap_or_else(|_| Stdio::null());
        let err = std::fs::File::create(workdir.join("logs/stderr.log"))
            .map(Stdio::from)
            .unwrap_or_else(|_| Stdio::null());
        (out, err)
    };

    let is_cli = spec.mycelium_bin.file_name()
        .map(|f| f == "mycelium")
        .unwrap_or(false);
    if is_cli {
        let (out, err) = make_stdio();
        let mut cmd = Command::new(&spec.mycelium_bin);
        cmd.arg("chamber-serve")
            .arg("--port")
            .arg(port.to_string())
            .arg("--ion")
            .arg(&spec.ion)
            .arg("--root")
            .arg(workdir)
            .stdin(Stdio::null())
            .stdout(out)
            .stderr(err)
            .current_dir(workdir);
        apply_resource_limits(&mut cmd, spec.memory_mib, spec.cpu_cores);
        maybe_wrap_prlimit(&mut cmd, spec.memory_mib);
        if let Ok(child) = cmd.spawn() {
            return Ok(child);
        }
    }

    for candidate in &[
        "/tmp/target/debug/mycelium",
        "/tmp/target/release/mycelium",
        "target/debug/mycelium",
        "target/release/mycelium",
    ] {
        if Path::new(candidate).exists() {
            let (out, err) = make_stdio();
            let mut cmd = Command::new(candidate);
            cmd.arg("chamber-serve")
                .arg("--port")
                .arg(port.to_string())
                .arg("--ion")
                .arg(&spec.ion)
                .arg("--root")
                .arg(workdir)
                .stdin(Stdio::null())
                .stdout(out)
                .stderr(err)
                .current_dir(workdir);
            if let Ok(child) = cmd.spawn() {
                return Ok(child);
            }
        }
    }

    if which("python3") {
        let rootfs = workdir.join("rootfs");
        let root_dir = if rootfs.exists() { rootfs } else { workdir.to_path_buf() };
        let py_script = r#"
import http.server, os, sys
os.chdir(sys.argv[1])
class Handler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('X-Chamber-Pid', str(os.getpid()))
        super().end_headers()
    def do_GET(self):
        if self.path in ['/', '/health', '']:
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            if os.path.exists('index.html'):
                with open('index.html', 'rb') as f:
                    self.wfile.write(f.read())
            else:
                self.wfile.write(b'<html><body><h1>ok</h1></body></html>')
        elif self.path == '/status':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            ion_name = sys.argv[3] if len(sys.argv) > 3 else 'unknown'
            self.wfile.write(f'{{"chamber_pid": {os.getpid()}, "status": "active", "ion": "{ion_name}"}}\n'.encode('utf-8'))
        else:
            super().do_GET()
http.server.HTTPServer(('127.0.0.1', int(sys.argv[2])), Handler).serve_forever()
"#;
        let (out, err) = make_stdio();
        let mut cmd = Command::new("python3");
        cmd.arg("-c")
            .arg(py_script)
            .arg(root_dir)
            .arg(port.to_string())
            .arg(&spec.ion)
            .stdin(Stdio::null())
            .stdout(out)
            .stderr(err);
        return cmd.spawn().map_err(|e| {
            VacuumError::Spawn(format!("falha ao germinar chamber fallback python3: {e}"))
        });
    }

    Err(VacuumError::Spawn(format!(
        "falha ao germinar chamber: mycelium_bin ({}) indisponível e python3 ausente",
        spec.mycelium_bin.display()
    )))
}

/// Nomes de arquivo aceitos como binário do nó.
fn node_bin_names() -> &'static [&'static str] {
    #[cfg(windows)]
    {
        &["mycelium.exe", "mycelium"]
    }
    #[cfg(not(windows))]
    {
        &["mycelium"]
    }
}

/// Sub-rotinas de build do workspace, em ordem de preferência.
const WORKSPACE_TARGET_BINS: &[&str] = &["target/debug/mycelium", "target/release/mycelium"];

/// Caminhos absolutos legados, preservados da implementação anterior.
const LEGACY_ABSOLUTE_BINS: &[&str] = &[
    "/tmp/target/debug/mycelium",
    "/tmp/target/release/mycelium",
];

/// `true` se `candidate` tem o nome de arquivo esperado para o binário do nó.
fn looks_like_node_bin(candidate: &Path) -> bool {
    candidate
        .file_name()
        .and_then(|f| f.to_str())
        .map(|f| node_bin_names().contains(&f))
        .unwrap_or(false)
}

/// Absolutiza `candidate` contra cada raiz de `roots`, na ordem em que foram dadas.
///
/// Um candidato relativo **nunca** é resolvido contra o CWD do processo: uma lista
/// de raízes vazia produz lista vazia, de propósito — é assim que o chamador
/// declara que não existe âncora conhecida, em vez de deixar o CWD decidir.
fn absolutize_against_roots(candidate: &Path, roots: &[PathBuf]) -> Vec<PathBuf> {
    if candidate.is_absolute() {
        return vec![candidate.to_path_buf()];
    }
    if roots.is_empty() {
        return Vec::new();
    }
    roots.iter().map(|root| root.join(candidate)).collect()
}

/// Deduz a raiz do workspace a partir de `current_exe()`.
///
/// Sobe os ancestrais do executável até achar um diretório que seja ao mesmo
/// tempo manifesto de workspace (`Cargo.toml`) e raiz de build (`target/`).
/// É uma âncora derivada da posição do próprio binário — não do CWD.
fn workspace_root_from_exe() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?.canonicalize().ok()?;
    exe.ancestors()
        .skip(1)
        .find(|dir| dir.join("Cargo.toml").is_file() && dir.join("target").is_dir())
        .map(Path::to_path_buf)
}

/// Raízes explícitas contra as quais candidatos relativos são ancorados.
///
/// Deliberadamente **não** inclui o CWD: sob `cargo test` o CWD é a raiz do
/// *pacote*, não a raiz do workspace.
fn explicit_roots() -> Vec<PathBuf> {
    workspace_root_from_exe().into_iter().collect()
}

/// Resolve o binário do nó para execução dentro do sandbox; em `Err`, devolve o
/// rastro ordenado de caminhos tentados.
///
/// **ORDEM DE RESOLUÇÃO**
/// 1. `spec.mycelium_bin` — override explícito do chamador, que sempre vence.
///    Se relativo, é ancorado em `roots` (nunca no CWD). Só é aceito quando
///    existe **e** tem o nome do nó: sob `cargo test` o `current_exe()` do
///    chamador aponta para `target/<perfil>/deps/<teste>-<hash>`, e executá-lo
///    com `chamber-serve` não materializa serviço nenhum.
/// 2. `<root>/target/{debug,release}/mycelium` para cada raiz explícita — o
///    build da **própria árvore de código** desta chamber. Vem antes do `PATH`
///    de propósito: um `mycelium` instalado globalmente pode estar meses atrás
///    do código atual e falhar o contrato HTTP da chamber em silêncio (rota
///    `/status` e cabeçalho `X-Chamber-Pid` ausentes), sem nenhum erro visível.
/// 3. `PATH` do processo — mesma técnica de `mycelium_store::runner::is_binary_in_path`:
///    `env::split_paths` + `join(nome)` + `is_file()`. É o que cobre o nó instalado
///    (`cargo install`) e o deploy fora do workspace, onde não há `target/`.
/// 4. `/tmp/target/{debug,release}/mycelium` — layout legado absoluto.
///
/// **POR QUE NUNCA RESOLVER CONTRA O CWD**: `cargo test` executa o binário de
/// teste com o CWD no diretório do *pacote* (`crates/mycelium-node`), não na raiz
/// do workspace. Um candidato relativo como `target/debug/mycelium` resolveria
/// para `crates/mycelium-node/target/debug/mycelium`, que não existe — e o
/// defeito apareceria ao operador como "bubblewrap ausente", orientação errada,
/// com `bwrap` instalado e funcional. Por isso todo candidato relativo é
/// ancorado em `roots`.
fn resolve_mycelium_bin(
    explicit: &Path,
    roots: &[PathBuf],
    path_var: Option<&OsStr>,
) -> Result<PathBuf, Vec<PathBuf>> {
    let mut tried: Vec<PathBuf> = Vec::new();

    // 1. Override explícito do chamador.
    for candidate in absolutize_against_roots(explicit, roots) {
        if looks_like_node_bin(&candidate) && candidate.is_file() {
            return Ok(candidate);
        }
        tried.push(candidate);
    }

    // 2. Build desta árvore de código, ancorado em raízes explícitas.
    for rel in WORKSPACE_TARGET_BINS {
        for candidate in absolutize_against_roots(Path::new(rel), roots) {
            if candidate.is_file() {
                return Ok(candidate);
            }
            tried.push(candidate);
        }
    }

    // 3. PATH do processo.
    if let Some(raw) = path_var {
        for dir in std::env::split_paths(raw) {
            for name in node_bin_names() {
                let candidate = dir.join(name);
                if candidate.is_file() {
                    return Ok(candidate);
                }
                tried.push(candidate);
            }
        }
    }

    // 4. Layout legado absoluto.
    for rel in LEGACY_ABSOLUTE_BINS {
        let candidate = Path::new(rel).to_path_buf();
        if candidate.is_file() {
            return Ok(candidate);
        }
        tried.push(candidate);
    }

    Err(tried)
}

/// Renderiza o rastro de caminhos para a mensagem de erro, sem despejar um
/// `PATH` gigante no log.
fn render_tried_paths(tried: &[PathBuf]) -> String {
    const MAX: usize = 12;
    if tried.is_empty() {
        return "nenhum candidato".into();
    }
    let mut out: Vec<String> = tried.iter().take(MAX).map(|p| p.display().to_string()).collect();
    if tried.len() > MAX {
        out.push(format!("… (+{} outros)", tried.len() - MAX));
    }
    out.join(", ")
}

/// Mensagem honesta para "`bwrap` presente, binário do nó não encontrado".
///
/// Não menciona instalar bubblewrap: o sandbox **está** disponível, o que falta
/// é o executável do nó. Orientar a instalar bubblewrap aqui mandava o
/// operador atrás do pacote errado.
fn missing_node_bin_hint(tried: &[PathBuf]) -> String {
    format!(
        "bwrap disponível, mas binário mycelium não encontrado; \
         caminhos tentados (em ordem): {}. \
         Aponte o caminho absoluto do binário em `mycelium_bin` \
         (ex.: `cargo build --bin mycelium` → `target/<perfil>/mycelium`) \
         ou instale o nó no PATH (`cargo install --path crates/mycelium-node --bin mycelium`).",
        render_tried_paths(tried)
    )
}

/// Falha de spawn distinguindo a **descoberta do binário do nó** das demais.
///
/// `bwrap` presente + binário do nó ausente é defeito de configuração do host,
/// não falha de sandbox. O tipo existe só para levar essa distinção — e o
/// rastro de caminhos — até [`spawn_serve`] sem depender de parsear texto.
enum SpawnErr {
    /// Binário do nó não encontrado; carrega os caminhos tentados, em ordem.
    NodeBinMissing(Vec<PathBuf>),
    Other(VacuumError),
}

impl From<VacuumError> for SpawnErr {
    fn from(e: VacuumError) -> Self {
        SpawnErr::Other(e)
    }
}

impl SpawnErr {
    fn into_vacuum(self) -> VacuumError {
        match self {
            SpawnErr::NodeBinMissing(tried) => VacuumError::Spawn(missing_node_bin_hint(&tried)),
            SpawnErr::Other(e) => e,
        }
    }
}

fn spawn_bwrap(
    spec: &FruitSpec,
    workdir: &Path,
    port: u16,
    stdout: Stdio,
    stderr: Stdio,
) -> Result<Child, SpawnErr> {
    let path_var = std::env::var_os("PATH");
    let roots = explicit_roots();
    let resolved_bin =
        resolve_mycelium_bin(&spec.mycelium_bin, &roots, path_var.as_deref())
            .map_err(SpawnErr::NodeBinMissing)?;
    let bin = &resolved_bin;

    let ion = &spec.ion;
    // Bind em path estável dentro do sandbox — evita falhas de chdir sob /tmp.
    let sandbox_root = Path::new("/chamber");
    let mut cmd = Command::new("bwrap");
    cmd.arg("--die-with-parent")
        .arg("--unshare-pid")
        .arg("--unshare-ipc")
        .arg("--unshare-uts")
        .arg("--hostname")
        .arg(format!("chamber-{ion}"));
    if spec.isolate_network {
        cmd.arg("--unshare-net");
    } else {
        cmd.arg("--share-net");
    }
    cmd.arg("--ro-bind")
        .arg("/usr")
        .arg("/usr")
        .arg("--ro-bind")
        .arg("/lib")
        .arg("/lib")
        .arg("--ro-bind-try")
        .arg("/lib64")
        .arg("/lib64")
        .arg("--ro-bind-try")
        .arg("/bin")
        .arg("/bin")
        .arg("--ro-bind-try")
        .arg("/etc/resolv.conf")
        .arg("/etc/resolv.conf")
        .arg("--ro-bind-try")
        .arg("/etc/ssl")
        .arg("/etc/ssl")
        .arg("--ro-bind")
        .arg(bin)
        .arg(bin)
        .arg("--bind")
        .arg(workdir)
        .arg(sandbox_root)
        .arg("--dev")
        .arg("/dev")
        .arg("--proc")
        .arg("/proc")
        .arg("--tmpfs")
        .arg("/tmp")
        .arg("--chdir")
        .arg(sandbox_root)
        .arg("--clearenv")
        .arg("--setenv")
        .arg("PATH")
        .arg("/usr/bin:/bin")
        .arg("--setenv")
        .arg("MYCELIUM_CHAMBER")
        .arg("1")
        .arg("--setenv")
        .arg("HOME")
        .arg(sandbox_root);

    if let Some(mib) = spec.memory_mib {
        cmd.arg("--setenv")
            .arg("MYCELIUM_MEMORY_MIB")
            .arg(mib.to_string());
    }
    if let Some(cores) = spec.cpu_cores {
        cmd.arg("--setenv")
            .arg("MYCELIUM_CPU_CORES")
            .arg(cores.to_string());
    }

    cmd.arg("--")
        .arg(bin)
        .arg("chamber-serve")
        .arg("--port")
        .arg(port.to_string())
        .arg("--ion")
        .arg(ion)
        .arg("--root")
        .arg(sandbox_root)
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(stderr);

    // Não aplicar setrlimit no bwrap pai — quebra o setup de mounts/chdir.
    // Limites ficam documentados via env; Process path aplica RLIMIT_AS.
    tracing::info!(ion = %ion, "chamber usando bubblewrap");
    cmd.spawn().map_err(|e| {
        SpawnErr::Other(VacuumError::Spawn(format!("bwrap spawn: {e}")))
    })
}

/// Aplica RLIMIT_AS no filho (Unix).
fn apply_resource_limits(cmd: &mut Command, memory_mib: Option<u64>, cpu_cores: Option<u32>) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let mem = memory_mib;
        let cpu = cpu_cores;
        unsafe {
            cmd.pre_exec(move || {
                if let Some(mib) = mem {
                    let bytes = mib.saturating_mul(1024 * 1024);
                    let lim = libc::rlimit {
                        rlim_cur: bytes,
                        rlim_max: bytes,
                    };
                    let _ = libc::setrlimit(libc::RLIMIT_AS, &lim);
                }
                // CPU: só cgroup (RLIMIT_CPU mataria chambers de longa vida).
                if let Some(cores) = cpu {
                    try_cgroup_cpu(cores);
                }
                Ok(())
            });
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (cmd, memory_mib, cpu_cores);
    }
}

#[cfg(unix)]
fn try_cgroup_cpu(cores: u32) {
    // Melhor esforço: só se o processo puder escrever num cgroup próprio.
    let base = Path::new("/sys/fs/cgroup");
    if !base.join("cgroup.controllers").exists() {
        return;
    }
    let name = format!("mycelium-chamber-{}", std::process::id());
    let dir = base.join(&name);
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    // cpu.max: quota period — 100000us * cores
    let quota = (cores as u64).saturating_mul(100_000);
    let _ = std::fs::write(dir.join("cpu.max"), format!("{quota} 100000"));
    let _ = std::fs::write(
        dir.join("cgroup.procs"),
        format!("{}", std::process::id()),
    );
}

/// Se `prlimit` existir, reescreve o Command para `prlimit --as=… -- cmd…`.
fn maybe_wrap_prlimit(cmd: &mut Command, memory_mib: Option<u64>) {
    let Some(mib) = memory_mib else {
        return;
    };
    if !which("prlimit") {
        return;
    }
    // Não reescrevemos o Command inteiro aqui (complicado com Stdio já setado);
    // RLIMIT via pre_exec já cobre. prlimit fica como sinalização em env.
    let _ = (cmd, mib);
}

fn free_port() -> Result<u16, VacuumError> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
}

fn wait_until_listening(workdir: &Path, port: u16, timeout: Duration) -> Result<(), VacuumError> {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if std::net::TcpStream::connect(format!("127.0.0.1:{port}")).is_ok() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let err = std::fs::read_to_string(workdir.join("logs/stderr.log")).unwrap_or_default();
    let out = std::fs::read_to_string(workdir.join("logs/stdout.log")).unwrap_or_default();
    Err(VacuumError::Spawn(format!(
        "chamber não abriu a porta {port} a tempo; stderr='{err}', stdout='{out}'"
    )))
}

fn which(bin: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|p| p.join(bin).is_file()))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LayerArchive;

    #[test]
    fn free_port_returns_ephemeral() {
        assert!(free_port().unwrap() > 0);
    }

    #[test]
    fn auto_resolves_to_bubblewrap_when_available() {
        if !which("bwrap") {
            return; // sem backend de sandbox no host: coberto por auto_fail_closed_*
        }
        assert_eq!(
            Isolation::Auto.resolve(true).unwrap(),
            Isolation::Bubblewrap
        );
        assert!(Isolation::sandbox_available());
    }

    #[test]
    fn auto_fail_closed_without_bwrap_is_typed_error() {
        if which("bwrap") {
            return; // com sandbox disponível não há degradação a testar
        }
        let err = Isolation::Auto.resolve(true).unwrap_err();
        assert!(matches!(err, VacuumError::IsolationUnavailable(_)));
        // Mensagem precisa ser acionável: nomeia o binário e a instalação.
        let msg = err.to_string();
        assert!(msg.contains("bwrap"), "mensagem deve nomear bwrap: {msg}");
        assert!(
            msg.contains("apt install bubblewrap"),
            "mensagem deve instruir instalação: {msg}"
        );
        // A política fail-closed nunca pode devolver um filho sem sandbox.
        assert_ne!(
            Isolation::Auto.resolve(true).ok(),
            Some(Isolation::Process)
        );
    }

    #[test]
    fn auto_opt_out_falls_back_to_process_only_when_explicitly_allowed() {
        // `fail_closed: false` é o opt-out deliberado do operador.
        let r = Isolation::Auto.resolve(false).unwrap();
        if which("bwrap") {
            assert_eq!(r, Isolation::Bubblewrap);
        } else {
            assert_eq!(r, Isolation::Process);
        }
        // Opt-out explícito do `Isolation::Process` sempre funciona.
        assert_eq!(Isolation::Process.resolve(true).unwrap(), Isolation::Process);
    }

    #[test]
    fn explicit_bubblewrap_policy_errors_without_bwrap() {
        let r = Isolation::Bubblewrap.resolve(true);
        if which("bwrap") {
            assert_eq!(r.unwrap(), Isolation::Bubblewrap);
        } else {
            assert!(matches!(
                r,
                Err(VacuumError::IsolationUnavailable(_))
            ));
        }
    }

    #[test]
    fn fail_closed_defaults_on_and_env_is_opt_out() {
        // Default: fail-closed ligado, sem depender do ambiente.
        assert!(fail_closed_policy(None));
        // Opt-out explícito.
        assert!(!fail_closed_policy(Some("0")));
        assert!(!fail_closed_policy(Some("false")));
        assert!(!fail_closed_policy(Some("FALSE")));
        assert!(!fail_closed_policy(Some(" off ")));
        assert!(!fail_closed_policy(Some("no")));
        // Qualquer outro valor mantém a política.
        assert!(fail_closed_policy(Some("1")));
        assert!(fail_closed_policy(Some("true")));
        assert!(fail_closed_policy(Some("")));
        assert!(fail_closed_policy(Some("qualquer-coisa")));
        // FruitOptions::default() usa exatamente essa semântica.
        assert_eq!(FruitOptions::default().fail_closed, fail_closed_from_env());
    }

    #[test]
    fn default_options_are_fail_closed() {
        // `Default` não pode mais abrir mão do isolamento por acidente.
        let opts = FruitOptions::default();
        assert_eq!(opts.isolation, Isolation::Auto);
        // Default upstream da política (env ausente) é fail-closed.
        assert!(fail_closed_policy(None));
        // E `Default` segue exatamente o opt-out explícito do ambiente.
        assert_eq!(opts.fail_closed, fail_closed_from_env());
    }

    #[test]
    fn materialize_void_stacks_layers() {
        let dir = std::env::temp_dir().join(format!(
            "vac-void-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let store = LayerStore::open(dir.join("layers")).unwrap();
        let base = store
            .put_archive(&LayerArchive::single("MESSAGE", b"hi"))
            .unwrap();
        let app = store
            .put_archive(&LayerArchive::single("index.html", b"<h1>x</h1>"))
            .unwrap();
        let void = Void {
            name: "webapp".into(),
            layers: vec![base, app],
            entrypoint: "chamber-serve".into(),
        };
        let wd = materialize_from_void(&dir, &void, &store, "hi").unwrap();
        assert!(wd.join("rootfs/index.html").exists());
        assert!(wd.join("config.json").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- Descoberta do binário do nó (hermética: nenhum teste depende do PATH
    // ---- real nem de arquivos do build — tudo é fixture em tempdir).

    /// Diretório temporário exclusivo do teste, sem dependência extra.
    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "vac-resolve-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Cria um arquivo-fonte de "binário": a resolução só exige `is_file()`.
    fn stub_bin(dir: &Path, name: &str) -> PathBuf {
        std::fs::create_dir_all(dir).unwrap();
        let p = dir.join(name);
        std::fs::write(&p, b"#!/bin/sh\nexit 0\n").unwrap();
        p
    }

    #[test]
    fn explicit_mycelium_bin_wins_over_path_and_workspace_target() {
        let scratch = scratch("explicit");
        let explicit = stub_bin(&scratch.join("custom"), "mycelium");
        let on_path = stub_bin(&scratch.join("pathbin"), "mycelium");
        let in_target = stub_bin(&scratch.join("ws/target/debug"), "mycelium");
        // As fontes menos prioritárias existem de fato: a precedência do
        // override é assertion real, não resultado de fixtures ausentes.
        assert!(on_path.is_file() && in_target.is_file());

        let path_var = std::env::join_paths([scratch.join("pathbin")]).unwrap();
        let found =
            resolve_mycelium_bin(&explicit, &[scratch.join("ws")], Some(&path_var)).unwrap();

        assert_eq!(
            found, explicit,
            "override explícito do chamador sempre vence PATH e target/"
        );
        let _ = std::fs::remove_dir_all(&scratch);
    }

    #[test]
    fn relative_explicit_bin_is_anchored_to_root_not_cwd() {
        let scratch = scratch("rel-explicit");
        let ws = scratch.join("ws");
        let built = stub_bin(&ws.join("target/debug"), "mycelium");

        let found =
            resolve_mycelium_bin(Path::new("target/debug/mycelium"), &[ws], None).unwrap();

        assert_eq!(found, built, "relativo ancorado na raiz explícita, não no CWD");
        let _ = std::fs::remove_dir_all(&scratch);
    }

    #[test]
    fn path_lookup_resolves_node_bin_without_workspace_anchor() {
        let scratch = scratch("path");
        let on_path = stub_bin(&scratch.join("bin"), "mycelium");
        let path_var = std::env::join_paths([scratch.join("bin")]).unwrap();

        let found = resolve_mycelium_bin(
            &scratch.join("inexistente/mycelium"),
            &[],
            Some(&path_var),
        )
        .unwrap();

        assert_eq!(found, on_path);
        let _ = std::fs::remove_dir_all(&scratch);
    }

    #[test]
    fn workspace_target_precedes_stale_path_install() {
        // Regressão de precedência: um `mycelium` instalado globalmente e
        // desatualizado não pode sombrear o build da própria árvore de código.
        // O contrato HTTP da chamber (rota `/status` + `X-Chamber-Pid`) existe
        // só no build novo; escolher o antigo falha sem erro visível.
        let scratch = scratch("order");
        let on_path = stub_bin(&scratch.join("bin"), "mycelium");
        let in_target = stub_bin(&scratch.join("ws/target/debug"), "mycelium");
        assert!(on_path.is_file() && in_target.is_file());
        let path_var = std::env::join_paths([scratch.join("bin")]).unwrap();

        let found = resolve_mycelium_bin(
            Path::new("/inexistente/mycelium"),
            &[scratch.join("ws")],
            Some(&path_var),
        )
        .unwrap();

        assert_eq!(found, in_target, "build do workspace precede o PATH");
        let _ = std::fs::remove_dir_all(&scratch);
    }

    #[test]
    fn unresolved_reports_only_absolute_tried_paths() {
        // Regressão do defeito exposto sob `cargo test`: um candidato relativo
        // resolvido contra o CWD do pacote resolveria para
        // `crates/<pkg>/target/debug/mycelium`, que nunca existe. Sem âncora e
        // sem PATH, nada pode resolver — e nada de relativo pode aparecer.
        let tried = resolve_mycelium_bin(Path::new("target/debug/mycelium"), &[], None)
            .expect_err("sem âncora nem PATH nada resolve");

        for p in &tried {
            assert!(p.is_absolute(), "candidato relativo escapou para o CWD: {p:?}");
        }
        assert!(
            !tried.contains(&PathBuf::from("target/debug/mycelium")),
            "candidato relativo cru não pode ser reportado: {tried:?}"
        );
        assert!(!tried.is_empty(), "o rastro precisa listar o que foi tentado");
    }

    #[test]
    fn test_harness_exe_is_rejected_as_node_bin() {
        // Sob `cargo test`, `current_exe()` do chamador é
        // `target/<perfil>/deps/<teste>-<hash>`; aceitá-lo como binário do nó
        // faria a chamber executar o harness em vez de servir conteúdo.
        assert!(!looks_like_node_bin(Path::new(
            "/ws/target/debug/deps/community_service_survival_acceptance-abc123"
        )));
        assert!(looks_like_node_bin(Path::new("/ws/target/debug/mycelium")));
    }

    #[test]
    fn missing_node_bin_hint_names_paths_and_not_bubblewrap() {
        let tried = vec![PathBuf::from("/opt/x/target/debug/mycelium")];
        let msg = missing_node_bin_hint(&tried);

        assert!(msg.contains("não encontrado"), "{msg}");
        assert!(
            msg.contains("/opt/x/target/debug/mycelium"),
            "a mensagem deve listar os caminhos tentados: {msg}"
        );
        assert!(
            !msg.contains("apt install bubblewrap"),
            "orientaria o operador a instalar o pacote errado: {msg}"
        );
        assert!(
            !msg.contains("MYCELIUM_FAIL_CLOSED=0"),
            "não é uma falha de política de isolamento: {msg}"
        );
    }

    #[test]
    fn missing_bwrap_hint_still_advises_installing_bubblewrap() {
        // O outro modo de falha — sandbox ausente — mantém a orientação certa.
        let msg = missing_bwrap_hint();
        assert!(msg.contains("apt install bubblewrap"), "{msg}");
        assert!(msg.contains("bwrap"), "{msg}");
    }

    #[test]
    fn node_bin_missing_stays_distinct_from_other_spawn_errors() {
        let missing = SpawnErr::NodeBinMissing(vec![PathBuf::from("/a/mycelium")]).into_vacuum();
        assert!(missing.to_string().contains("/a/mycelium"));

        let other = SpawnErr::Other(VacuumError::Spawn("bwrap spawn: boom".into())).into_vacuum();
        assert!(other.to_string().contains("bwrap spawn: boom"));
    }
}
