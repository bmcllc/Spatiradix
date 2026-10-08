//! # Mycelium Store — Decentralized Retro Software & Hardware Launcher Store
//!
//! A Mycelium Store é uma App Store / Steam descentralizada para software antigo, jogos retro e
//! plataformas de hardware legado, construída sobre o ecossistema P2P Mycelium Network.
//!
//! Recursos:
//! - Catálogo descentralizado com SporeBank (IPFS / DHT / Nostr)
//! - Motor de emulação dinâmica: RetroArch (Libretro), MAME, QEMU (x86, PPC, SPARC)
//! - WebAssembly embutido (RetroArch/EmulatorJS) para execução em navegadores
//! - Cloud Gaming P2P e sandboxing de segurança com Vacuum (bwrap)

pub mod catalog;
pub mod process;
pub mod qemu_builder;
pub mod runner;
pub mod spore;

pub use catalog::{CatalogError, StoreCatalog};
pub use process::{ManagedProcess, ProcessManager};
pub use qemu_builder::QemuBuilder;
pub use runner::{EmulatorRunner, SystemCapabilities};
pub use spore::{ExecutionEngineType, ExecutionMatrix, QemuConfig, SoftwareSpore, SporeLicense, TargetPlatform};

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use axum::extract::Path as AxumPath;
use serde_json::json;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use tracing::error;

/// Estado compartilhado da store HTTP.
///
/// Tolerância a `Poison` — escopo: VIVACIDADE. Garantia de correção — escopo:
/// ESTE ARQUIVO.
///
/// `catalog` e `processes` são `std::sync::Mutex`. Sobre `processes`, este
/// arquivo usa `lock().unwrap_or_else(|e| e.into_inner())` para que um panic em
/// uma requisição não tijolo os *outros* handlers deste arquivo. Sobre o
/// catálogo, NADA é recuperado: `catalog_locked` faz `match` ao resultado do
/// `lock()` e recusa um mutex envenenado, um `catalog.json` ilegível, ou um
/// índice em memória em desacordo com o disco (`StoreCatalog::validate` →
/// `CatalogError::Poisoned`). A razão de o catálogo ser diferente: o seu índice
/// é fonte de verdade para decidir o que este host executa, ao passo que a
/// tabela de processos só precisa de sobreviver ao panic seguinte.
///
/// Limites conhecidos desta garantia:
/// - O MESMO `catalog` é partilhado com `mycelium-node/src/organism.rs`
///   (StoreList/StoreLaunch/StorePublish). Lá, o tratamento de `Poison` e a
///   chamada a `validate()` são os mesmos (o helper `catalog_locked` do lado do
///   daemon), de modo que as duas pontas respondem o mesmo ao mesmo estado:
///   nenhum dos dois lados consome um índice que o outro recusa.
/// - O que `validate()` garante é ACORDO ENTRE MEMÓRIA E DISCO, não
///   verdade do registro: ela relê `catalog.json` e compara. Não repara, e
///   nunca substitui `self.index` pela cópia relida — essa cópia passaria a
///   validar-se a si própria no teste seguinte, e a falha original desapareceria
///   sem registo.
/// - `validate()` é O(n) em esporos e relê `catalog.json` do disco em TODA
///   aquisição do guard; `launch_spore_handler` adquire duas vezes (registro e
///   `resolve_game_path`). Ver a nota de custo em `catalog_locked`.
/// - `resolve_game_path` devolve `Option<PathBuf>` e não pode propagar
///   `CatalogError`: num catálogo recusado devolve `None`, indistinguível de
///   "binário não encontrado" para o chamador.
/// - Nenhum guarda é mantido através de `.await` (nenhum handler deste arquivo
///   faz `await`), mas todo syscall bloqueante ocorre FORA do guarda que
///   protege a sua tabela: a escrita no stdin de um filho, o `kill`/`wait`, o
///   `spawn` do emulador e a escrita do binário recalled por `fs::write`.
///
/// FAIL-CLOSED (aplicado): todo acesso ao `catalog` neste arquivo passa por
/// `catalog_locked`. `launch_spore_handler` — que decide caminho de executável
/// e flags de emulador a partir do registro — converte a recusa num erro HTTP
/// 500; nunca consome um registro recuperado.
#[derive(Clone)]
pub struct StoreAppState {
    pub catalog: Arc<Mutex<StoreCatalog>>,
    pub processes: Arc<Mutex<ProcessManager>>,
    pub home: PathBuf,
    pub control_token: Option<String>,
}

/// Resposta devolvida ao cliente quando o catálogo é recusado.
///
/// Não transporta caminho, ID de spore nem detalhe de parse: quem diagnostica é
/// o `error!` no servidor, não o cliente. Diz o suficiente para o operador
/// perceber que o problema é o catálogo e não o pedido.
const CATALOG_INCONSISTENT: &str = "catálogo inconsistente: estado envenenado, operação recusada";

/// Adquire o catálogo mantendo a VIVACIDADE do `Poison`, mas sem aceitar um
/// valor não verificado.
///
/// Um mutex envenenado é recusado: o `Poison` significa que uma requisição
/// anterior entrou em pânico a meio de uma escrita, e a parte que não roda
/// depois desse ponto é desconhecida. Deixar passar daria ao próximo handler um
/// índice que ninguém validou. Um índice que não bate com `catalog.json` é
/// recusado pelo mesmo motivo — e pela mesma razão que `IndexCorrupt` existe
/// para não ser absorvido em silêncio.
///
/// Custo: `validate()` relê e parseia `catalog.json` a CADA aquisição. Com o
/// índice atual (uma dúzia de esporos) isso é irrelevante, mas é O(n) em
/// esporos e uma leitura de disco por pedido de leitura. Optimização
/// possível — flag `dirty`/`validated` limpo por `insert_spore`/`publish_spore`
/// — fica por fazer de propósito: um erro aqui deixa de ser fail-closed.
fn catalog_locked(state: &StoreAppState) -> Result<MutexGuard<'_, StoreCatalog>, CatalogError> {
    // O `Poison` é uma propriedade do RESULTADO do `lock()`, não do guard: o
    // `MutexGuard` devolvido por um `Ok` nunca o transporta, e por isso não há
    // `is_poisoned()` a consultar. O `unwrap_or_else(|e| e.into_inner())`
    // anterior RECUPERAVA o guard e depois não tinha como recusar — o índice
    // recuperado passava adiante sem ninguém ter observado o `Poison`. Aqui o
    // `match` é sobre o `lock()`: `Err` significa que uma requisição anterior
    // entrou em pânico a meio de uma escrita e a parte do estado que não voltou
    // a correr é desconhecida, logo não passa.
    let guard = match state.catalog.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            error!("[Mycelium Store] catalog_locked: mutex do catálogo envenenado: {poisoned}");
            return Err(CatalogError::Poisoned("mutex do catálogo envenenado"));
        }
    };
    guard.validate()?;
    Ok(guard)
}

/// Verifica se a requisição possui autorização válida quando um token de controle é exigido.
fn is_authorized(headers: &axum::http::HeaderMap, expected: Option<&str>) -> bool {
    let expected = match expected {
        Some(t) if !t.trim().is_empty() => t.trim(),
        _ => return true,
    };
    if let Some(val) = headers.get("x-control-token").and_then(|v| v.to_str().ok()) {
        if val.trim() == expected {
            return true;
        }
    }
    if let Some(val) = headers.get(axum::http::header::AUTHORIZATION).and_then(|v| v.to_str().ok()) {
        if let Some(token) = val.strip_prefix("Bearer ") {
            if token.trim() == expected {
                return true;
            }
        }
    }
    false
}

/// Cria o router HTTP Axum para a Mycelium Store integrar ao Singularity Event Horizon (sem token exigido).
pub fn create_store_router(home: impl AsRef<Path>, catalog: Arc<Mutex<StoreCatalog>>) -> Router {
    create_store_router_with_auth(home, catalog, None)
}

/// Cria o router HTTP Axum para a Mycelium Store com token de controle opcional para proteger execução de processos.
pub fn create_store_router_with_auth(
    home: impl AsRef<Path>,
    catalog: Arc<Mutex<StoreCatalog>>,
    control_token: Option<String>,
) -> Router {
    let state = StoreAppState {
        catalog,
        processes: Arc::new(Mutex::new(ProcessManager::new())),
        home: home.as_ref().to_path_buf(),
        control_token,
    };

    Router::new()
        .route("/api/store/capabilities", get(get_capabilities_handler))
        .route("/api/store/spores", get(list_spores_handler))
        .route("/api/store/spores/{id}", get(get_spore_handler))
        .route("/api/store/spores/{id}/launch", post(launch_spore_handler))
        .route("/api/store/covers/{id}", get(get_cover_handler))
        .route("/api/store/processes", get(list_processes_handler))
        .route("/api/store/processes/{id}/output", get(process_output_handler))
        .route("/api/store/processes/{id}/input", post(process_input_handler))
        .route("/api/store/processes/{id}/stop", post(process_stop_handler))
        .with_state(state)
}

/// Cria o router que serve a UI estática da store (index.html e game.html)
pub fn create_store_ui_router(home: impl AsRef<Path>) -> Router {
    let home = home.as_ref().to_path_buf();
    let home_for_ui = home.clone();
    Router::new()
        .route("/", get(move || serve_store_ui(home.clone())))
        .route("/web/{id}", get(move |AxumPath(id): AxumPath<String>| serve_game_page(home_for_ui.clone(), id)))
}

async fn serve_store_ui(home: PathBuf) -> impl IntoResponse {
    let default_ui = include_str!("../../../deploy/store-ui/index.html");
    let ui_path = home.join("store-ui").join("index.html");
    let html = std::fs::read_to_string(&ui_path).unwrap_or_else(|_| default_ui.to_string());
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
}

async fn serve_game_page(home: PathBuf, id: String) -> impl IntoResponse {
    let default_ui = include_str!("../../../deploy/store-ui/game.html");
    let ui_path = home.join("store-ui").join("game.html");
    let mut html = std::fs::read_to_string(&ui_path).unwrap_or_else(|_| default_ui.to_string());
    html = html.replace("__SPORE_ID__", &id);
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
}

async fn get_capabilities_handler() -> impl IntoResponse {
    let caps = EmulatorRunner::detect_capabilities();
    (StatusCode::OK, Json(caps))
}

/// Lista apenas spores com licença de distribuição pública.
/// Spores `proprietary` (BYOR) não aparecem na loja pública.
async fn list_spores_handler(State(state): State<StoreAppState>) -> impl IntoResponse {
    let catalog = match catalog_locked(&state) {
        Ok(catalog) => catalog,
        Err(e) => {
            error!(
                "[Mycelium Store] list_spores_handler: catálogo recusado (campo `catalog`): {e}"
            );
            return catalog_json_err();
        }
    };
    let spores: Vec<SoftwareSpore> = catalog.list_public_spores().into_iter().cloned().collect();
    // `impl IntoResponse` fixa UM tipo concreto de retorno por função, e o
    // `catalog_locked` acima devolve `catalog_json_err()` — `Json<Value>`. O
    // corpo de sucesso tem de produzir o MESMO tipo: `Json(spores)` seria
    // `Json<Vec<SoftwareSpore>>` e não compila contra o ramo de erro. Reembalado
    // por `json!`, o corpo continua a ser o array de esporos — a resposta
    // (`application/json`, array) não muda, e é agora literalmente a mesma
    // `Json<Value>` que `get_spore_handler` e `catalog_json_err` já devolviam.
    (StatusCode::OK, Json(json!(spores)))
}

async fn get_spore_handler(
    State(state): State<StoreAppState>,
    AxumPath(id): AxumPath<String>,
) -> impl IntoResponse {
    let catalog = match catalog_locked(&state) {
        Ok(catalog) => catalog,
        Err(e) => {
            error!("[Mycelium Store] get_spore_handler: catálogo recusado (campo `catalog`): {e}");
            return catalog_json_err();
        }
    };
    if let Some(spore) = catalog.get_spore(&id) {
        (StatusCode::OK, Json(json!(spore)))
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Spore não encontrado"})),
        )
    }
}

async fn launch_spore_handler(
    State(state): State<StoreAppState>,
    headers: axum::http::HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> impl IntoResponse {
    if !is_authorized(&headers, state.control_token.as_deref()) {
        return (
            StatusCode::UNAUTHORIZED,
            [(axum::http::header::CONTENT_TYPE, "application/json; charset=utf-8")],
            json!({"error": "autorização necessária para controle e execução de processos"}).to_string(),
        );
    }
    // FAIL-CLOSED: a partir daqui o registro decide caminho de executável e
    // flags de emulador. Um índice recusado por `catalog_locked` nunca chega a
    // ser clonado — sai daqui como 500, não como um registro recuperado.
    let spore = {
        let catalog = match catalog_locked(&state) {
            Ok(catalog) => catalog,
            Err(e) => {
                error!("[Mycelium Store] launch_spore_handler: catálogo recusado (campo `catalog`): {e}");
                return process_json_err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    CATALOG_INCONSISTENT.into(),
                );
            }
        };
        match catalog.get_spore(&id) {
            Some(s) => s.clone(),
            None => {
                return (
                    StatusCode::NOT_FOUND,
                    [(axum::http::header::CONTENT_TYPE, "application/json; charset=utf-8")],
                    json!({"error": format!("spore '{id}' não encontrado")}).to_string(),
                );
            }
        }
    };

    let caps = EmulatorRunner::detect_capabilities();
    let engine = EmulatorRunner::resolve_best_engine(&spore, &caps, None);

    let game_path = resolve_game_path(&state, &spore);
    let terminal = engine == ExecutionEngineType::QEMU;

    match EmulatorRunner::build_launch_command(&spore, game_path.as_deref(), &engine, false, terminal)
    {
        Ok((program, args, cwd)) => {
            // `fork`/`exec` e os `thread::spawn` de captura correm FORA do
            // bloqueio de `processes`: um spawn lento (emulador a carregar
            // binário) seguraria a tabela e travaria `list`/`output`/`stop`.
            // Só a inserção final volta a usar o guard, e essa é rápida.
            let prepared = ProcessManager::build(&program, &args, cwd);
            let process_id = {
                let mut processes = state.processes.lock().unwrap_or_else(|e| e.into_inner());
                match prepared {
                    Ok(prepared) => processes.attach(
                        prepared,
                        spore.id.clone(),
                        format!("{engine:?}"),
                        spore.title.clone(),
                    ),
                    Err(e) => {
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            [(axum::http::header::CONTENT_TYPE, "application/json; charset=utf-8")],
                            json!({ "status": "error", "message": e }).to_string(),
                        );
                    }
                }
            };
            let bin = game_path.map(|p| p.to_string_lossy().to_string());
            let mode = if terminal {
                "terminal-web"
            } else {
                "janela-host"
            };
            (
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, "application/json; charset=utf-8")],
                json!({
                    "status": "launched",
                    "spore_id": spore.id,
                    "engine": format!("{engine:?}"),
                    "process_id": process_id,
                    "mode": mode,
                    "binary": bin,
                    "message": format!(
                        "{} iniciado via {} ({})",
                        spore.title,
                        program,
                        mode
                    ),
                })
                .to_string(),
            )
        }
        Err(e) => (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/json; charset=utf-8")],
            json!({
                "status": "prepared",
                "engine": format!("{engine:?}"),
                "message": format!("{} não pôde ser lançado: {e}", spore.title),
            })
            .to_string(),
        ),
    }
}

fn resolve_game_path(state: &StoreAppState, spore: &SoftwareSpore) -> Option<PathBuf> {
    let local = state.home.join("store").join(&spore.main_binary_file);
    if local.exists() {
        return Some(local);
    }
    // Só a leitura do spore print e a cópia do conteúdo acontecem sob o guard.
    // A escrita do binário inteiro — o passo caro, head-of-line para qualquer
    // leitor do catálogo — fica sem nenhum bloqueio da tabela.
    let content = {
        let catalog = match catalog_locked(state) {
            Ok(catalog) => catalog,
            Err(e) => {
                error!(
                    "[Mycelium Store] resolve_game_path: catálogo recusado (campo `catalog`): {e}"
                );
                // `Option<PathBuf>` não transporta `CatalogError`, e `None` é
                // indistinguível de "binário não encontrado" para o chamador.
                // Devolver `None` é ainda assim fail-closed: o `recall` é
                // abortado ANTES de o conteúdo ser copiado para disco e
                // executado. Follow-up recomendado (não aplicado aqui, por
                // mudar a assinatura): `Result<Option<PathBuf>, CatalogError>`.
                return None;
            }
        };
        let plot = catalog.sporebank().recall(&spore.content_id)?;
        let leaf = plot
            .leaves
            .iter()
            .find(|l| l.path == spore.main_binary_file)?;
        leaf.content.clone()
    }; // guard de `catalog` DROPADO aqui
    let ext = spore
        .main_binary_file
        .rsplit('.')
        .next()
        .unwrap_or("bin");
    let tmp = std::env::temp_dir().join(format!("mycelium-{}-{}", spore.id, ext));
    if std::fs::write(&tmp, &content).is_ok() {
        Some(tmp)
    } else {
        None
    }
}

async fn list_processes_handler(State(state): State<StoreAppState>) -> impl IntoResponse {
    let mut processes = state.processes.lock().unwrap_or_else(|e| e.into_inner());
    let snapshot = processes.snapshot();
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json; charset=utf-8")],
        serde_json::to_string(&json!({ "processes": snapshot })).unwrap_or_else(|_| "{}".into()),
    )
}

async fn process_output_handler(
    State(state): State<StoreAppState>,
    AxumPath(id): AxumPath<String>,
) -> impl IntoResponse {
    let id: u64 = match id.parse() {
        Ok(v) => v,
        Err(_) => return process_json_err(StatusCode::BAD_REQUEST, "id de processo inválido".into()),
    };
    let mut processes = state.processes.lock().unwrap_or_else(|e| e.into_inner());
    match processes.get_mut(id) {
        Some(p) => {
            let output = p.drain();
            let status = p.status.clone();
            let output_str = String::from_utf8_lossy(&output).to_string();
            (
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, "application/json; charset=utf-8")],
                json!({ "process_id": id, "status": status, "output": output_str }).to_string(),
            )
        }
        None => process_json_err(StatusCode::NOT_FOUND, format!("processo {id} não encontrado")),
    }
}

async fn process_input_handler(
    State(state): State<StoreAppState>,
    headers: axum::http::HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    if !is_authorized(&headers, state.control_token.as_deref()) {
        return process_json_err(StatusCode::UNAUTHORIZED, "autorização necessária para enviar input".into());
    }
    let id: u64 = match id.parse() {
        Ok(v) => v,
        Err(_) => return process_json_err(StatusCode::BAD_REQUEST, "id de processo inválido".into()),
    };
    let input = body
        .get("input")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let pipe = {
        let mut processes = state.processes.lock().unwrap_or_else(|e| e.into_inner());
        processes.get_mut(id).map(|p| p.stdin_pipe())
    };
    // Guard de `processes` DROPADO aqui. `write_all` num pipe cujo leitor parou
    // é um syscall sem prazo; mantido sob a tabela, `process_stop_handler` nunca
    // alcançaria `child.kill()` — a única forma de desfazer essa escrita — e a
    // API de processos deadlockava na íntegra. O mutex do pipe serializa apenas
    // as escritas concorrentes no MESMO filho.
    match pipe {
        Some(pipe) => match ManagedProcess::write_stdin(&pipe, input.as_bytes()) {
            Ok(()) => (
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, "application/json; charset=utf-8")],
                json!({ "ok": true }).to_string(),
            ),
            Err(e) => process_json_err(StatusCode::INTERNAL_SERVER_ERROR, e),
        },
        None => process_json_err(StatusCode::NOT_FOUND, format!("processo {id} não encontrado")),
    }
}

async fn process_stop_handler(
    State(state): State<StoreAppState>,
    headers: axum::http::HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> impl IntoResponse {
    if !is_authorized(&headers, state.control_token.as_deref()) {
        return process_json_err(StatusCode::UNAUTHORIZED, "autorização necessária para encerrar processo".into());
    }
    let id: u64 = match id.parse() {
        Ok(v) => v,
        Err(_) => return process_json_err(StatusCode::BAD_REQUEST, "id de processo inválido".into()),
    };
    // A entrada sai da tabela sob o guard; `kill`/`wait` (syscalls bloqueantes)
    // ficam de fora dele para não travar `list`/`output`/`input`.
    let detached = {
        let mut processes = state.processes.lock().unwrap_or_else(|e| e.into_inner());
        processes.detach(id)
    };
    // Guard de `processes` DROPADO aqui.
    match detached {
        Some((mut p, child)) => {
            p.finish_stop(child);
            (
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, "application/json; charset=utf-8")],
                json!({ "ok": true, "stopped": p.spore_id }).to_string(),
            )
        }
        None => process_json_err(StatusCode::NOT_FOUND, format!("processo {id} não encontrado")),
    }
}

fn process_json_err(
    status: StatusCode,
    message: String,
) -> (StatusCode, [(axum::http::header::HeaderName, &'static str); 1], String) {
    (
        status,
        [(axum::http::header::CONTENT_TYPE, "application/json; charset=utf-8")],
        json!({ "error": message }).to_string(),
    )
}

/// Equivalente a [`process_json_err`] para os handlers cujo braço de sucesso
/// devolve `(StatusCode, Json<T>)` — `list_spores_handler` e
/// `get_spore_handler`.
///
/// Não é um duplicado por preguiça: `impl IntoResponse` fixa UM tipo concreto
/// de retorno por função, e `process_json_err` devolve
/// `(StatusCode, [(HeaderName, &str); 1], String)`. Um `return
/// process_json_err(...)` dentro de um handler que no sucesso devolve
/// `Json<T>` não compila. Mover o corpo de sucesso para a forma de string
/// resolveria, mas mudaria a resposta desses endpoints — daí a segunda
/// função, em vez de tocar no corpo de sucesso.
fn catalog_json_err() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "error": CATALOG_INCONSISTENT })),
    )
}

async fn get_cover_handler(
    State(state): State<StoreAppState>,
    AxumPath(id): AxumPath<String>,
) -> impl IntoResponse {
    let id = id.strip_suffix(".svg").unwrap_or(&id).to_string();
    let (title, platform) = match catalog_locked(&state) {
        Ok(catalog) => match catalog.get_spore(&id) {
            Some(spore) => (spore.title.clone(), spore.platform.clone()),
            None => (format!("Spore não encontrado: {id}"), spore::TargetPlatform::NativeSystem),
        },
        Err(e) => {
            error!("[Mycelium Store] get_cover_handler: catálogo recusado (campo `catalog`): {e}");
            // Este handler responde SVG com dois cabeçalhos, um tipo concreto
            // diferente do de `process_json_err`; `impl IntoResponse` só admite
            // um, e a forma de sucesso fica intacta. `no-store` impede que um
            // 500 de catálogo seja cacheado como se fosse uma capa.
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                [
                    (
                        axum::http::header::CONTENT_TYPE,
                        "application/json; charset=utf-8",
                    ),
                    (axum::http::header::CACHE_CONTROL, "no-store"),
                ],
                json!({ "error": CATALOG_INCONSISTENT }).to_string(),
            );
        }
    };
    let svg = cover_svg(&title, &platform);
    (
        StatusCode::OK,
        [
            (axum::http::header::CONTENT_TYPE, "image/svg+xml; charset=utf-8"),
            (axum::http::header::CACHE_CONTROL, "public, max-age=86400"),
        ],
        svg,
    )
}

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn platform_gradient(platform: &spore::TargetPlatform) -> (&'static str, &'static str) {
    use spore::TargetPlatform::*;
    match platform {
        MSDOS | Windows95 | Windows98 | WindowsXP => ("#0f2a3d", "#0e7c86"),
        SNES | NES | N64 | GameBoyAdvance => ("#2a0f3d", "#7c2ae8"),
        ArcadeMame | NeoGeo | MegaDrive => ("#0f3d17", "#00b359"),
        PowerPCMac | Amiga | SunOSSPARC => ("#3d240f", "#ff9100"),
        SegaSaturn | Dreamcast | PlayStation1 | PlayStation2 => ("#3d0f24", "#e8478f"),
        NativeSystem => ("#1a2333", "#2d3748"),
    }
}

fn cover_svg(title: &str, platform: &spore::TargetPlatform) -> String {
    let (c1, c2) = platform_gradient(platform);
    let safe = escape_xml(title);
    let line1 = safe.chars().take(22).collect::<String>();
    let line2: String = safe.chars().skip(22).take(22).collect();
    let mut lines = String::new();
    if !line1.is_empty() {
        lines.push_str(&format!(
            r#"<text x="300" y="520" font-family="monospace" font-size="30" font-weight="bold" text-anchor="middle" fill="rgba(255,255,255,0.92)" letter-spacing="2">{line1}</text>"#
        ));
    }
    if !line2.is_empty() {
        lines.push_str(&format!(
            r#"<text x="300" y="560" font-family="monospace" font-size="30" font-weight="bold" text-anchor="middle" fill="rgba(255,255,255,0.92)" letter-spacing="2">{line2}</text>"#
        ));
    }
    format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" width="600" height="800" viewBox="0 0 600 800">
<defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="{c1}"/><stop offset="1" stop-color="{c2}"/></linearGradient></defs>
<rect width="600" height="800" fill="url(#g)"/>
<rect x="24" y="24" width="552" height="752" fill="none" stroke="rgba(255,255,255,0.28)" stroke-width="6" rx="20"/>
<text x="300" y="400" font-size="230" text-anchor="middle">🎮</text>
{lines}
<text x="300" y="640" font-family="monospace" font-size="26" text-anchor="middle" fill="rgba(255,255,255,0.55)" letter-spacing="3">MYCELIUM RETRO STORE</text>
</svg>"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir() -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("mycelium-store-test-{}", nanos));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_store_catalog_creation() {
        let home = tmp_dir();
        let catalog = StoreCatalog::open(&home).unwrap();
        assert!(!catalog.list_spores().is_empty());
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn test_catalog_seed_only_has_redistributable_spores() {
        let home = tmp_dir();
        let catalog = StoreCatalog::open(&home).unwrap();

        // O seed público deve conter apenas conteúdo com licença redistribuível
        // (Shareware/Freeware/OpenSource/PublicDomain). Nenhum spore copyright (BYOR).
        let all = catalog.list_spores();
        assert!(!all.is_empty(), "catálogo seed não pode estar vazio");
        for spore in &all {
            assert!(
                spore.license.is_publicly_redistributable(),
                "spore '{}' ({}) é copyright e não pode estar no seed público",
                spore.id,
                spore.title
            );
        }

        let public = catalog.list_public_spores();
        assert_eq!(public.len(), all.len(), "seed deve ser 100% redistribuível");

        std::fs::remove_dir_all(&home).ok();
    }
}
