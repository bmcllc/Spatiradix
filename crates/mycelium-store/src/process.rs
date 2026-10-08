//! # Process Manager — execução supervisionada de emuladores
//!
//! Gerencia processos de emuladores (RetroArch, MAME, QEMU) lançados pelo
//! launcher: captura stdout/stderr em buffer, aceita input no stdin (terminal
//! web para QEMU `-nographic`) e permite parar o processo.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Arc, Mutex, TryLockError};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{error, info, warn};

/// Teto de bytes aceites por request de input. Acima disto o cliente não
/// paginou, e num pipe cujo leitor parou a escrita passaria a ser um bloqueio
/// indefinido. Mesmo valor do chunk lido por `pump`.
const MAX_INPUT_BYTES: usize = 8 * 1024;

/// Um processo de emulador supervisionado.
pub struct ManagedProcess {
    pub id: u64,
    pub pid: u32,
    pub spore_id: String,
    pub engine: String,
    pub label: String,
    pub status: String,
    pub started_at: u64,
    pub exit_code: Option<i32>,
    child: Option<Child>,
    // O stdin tem mutex PRÓPRIO: a escrita num pipe de filho serializa no
    // PIPE, não na tabela global de processos. Sem isto, um `write_all`
    // travado seguraria a tabela e ninguém alcançaria `child.kill()`, que é a
    // única forma de desfazer essa escrita — deadlock permanente da API.
    stdin: Arc<Mutex<Option<ChildStdin>>>,
    buffer: Arc<Mutex<Vec<u8>>>,
    consumed: usize,
}

/// Processo já executado (`fork`/`exec` feito, threads de `pump` a correr) mas
/// ainda não inserido na tabela. Produzido FORA do bloqueio da tabela de
/// propósito: `ProcessManager::build` é deliberadamente bloqueante.
pub struct PreparedProcess {
    pub pid: u32,
    pub child: Child,
    pub stdin: Arc<Mutex<Option<ChildStdin>>>,
    pub buffer: Arc<Mutex<Vec<u8>>>,
}

impl ManagedProcess {
    /// Bytes novos de output desde a última consulta.
    pub fn drain(&mut self) -> Vec<u8> {
        // Tolerante a `Poison`: um panic nas threads de `pump` não pode tornar a
        // leitura de output permanentemente indisponível. O lado escritor
        // (`pump`) recupera do mesmo modo — se só este lado engolisse o erro, o
        // buffer ficaria congelado no instante do `Poison` sem nenhum sinal.
        let buf = self.buffer.lock().unwrap_or_else(|e| e.into_inner());
        if self.consumed > buf.len() {
            self.consumed = 0;
        }
        let out = buf[self.consumed..].to_vec();
        self.consumed = buf.len();
        out
    }

    /// Envia bytes para o stdin do processo (terminal).
    pub fn send_input(&mut self, bytes: &[u8]) -> Result<(), String> {
        let pipe = self.stdin.clone();
        Self::write_stdin(&pipe, bytes)
    }

    /// Handle clonável do pipe de stdin. Extraído sob o guard da tabela, o
    /// caller DROPA esse guard e só depois chama [`Self::write_stdin`].
    pub fn stdin_pipe(&self) -> Arc<Mutex<Option<ChildStdin>>> {
        self.stdin.clone()
    }

    /// Escreve no stdin do filho a partir de um handle já extraído da tabela.
    /// Serializa no PIPE, nunca na tabela global de processos.
    pub fn write_stdin(pipe: &Arc<Mutex<Option<ChildStdin>>>, bytes: &[u8]) -> Result<(), String> {
        if bytes.len() > MAX_INPUT_BYTES {
            return Err(format!(
                "input acima do limite de {MAX_INPUT_BYTES} bytes ({} recebidos)",
                bytes.len()
            ));
        }
        let mut slot = pipe.lock().unwrap_or_else(|e| e.into_inner());
        let stdin = slot.as_mut().ok_or("stdin indisponível".to_string())?;
        stdin
            .write_all(bytes)
            .map_err(|e| format!("escrever no stdin: {e}"))
    }

    /// Solta o pipe de stdin SEM bloquear. Chamado sempre sob o guard da tabela,
    /// onde esperar por uma escrita em voo reintroduziria o deadlock que o
    /// mutex do pipe existe para evitar: quem está a escrever é desfazido pelo
    /// `child.kill()` de `stop`, que fecha a ponta de leitura e faz a escrita
    /// terminar com `EPIPE`.
    ///
    /// Recebe o campo, não `&self`: os callers já têm `self.child` emprestado
    /// e um `&self` inteiro colidiria com esse empréstimo.
    fn release_stdin(pipe: &Arc<Mutex<Option<ChildStdin>>>) {
        // `try_lock()` devolve `Result<MutexGuard, TryLockError>`, e o `guard`
        // está dentro do `Ok` — o `Err` é um ENUM (`WouldBlock` |
        // `Poisoned(PoisonError<..>)`), não um `PoisonError`. É o `PoisonError`
        // interno que tem o `into_inner()` que devolve o guard.
        match pipe.try_lock() {
            Ok(mut slot) => {
                slot.take();
            }
            Err(TryLockError::WouldBlock) => {
                // Não espera, não gira: alguém está a escrever neste pipe AGORA.
                // A escrita em voo é desfeita pelo `child.kill()` de `stop`, que
                // fecha a ponta de leitura e faz a escrita terminar com `EPIPE`;
                // o `ChildStdin` cai com o guard de quem escreve. Esperar aqui
                // sob o guard da tabela reintroduzia exatamente o deadlock que o
                // mutex PRÓPRIO do pipe existe para impedir. O `Option` fica
                // como está e o filho já está a morrer — não há o que libertar.
            }
            Err(TryLockError::Poisoned(poisoned)) => {
                // Um pânico dentro de quem segura o pipe não pode deixar o
                // `ChildStdin` permanentemente preso: recupera-se o guard e
                // larga-se a ponta de escrita, como no ramo `Ok`.
                let mut slot = poisoned.into_inner();
                slot.take();
            }
        }
    }

    /// Finaliza um processo já detached: `kill` + `wait` são syscalls
    /// bloqueantes e devem correr FORA do bloqueio da tabela de processos.
    pub fn finish_stop(&mut self, child: Option<Child>) {
        if let Some(mut child) = child {
            let _ = child.kill();
            let _ = child.wait();
            self.exit_code = Some(0);
            self.status = "stopped".to_string();
        }
    }

    pub fn is_running(&mut self) -> bool {
        match self.child.as_mut() {
            Some(child) => match child.try_wait() {
                Ok(Some(status)) => {
                    self.exit_code = status.code();
                    self.status = if self.exit_code == Some(0) {
                        "exited".to_string()
                    } else {
                        "errored".to_string()
                    };
                    ManagedProcess::release_stdin(&self.stdin);
                    false
                }
                Ok(None) => true,
                Err(_) => true,
            },
            None => false,
        }
    }
}

/// Gestor global de processos do launcher.
#[derive(Default)]
pub struct ProcessManager {
    pub processes: HashMap<u64, ManagedProcess>,
    next_id: u64,
}

impl ProcessManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Executa `fork`/`exec` e arranca as threads de captura de output.
    ///
    /// Bloqueante por natureza (spawn + 2× `thread::spawn`) e deliberadamente
    /// cego à tabela: o caller deve invocá-lo SEM o guard de `ProcessManager`,
    /// e só depois inserir o resultado com [`Self::attach`].
    pub fn build(
        program: &str,
        args: &[String],
        cwd: Option<PathBuf>,
    ) -> Result<PreparedProcess, String> {
        let mut cmd = Command::new(program);
        cmd.args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(dir) = cwd {
            cmd.current_dir(dir);
        }
        let mut child = cmd.spawn().map_err(|e| format!("spawn {program}: {e}"))?;

        let buffer = Arc::new(Mutex::new(Vec::new()));
        let pid = child.id();

        let stdin = Arc::new(Mutex::new(child.stdin.take()));
        let stdout = child.stdout.take().ok_or("sem stdout")?;
        let stderr = child.stderr.take().ok_or("sem stderr")?;
        let buf_out = buffer.clone();
        std::thread::spawn(move || pump(stdout, buf_out, "stdout"));
        let buf_err = buffer.clone();
        std::thread::spawn(move || pump(stderr, buf_err, "stderr"));

        Ok(PreparedProcess {
            pid,
            child,
            stdin,
            buffer,
        })
    }

    /// Insere um processo já preparado e devolve o id atribuído. Rápido: só
    /// mexe no mapa, portanto seguro com o guard da tabela em mãos.
    pub fn attach(
        &mut self,
        prepared: PreparedProcess,
        spore_id: String,
        engine: String,
        label: String,
    ) -> u64 {
        let started_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let id = self.next_id;
        self.next_id += 1;

        let PreparedProcess {
            pid,
            child,
            stdin,
            buffer,
        } = prepared;

        self.processes.insert(
            id,
            ManagedProcess {
                id,
                pid,
                spore_id,
                engine: engine.clone(),
                label,
                status: "running".to_string(),
                started_at,
                exit_code: None,
                child: Some(child),
                stdin,
                buffer,
                consumed: 0,
            },
        );
        info!(id, pid, engine = %engine, "launcher: processo iniciado");
        id
    }

    /// Lança um emulador supervisionado e devolve o id.
    pub fn spawn(
        &mut self,
        program: &str,
        args: &[String],
        cwd: Option<PathBuf>,
        spore_id: String,
        engine: String,
        label: String,
    ) -> Result<u64, String> {
        let prepared = Self::build(program, args, cwd)?;
        Ok(self.attach(prepared, spore_id, engine, label))
    }

    pub fn get_mut(&mut self, id: u64) -> Option<&mut ManagedProcess> {
        self.processes.get_mut(&id)
    }

    /// Separa o processo da tabela e devolve o `Child` vivo (se o houver) para
    /// o caller finalizar com [`ManagedProcess::finish_stop`].
    ///
    /// É a metade NÃO bloqueante de [`Self::stop`]: `kill`/`wait` ficam de fora
    /// para não-meter um `waitpid` dentro do bloqueio da tabela.
    pub fn detach(&mut self, id: u64) -> Option<(ManagedProcess, Option<Child>)> {
        let mut p = self.processes.remove(&id)?;
        ManagedProcess::release_stdin(&p.stdin);
        let child = p.child.take();
        info!(id, "launcher: processo retirado da tabela");
        Some((p, child))
    }

    /// Mata o processo (SIGTERM → SIGKILL) e remove-o da tabela.
    pub fn stop(&mut self, id: u64) -> Option<ManagedProcess> {
        let (mut p, child) = self.detach(id)?;
        p.finish_stop(child);
        info!(id, "launcher: processo parado");
        Some(p)
    }

    /// Recolhe processos que já saíram (prune) e devolve snapshot para a UI.
    pub fn snapshot(&mut self) -> Vec<serde_json::Value> {
        let mut out = Vec::new();
        let mut dead = Vec::new();
        for (id, p) in self.processes.iter_mut() {
            p.is_running();
            out.push(serde_json::json!({
                "id": p.id,
                "pid": p.pid,
                "spore_id": p.spore_id,
                "engine": p.engine,
                "label": p.label,
                "status": p.status,
                "started_at": p.started_at,
                "exit_code": p.exit_code,
            }));
            if p.status != "running" {
                dead.push(*id);
            }
        }
        for id in dead {
            if let Some(p) = self.processes.remove(&id) {
                warn!(id, status = p.status, "launcher: processo removido");
            }
        }
        out
    }
}

/// Lê um pipe até EOF e acumula no buffer partilhado.
fn pump<R: Read>(mut reader: R, buffer: Arc<Mutex<Vec<u8>>>, tag: &'static str) {
    let mut chunk = [0u8; 8192];
    // O `Poison` é recuperado (como no leitor `drain`) e sinalizado UMA vez por
    // thread: recuperar é obrigatório, senão este lado descartaria chunks para
    // sempre e congelaria o output sem rasto; repetir o aviso a cada chunk
    // transformaria um evento raro em spam.
    let mut warned_poison = false;
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                let mut buf = match buffer.lock() {
                    Ok(buf) => buf,
                    Err(poisoned) => {
                        if !warned_poison {
                            warn!(tag, "launcher: buffer de output envenenado, recuperando");
                            warned_poison = true;
                        }
                        poisoned.into_inner()
                    }
                };
                buf.extend_from_slice(&chunk[..n]);
            }
            Err(e) => {
                error!(tag, "launcher: erro a ler pipe: {e}");
                break;
            }
        }
    }
}

// NOTA: `ManagedProcess.stdin` guarda o `ChildStdin` do child atrás do seu
// próprio `Mutex`, para que a escrita no pipe nunca exija o bloqueio da tabela
// global de processos.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spawn_capture_and_drain() {
        let mut mgr = ProcessManager::new();
        let id = mgr
            .spawn(
                "sh",
                &["-c".to_string(), "echo hello-from-launcher; sleep 0.2; echo done".to_string()],
                None,
                "test".into(),
                "shell".into(),
                "teste".into(),
            )
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(600));
        let p = mgr.get_mut(id).unwrap();
        let out = String::from_utf8_lossy(&p.drain()).to_string();
        assert!(out.contains("hello-from-launcher"), "output: {out}");
        assert!(out.contains("done"), "output: {out}");
        assert!(!p.is_running());
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    #[test]
    fn stop_kills_process() {
        let mut mgr = ProcessManager::new();
        let id = mgr
            .spawn(
                "sh",
                &["-c".to_string(), "sleep 30".to_string()],
                None,
                "test".into(),
                "shell".into(),
                "teste".into(),
            )
            .unwrap();
        assert!(mgr.stop(id).is_some());
        assert!(!mgr.processes.contains_key(&id));
    }
}
