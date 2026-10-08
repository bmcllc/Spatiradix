use ed25519_dalek::VerifyingKey;
use mycelium_core::ContentId;
use mycelium_s1::{
    benchmark::{self, BenchmarkConfig, Metering},
    billing::Store,
    economy::EconomyCheckout,
    publication::{self, SiteBundle, SiteManifest, MANIFEST_PATH},
    training::{self, Dataset, TrainingConfig},
    Evaluation, Model, Ticket,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    error::Error,
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpStream},
    path::Path,
    str::FromStr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

type CliResult<T = ()> = Result<T, Box<dyn Error>>;

const HELP: &str = r#"mycelium-s1 — local S1 runtime and Mycelium Economy checkout

  compile INPUT.json OUTPUT.json
  evaluate REQUEST.json
  train DATASET.json CONFIG.json MODEL.json REPORT.json
  fine-tune DATASET.json CONFIG.json INITIAL.json MODEL.json REPORT.json
  benchmark REQUEST.json CONFIG.json REPORT.json
    [--metered TICKET.json KEY_HEX NOW MODEL_ID DEVICE]
  credit S1_STORE RECEIPT STUDIO AMOUNT
  reserve S1_STORE ALLOWANCE.json
  checkout quote NODE_HOME STUDIO ORDER PACK
  checkout confirm NODE_HOME STUDIO ORDER TRANSACTION_HASH
  issue-client-key NODE_HOME STUDIO
  serve NODE_HOME [127.0.0.1:7481]
  prepare-site BUILD_DIR APPLICATION REPOSITORY BRANCH REQUEST.json
    [--entrypoint index.html] [--previous CID] [--message "[public] S1 portal"]
    [--publish NODE_HOME]
  publish NODE_HOME REQUEST.json

NODE_HOME is explicit: S1 data uses NODE_HOME/s1, Economy uses NODE_HOME/economy.
PACK is 100k, 1m, 10m or 100m. Quote never submits a payment; confirm checks
the settled Economy transaction before issuing credits. Credit is an operator tool.
Issue-client-key prints a secret once; store it securely for Bearer authentication.
Serve accepts a loopback address; clients can access it through the local node.
Benchmark uses an in-memory bucket, including warmup calls, and does not persist
consumption. Use a dedicated benchmark ticket. KEY_HEX is the issuer public key;
NOW is a Unix timestamp. TICKET may also be the JSON envelope returned by reserve.
Prepare-site packages only a static build and writes an unauthenticated request.
Publish validates that request and contacts the existing local node (Unix socket,
or loopback TCP), adding MYCELIUM_CONTROL_TOKEN or NODE_HOME/control.token.
The resulting src.mycelium URL needs a Mycelium client. Publication does not
by itself guarantee replication by another peer.
"#;

fn exact(args: &[String], count: usize, usage: &str) -> CliResult {
    if args.len() != count {
        return Err(format!("usage: mycelium-s1 {usage}").into());
    }
    Ok(())
}

fn read_json<T: DeserializeOwned>(path: impl AsRef<Path>) -> CliResult<T> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

fn write_json(path: impl AsRef<Path>, value: &impl Serialize) -> CliResult {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    fs::write(path, bytes)?;
    Ok(())
}

fn print_json(value: &impl Serialize) -> CliResult {
    println!("{}", serde_json::to_string(value)?);
    Ok(())
}

fn benchmark_command(args: &[String]) -> CliResult {
    if args.len() != 3 && !(args.len() == 9 && args[3] == "--metered") {
        return Err("usage: mycelium-s1 benchmark REQUEST CONFIG REPORT [--metered TICKET KEY_HEX NOW MODEL_ID DEVICE]".into());
    }
    let request: Evaluation = read_json(&args[0])?;
    let config: BenchmarkConfig = read_json(&args[1])?;
    let report = if args.len() == 9 {
        let value: Value = read_json(&args[4])?;
        let ticket: Ticket = serde_json::from_value(value.get("ticket").cloned().unwrap_or(value))?;
        let key_bytes: [u8; 32] = hex::decode(&args[5])?
            .try_into()
            .map_err(|_| "issuer public key must have exactly 32 bytes")?;
        let key = VerifyingKey::from_bytes(&key_bytes)?;
        benchmark::run_metered(
            &request.model,
            &request.features,
            &request.allowed,
            &config,
            Metering {
                ticket,
                key: &key,
                now: args[6].parse()?,
                model_id: &args[7],
                device: &args[8],
            },
        )?
    } else {
        benchmark::run(&request.model, &request.features, &request.allowed, &config)?
    };
    write_json(&args[2], &report)?;
    print_json(&report)
}

fn checkout_command(args: &[String]) -> CliResult {
    exact(
        args,
        5,
        "checkout quote|confirm NODE_HOME STUDIO ORDER PACK|TRANSACTION_HASH",
    )?;
    let home = Path::new(&args[1]);
    let checkout = EconomyCheckout::new(home.join("s1"), home.join("economy"));
    match args[0].as_str() {
        "quote" => print_json(&checkout.quote(&args[2], &args[3], &args[4])?),
        "confirm" => print_json(&checkout.confirm(&args[2], &args[3], &args[4])?),
        _ => Err("checkout command must be quote or confirm".into()),
    }
}

fn prepare_site_command(args: &[String]) -> CliResult {
    if args.len() < 5 || !(args.len() - 5).is_multiple_of(2) {
        return Err("usage: mycelium-s1 prepare-site BUILD_DIR APPLICATION REPOSITORY BRANCH REQUEST [--entrypoint PATH] [--previous CID] [--message PUBLIC_MESSAGE] [--publish NODE_HOME]".into());
    }
    let mut entrypoint = "index.html";
    let mut previous = None;
    let mut message = "[public] S1 portal";
    let mut publish_home = None;
    let mut seen = BTreeSet::new();
    for option in args[5..].chunks_exact(2) {
        if !seen.insert(option[0].as_str()) {
            return Err(format!("duplicate option: {}", option[0]).into());
        }
        match option[0].as_str() {
            "--entrypoint" => entrypoint = &option[1],
            "--previous" => previous = Some(ContentId::from_str(&option[1])?),
            "--message" => message = &option[1],
            "--publish" => publish_home = Some(Path::new(&option[1])),
            _ => return Err(format!("unknown option: {}", option[0]).into()),
        }
    }
    let bundle = publication::prepare_site(&args[0], &args[1], entrypoint)?;
    let request = bundle.repo_publish_request(&args[2], &args[3], previous, message)?;
    write_json(&args[4], &request)?;
    if let Some(home) = publish_home {
        print_json(&publish_site(home, request, entrypoint)?)
    } else {
        print_json(&json!({
            "status": "site_prepared", "request_file": args[4],
            "assets": bundle.manifest.files.len(), "entrypoint": entrypoint,
            "published": false,
        }))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublishRequest {
    cmd: String,
    repository: String,
    branch: String,
    expected_previous_cid: Option<String>,
    message: String,
    leaves: Vec<giggs::Leaf>,
}

/// Rebuild the request from a verified bundle. Arbitrary node commands and
/// embedded credentials cannot be forwarded through the site publishing CLI.
fn validated_publish_request(bytes: &[u8]) -> CliResult<(Value, String)> {
    let request: PublishRequest = serde_json::from_slice(bytes)?;
    if request.cmd != "repo_publish" {
        return Err("publish accepts only a repo_publish site request".into());
    }
    let manifest_leaf = request
        .leaves
        .iter()
        .find(|leaf| leaf.path == MANIFEST_PATH)
        .ok_or("site request has no manifest")?;
    let manifest: SiteManifest = serde_json::from_slice(&manifest_leaf.content)?;
    let entrypoint = manifest.entrypoint.clone();
    let bundle = SiteBundle {
        manifest,
        leaves: request.leaves,
    };
    let previous = request
        .expected_previous_cid
        .as_deref()
        .map(ContentId::from_str)
        .transpose()?;
    let value = bundle.repo_publish_request(
        &request.repository,
        &request.branch,
        previous,
        &request.message,
    )?;
    Ok((value, entrypoint))
}

fn read_bounded(path: &Path, limit: usize) -> CliResult<Vec<u8>> {
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err("file exceeds the command's size limit".into());
    }
    Ok(bytes)
}

fn control_token(home: &Path) -> CliResult<Option<String>> {
    if let Ok(value) = std::env::var("MYCELIUM_CONTROL_TOKEN") {
        if !value.trim().is_empty() {
            return Ok(Some(value.trim().to_owned()));
        }
    }
    match read_bounded(&home.join("control.token"), 4096) {
        Ok(bytes) => {
            let value = String::from_utf8(bytes)?;
            Ok((!value.trim().is_empty()).then(|| value.trim().to_owned()))
        }
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

fn exchange_control(mut stream: impl Read + Write, request: &Value) -> CliResult<Value> {
    let mut bytes = serde_json::to_vec(request)?;
    bytes.push(b'\n');
    stream.write_all(&bytes)?;
    stream.flush()?;
    let mut response = Vec::new();
    let limit = 1024 * 1024;
    BufReader::new(stream)
        .take(limit + 1)
        .read_until(b'\n', &mut response)?;
    if response.len() > limit as usize || response.last() != Some(&b'\n') {
        return Err("control response is oversized or incomplete".into());
    }
    Ok(serde_json::from_slice(&response)?)
}

fn call_control(home: &Path, request: &Value) -> CliResult<Value> {
    let timeout = Some(Duration::from_secs(30));
    #[cfg(unix)]
    if let Ok(stream) = std::os::unix::net::UnixStream::connect(home.join("mycelium.sock")) {
        stream.set_read_timeout(timeout)?;
        stream.set_write_timeout(timeout)?;
        // Do not retry after a request is sent: the publication may have committed.
        return exchange_control(stream, request);
    }
    let port: u16 = String::from_utf8(read_bounded(&home.join("mycelium.tcp"), 32)?)?
        .trim()
        .parse()?;
    if port == 0 {
        return Err("node control TCP port is invalid".into());
    }
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    let stream = TcpStream::connect_timeout(&address, Duration::from_secs(10))?;
    stream.set_read_timeout(timeout)?;
    stream.set_write_timeout(timeout)?;
    exchange_control(stream, request)
}

fn publish_site(home: &Path, mut request: Value, entrypoint: &str) -> CliResult<Value> {
    if let Some(token) = control_token(home)? {
        request
            .as_object_mut()
            .ok_or("invalid publication object")?
            .insert("auth".into(), Value::String(token));
    }
    let response = call_control(home, &request)?;
    if response.get("status").and_then(Value::as_str) != Some("repo_published") {
        // Avoid printing an arbitrary daemon error which could echo a credential.
        return Err("the node did not confirm site publication; inspect the local node log".into());
    }
    let cid = ContentId::from_str(
        response
            .get("cid")
            .and_then(Value::as_str)
            .ok_or("publication response has no content identifier")?,
    )?;
    let leaves = response
        .get("leaves")
        .and_then(Value::as_u64)
        .ok_or("publication response has no leaf count")?;
    let bytes = response
        .get("bytes")
        .and_then(Value::as_u64)
        .ok_or("publication response has no byte count")?;
    Ok(json!({
        "status": "repo_published", "cid": cid.to_string(), "leaves": leaves,
        "bytes": bytes, "entry_url": publication::site_entry_url(cid, entrypoint)?,
    }))
}

#[tokio::main]
async fn main() -> CliResult {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(command) = args.first() else {
        println!("{HELP}");
        return Err("a command is required".into());
    };
    let params = &args[1..];
    match command.as_str() {
        "--help" | "-h" | "help" => {
            println!("{HELP}");
            Ok(())
        }
        "compile" => {
            exact(params, 2, "compile INPUT OUTPUT")?;
            let model: Model = read_json(&params[0])?;
            model.evaluate(
                &vec![0.; model.weights.first().map_or(0, Vec::len)],
                &vec![true; model.actions.len()],
            )?;
            write_json(&params[1], &model)
        }
        "evaluate" => {
            exact(params, 1, "evaluate REQUEST")?;
            let request: Evaluation = read_json(&params[0])?;
            print_json(
                &request
                    .model
                    .evaluate(&request.features, &request.allowed)?,
            )
        }
        "train" => {
            exact(params, 4, "train DATASET CONFIG MODEL REPORT")?;
            let dataset: Dataset = read_json(&params[0])?;
            let config: TrainingConfig = read_json(&params[1])?;
            let (model, report) = training::train(&dataset, &config)?;
            write_json(&params[2], &model)?;
            write_json(&params[3], &report)?;
            print_json(&report)
        }
        "fine-tune" => {
            exact(params, 5, "fine-tune DATASET CONFIG INITIAL MODEL REPORT")?;
            let dataset: Dataset = read_json(&params[0])?;
            let config: TrainingConfig = read_json(&params[1])?;
            let initial: Model = read_json(&params[2])?;
            let (model, report) = training::fine_tune(&dataset, &config, &initial)?;
            write_json(&params[3], &model)?;
            write_json(&params[4], &report)?;
            print_json(&report)
        }
        "benchmark" => benchmark_command(params),
        "credit" => {
            exact(params, 4, "credit S1_STORE RECEIPT STUDIO AMOUNT")?;
            let mut store = Store::open(Path::new(&params[0]))?;
            store
                .ledger
                .credit(&params[1], &params[2], params[3].parse()?)?;
            store.save()?;
            print_json(&store.ledger.balances)
        }
        "reserve" => {
            exact(params, 2, "reserve S1_STORE ALLOWANCE")?;
            let mut store = Store::open(Path::new(&params[0]))?;
            let allowance = read_json(&params[1])?;
            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            let ticket = store.ledger.reserve(allowance, &store.issuer, now)?;
            store.save()?;
            print_json(&json!({"ticket": ticket,
                "public_key": hex::encode(store.issuer.verifying_key().to_bytes())}))
        }
        "checkout" => checkout_command(params),
        "issue-client-key" => {
            exact(params, 2, "issue-client-key NODE_HOME STUDIO")?;
            let key =
                mycelium_s1::http::issue_client_key(&Path::new(&params[0]).join("s1"), &params[1])?;
            print_json(&json!({"studio": params[1], "client_key": key}))
        }
        "serve" => {
            if params.is_empty() || params.len() > 2 {
                return Err("usage: mycelium-s1 serve NODE_HOME [127.0.0.1:7481]".into());
            }
            let address: SocketAddr = params
                .get(1)
                .map_or("127.0.0.1:7481", String::as_str)
                .parse()?;
            if !address.ip().is_loopback() {
                return Err("serve requires a loopback address".into());
            }
            let listener = tokio::net::TcpListener::bind(address).await?;
            println!("S1 portal: http://{}", listener.local_addr()?);
            axum::serve(
                listener,
                mycelium_s1::configured_router(Path::new(&params[0]).to_path_buf()),
            )
            .await?;
            Ok(())
        }
        "prepare-site" => prepare_site_command(params),
        "publish" => {
            exact(params, 2, "publish NODE_HOME REQUEST")?;
            let request_bytes = read_bounded(Path::new(&params[1]), 48 * 1024 * 1024)?;
            let (request, entrypoint) = validated_publish_request(&request_bytes)?;
            print_json(&publish_site(Path::new(&params[0]), request, &entrypoint)?)
        }
        _ => Err(format!("unknown command {command}; run mycelium-s1 --help").into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publication_rejects_other_commands_and_embedded_auth() {
        let command = json!({"cmd":"shutdown", "repository":"s1", "branch":"main",
            "expected_previous_cid":null,"message":"[public] portal","leaves":[]});
        assert!(validated_publish_request(&serde_json::to_vec(&command).unwrap()).is_err());
        let mut command = command;
        command["cmd"] = json!("repo_publish");
        command["auth"] = json!("secret");
        assert!(validated_publish_request(&serde_json::to_vec(&command).unwrap()).is_err());
    }

    #[test]
    fn publication_revalidates_content_and_visibility() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("index.html"), "<html>S1</html>").unwrap();
        let bundle = publication::prepare_site(dir.path(), "s1", "index.html").unwrap();
        let request = bundle
            .repo_publish_request("s1", "main", None, "[public] portal")
            .unwrap();
        assert!(validated_publish_request(&serde_json::to_vec(&request).unwrap()).is_ok());
        let mut damaged = request.clone();
        damaged["leaves"][0]["content"][0] = json!(0);
        assert!(validated_publish_request(&serde_json::to_vec(&damaged).unwrap()).is_err());
        let mut private = request;
        private["message"] = json!("private portal");
        assert!(validated_publish_request(&serde_json::to_vec(&private).unwrap()).is_err());
    }
}
