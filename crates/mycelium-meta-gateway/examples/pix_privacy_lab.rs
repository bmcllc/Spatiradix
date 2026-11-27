fn main() {
    match mycelium_meta_gateway::run_pix_privacy_lab() {
        Ok(report) => println!("{report:#?} verified=false; local QA only"),
        Err(error) => {
            eprintln!("W7: {error}");
            std::process::exit(1);
        }
    }
}
