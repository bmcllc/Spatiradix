fn main() {
    match mycelium_meta_gateway::run_pix_pay_lab() {
        Ok(report) => println!("{report:#?} verified=false; local QA only"),
        Err(error) => {
            eprintln!("W8: {error}");
            std::process::exit(1);
        }
    }
}
