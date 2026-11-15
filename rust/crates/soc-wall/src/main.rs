//! The p2soc wall binary. All behaviour lives in `soc_wall::dispatch`; this is
//! just the process entry point so the dispatcher is library code and testable.

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let argv0 = args.first().map(String::as_str).unwrap_or("soc-wall");
    std::process::exit(soc_wall::dispatch::dispatch(argv0, args.get(1..).unwrap_or(&[])));
}
