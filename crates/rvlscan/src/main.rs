use std::process::ExitCode;

const NAME: &str = env!("CARGO_PKG_NAME");
const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("--version") | Some("-V") => {
            println!("{NAME} {VERSION}");
            ExitCode::SUCCESS
        }
        Some("--help") | Some("-h") | None => {
            print_help();
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("error: unrecognized argument '{other}'");
            eprintln!("run '{NAME} --help' for usage");
            ExitCode::FAILURE
        }
    }
}

fn print_help() {
    println!("{NAME} {VERSION} - Revelara reliability scanner");
    println!();
    println!("Usage: {NAME} [OPTIONS]");
    println!();
    println!("Options:");
    println!("  -V, --version  Print version");
    println!("  -h, --help     Print help");
}
