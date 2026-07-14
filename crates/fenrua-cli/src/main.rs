use std::process::ExitCode;

fn main() -> ExitCode {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let mut stdout = std::io::stdout().lock();
    let mut stderr = std::io::stderr().lock();
    fenrua_cli::run(&arguments, &mut stdout, &mut stderr)
}
