#[macro_use]
extern crate clap;
extern crate minidump;

use clap::{App, Arg};
use minidump::Minidump;
use std::fmt::{self, Display, Formatter};

#[derive(Debug)]
enum Error {
    MinidumpReadFailure(minidump::Error),
}

impl From<minidump::Error> for Error {
    fn from(e: minidump::Error) -> Error {
        Error::MinidumpReadFailure(e)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Error::MinidumpReadFailure(ref e) => {
                write!(f, "minidump read failure: {:?}", e)
            }
        }
    }
}

fn run(minidump_filename: &str) -> Result<(), Error> {
    let dump = Minidump::read_path(minidump_filename)?;

    Result::Ok(())
}

fn main() {
    let matches = App::new(crate_name!())
        .version(crate_version!())
        .about(crate_description!())
        .arg(
            Arg::with_name("MINIDUMP")
                .help("Specifies the input minidump file")
                .index(1)
                .required(true)
        )
        .get_matches();

    let minidump_filename = matches.value_of("MINIDUMP").unwrap();

    if let Err(e) = run(minidump_filename) {
        eprintln!("{}", e);
    }
}
