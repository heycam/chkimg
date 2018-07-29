use std::fmt::{self, Display, Formatter};
use std::fs::File;
use std::path::PathBuf;
use std::result;
use std::io::{self, Read};

pub struct SymbolCache<'a> {
    path: Option<PathBuf>,
    urls: Box<[&'a str]>,
}

#[derive(Debug)]
pub enum Error {
    LoadFailure(io::Error),
    NotFound,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Error::LoadFailure(ref e) => {
                write!(f, "symbol cache load failure: {:?}", e)
            }
            Error::NotFound => {
                write!(f, "not found")
            }
        }
    }
}

pub type Result<T> = result::Result<T, Error>;

impl<'a> SymbolCache<'a> {
    pub fn new(
        symbol_cache_path: Option<&str>,
        symbol_server_urls: &[&'a str],
    ) -> SymbolCache<'a> {
        SymbolCache {
            path: symbol_cache_path.map(PathBuf::from),
            urls: symbol_server_urls.to_vec().into_boxed_slice(),
        }
    }

    pub fn load_code_file(
        &self,
        code_file: &str,
        code_identifier: &str
    ) -> Result<CodeFile> {
        if let Some(f) = self
            .load_cached_code_file(code_file, code_identifier)
            .map_err(Error::LoadFailure)?
        {
            return Ok(f);
        }

        Err(Error::NotFound)
    }

    fn load_cached_code_file(
        &self,
        code_file: &str,
        code_identifier: &str
    ) -> io::Result<Option<CodeFile>> {
        if let Some(ref path) = self.path {
            let mut path = path.clone();
            path.push(code_file);
            path.push(code_identifier);
            path.push(code_file);
            if path.exists() {
                let mut file = File::open(path)?;
                let mut buf = vec![];
                file.read_to_end(&mut buf)?;
                let codefile = CodeFile {
                    data: buf.into_boxed_slice(),
                };
                return Ok(Some(codefile));
            }
        };
        Ok(None)
    }
}

pub struct CodeFile {
    pub data: Box<[u8]>,
}
