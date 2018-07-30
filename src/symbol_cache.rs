extern crate reqwest;

use self::reqwest::StatusCode;
use std::fmt::{self, Display, Formatter};
use std::fs::{DirBuilder, File};
use std::path::PathBuf;
use std::result;
use std::io::{self, Read, Write};

pub struct SymbolCache<'a> {
    path: Option<PathBuf>,
    urls: Box<[&'a str]>,
}

#[derive(Debug)]
pub enum Error {
    LoadFailure(io::Error),
    NotFound,
    EmptyURL,
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
            Error::EmptyURL => {
                write!(f, "empty symbol server URL")
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
        // Try to load it from the cache.
        if let Some(f) = self
            .load_cached_code_file(code_file, code_identifier)
            .map_err(Error::LoadFailure)?
        {
            return Ok(f);
        }

        // Try each symbol server.
        for url in self.urls.iter() {
            if url.is_empty() {
                return Err(Error::EmptyURL);
            }

            let f = match self.load_code_file_from_server(
                code_file,
                code_identifier,
                url,
            ) {
                Err(e) => {
                    eprintln!(
                        "warning: could not read {} from symbol server {}: {}",
                        code_file,
                        url,
                        e,
                    );
                    continue;
                }
                Ok(None) => continue,
                Ok(Some(f)) => f,
            };

            match self.store_cached_code_file(code_file, code_identifier, &f) {
                Err(e) => {
                    eprintln!(
                        "warning: could not write {} to symbol cache: {}",
                        code_file,
                        e,
                    );
                }
                Ok(()) => {}
            }
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

    fn store_cached_code_file(
        &self,
        code_file: &str,
        code_identifier: &str,
        f: &CodeFile,
    ) -> io::Result<()> {
        if let Some(ref path) = self.path {
            let mut path = path.clone();
            path.push(code_file);
            path.push(code_identifier);

            DirBuilder::new()
                .recursive(true)
                .create(&path)?;

            path.push(code_file);

            let mut file = File::create(path)?;
            file.write_all(&f.data)?;
        }
        Ok(())
    }

    fn load_code_file_from_server(
        &self,
        code_file: &str,
        code_identifier: &str,
        url: &str,
    ) -> reqwest::Result<Option<CodeFile>> {

        println!("Looking for {} at {}...", code_file, url);

        let client = reqwest::Client::new();

        let mut base_url = url.to_string();
        if base_url.chars().last().unwrap() != '/' {
            base_url.push('/');
        }
        base_url.push_str(code_file);
        base_url.push('/');
        base_url.push_str(code_identifier);
        base_url.push('/');

        let mut uncompressed_url = base_url.clone();
        uncompressed_url.push_str(code_file);

        let response = client.head(&uncompressed_url).send()?;
        match response.status() {
            StatusCode::Ok => {
                println!("Fetching {} from {}...", code_file, url);
                let mut buffer = vec![];
                client.get(&uncompressed_url)
                    .send()?
                    .copy_to(&mut buffer)?;
                return Ok(Some(CodeFile {
                    data: buffer.into_boxed_slice(),
                }));
            }
            _ => {}
        }

        Ok(None)
    }
}

pub struct CodeFile {
    pub data: Box<[u8]>,
}
