#[macro_use]
extern crate clap;
extern crate minidump;
extern crate pe;

mod symbol_cache;

use clap::{App, Arg};
use minidump::{Minidump, MinidumpException, MinidumpMemory, MinidumpMemoryList};
use minidump::{MinidumpModule, MinidumpModuleList, MinidumpRawContext, Module};
use pe::{Pe, RVA};
use std::fmt::{self, Display, Formatter};
use std::mem;
use symbol_cache::SymbolCache;

#[derive(Debug)]
enum Error {
    MinidumpReadFailure(minidump::Error),
    SymbolCacheFailure(symbol_cache::Error),
    PeFailure(pe::Error),
    NoSymbolSource,
}

impl From<minidump::Error> for Error {
    fn from(e: minidump::Error) -> Error {
        Error::MinidumpReadFailure(e)
    }
}

impl From<symbol_cache::Error> for Error {
    fn from(e: symbol_cache::Error) -> Error {
        Error::SymbolCacheFailure(e)
    }
}

impl From<pe::Error> for Error {
    fn from(e: pe::Error) -> Error {
        Error::PeFailure(e)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Error::MinidumpReadFailure(ref e) => {
                write!(f, "minidump read failure: {:?}", e)
            }
            Error::SymbolCacheFailure(ref e) => {
                write!(f, "symbol cache failure: {}", e)
            }
            Error::PeFailure(ref e) => {
                write!(f, "PE failure: {:?}", e)
            }
            Error::NoSymbolSource => {
                write!(f, "no symbol server or symbol cache specified")
            }
        }
    }
}

#[derive(Clone, Copy)]
struct Span {
    offset: u64,
    len: u32,
}

impl Span {
    fn end(&self) -> u64 {
        self.offset + self.len as u64
    }

    fn intersect(&self, other: Span) -> Option<Span> {
        if other.offset < self.offset {
            other.intersect(*self)
        } else if self.end() <= other.offset {
            None
        } else if self.end() >= other.end() {
            Some(other)
        } else {
            let len = self.end() - other.offset;
            if len > 0xffffffff {
                None
            } else {
                Some(Span {
                    offset: other.offset,
                    len: len as u32,
                })
            }
        }
    }
}

trait MemorySpan {
    fn span(&self) -> Span;
}

impl MemorySpan for MinidumpMemory {
    fn span(&self) -> Span {
        assert!(self.size <= 0xffffffff);
        Span {
            offset: self.base_address,
            len: self.size as u32,
        }
    }
}

impl MemorySpan for MinidumpModule {
    fn span(&self) -> Span {
        assert!(self.size() <= 0xffffffff);
        Span {
            offset: self.base_address(),
            len: self.size() as u32,
        }
    }
}

struct Intersection<'a, 'b> {
    memory: &'a MinidumpMemory,
    module: &'b MinidumpModule,
    span: Span,
}

impl<'a, 'b> Intersection<'a, 'b> {
    fn of(
        memory: &'a MinidumpMemory,
        module: &'b MinidumpModule,
    ) -> Option<Intersection<'a, 'b>> {
        memory.span().intersect(module.span()).map(|span| {
            Intersection {
                memory,
                module,
                span,
            }
        })
    }
}

fn find_intersections<'a, 'b>(
    memories: &[&'a MinidumpMemory],
    modules: &[&'b MinidumpModule],
) -> Vec<Intersection<'a, 'b>> {
    let mut memory_iter = memories.iter();
    let mut module_iter = modules.iter();
    let mut cur_memory = memory_iter.next();
    let mut cur_module = module_iter.next();

    let mut intersections = vec![];

    loop {
        if let (Some(memory), Some(module)) = (cur_memory, cur_module) {
            if let Some(intersection) = Intersection::of(memory, module) {
                intersections.push(intersection);
            }
            if memory.span().end() <= module.span().end() {
                cur_memory = memory_iter.next();
            } else {
                cur_module = module_iter.next();
            }
        } else {
            break;
        }
    }

    intersections
}

struct Mismatch<'a, 'b> {
    actual: &'a [u8],
    expected: &'b [u8],
    offset: u64,
}

impl<'a, 'b> Mismatch<'a, 'b> {
    fn len(&self) -> u32 {
        assert!(self.actual.len() == self.expected.len());
        assert!(self.actual.len() <= 0xffffffff);
        self.actual.len() as u32
    }

    fn span(&self) -> Span {
        Span {
            offset: self.offset,
            len: self.len(),
        }
    }
}

fn make_rva(addr: u64) -> RVA<[u8]> {
    assert!(addr <= 0xffffffff, "RVAs should always fit in 32 bits");

    // pe crate doesn't provide a good way to produce an RVA from scratch.
    unsafe { mem::transmute(addr as u32) }
}

fn run(
    minidump_filename: &str,
    symbol_cache: Option<&str>,
    symbol_servers: &[&str],
) -> Result<(), Error> {
    // Read the minidump file.
    let mut dump = Minidump::read_path(minidump_filename)?;

    // Print crashing IP.
    let exception: MinidumpException = dump.get_stream()?;
    if let Some(context) = exception.context {
        let ip = match context.raw {
            MinidumpRawContext::X86(ctx) => Some(ctx.eip as u64),
            MinidumpRawContext::AMD64(ctx) => Some(ctx.rip),
            _ => None,
        };
        if let Some(ip) = ip {
            println!("Crashing IP: 0x{:08x}", ip);
        }
    }

    if symbol_cache.is_none() && symbol_servers.is_empty() {
        return Err(Error::NoSymbolSource);
    }

    // Get the memory regions and loaded modules.
    let memory_list: MinidumpMemoryList = dump.get_stream()?;
    let module_list: MinidumpModuleList = dump.get_stream()?;

    let mut memories: Vec<_> = memory_list.iter().collect();
    let mut modules: Vec<_> = module_list.iter().collect();

    // Find any intersecting intervals of memory ranges.
    memories.sort_by(|a, b| a.base_address.cmp(&b.base_address));
    modules.sort_by(|a, b| a.base_address().cmp(&b.base_address()));

    let intersections = find_intersections(&memories, &modules);
    if intersections.is_empty() {
        println!("no memory ranges to check");
        return Ok(());
    }

    let mut found_errors = false;

    let sym_cache = SymbolCache::new(symbol_cache, symbol_servers);

    // Go over each intersecting memory range and compare bytes from the
    // minidump with bytes from the original image.
    for intersection in intersections {

        let offset = intersection.span.offset;
        let len = intersection.span.len;
        let memory_base = intersection.memory.base_address;
        let module_base = intersection.module.base_address();

        // Get the bytes from the minidump.
        let (_, memory_bytes) = intersection
            .memory
            .bytes
            .as_slice()
            .split_at((offset - memory_base) as usize);

        // Load the binary from the symbol server.
        let file = intersection.module.code_file();
        let file = file.split("\\").last().unwrap();
        let code_file = sym_cache.load_code_file(
            &*file,
            &*intersection.module.code_identifier(),
        );

        let code_file = match code_file {
            Ok(f) => f,
            Err(e) => {
                eprintln!("warning: {}: {}", file, e);
                continue;
            }
        };

        // Get the bytes from the binary.
        let pe = Pe::new(&code_file.data)?;
        let rva = make_rva(offset - module_base);
        let code_file_bytes = pe.ref_slice_at(rva, len).unwrap();

        // Compare the bytes to find spans of mismatches.
        let mut errors: Vec<Mismatch> = vec![];
        for (i, (a, b)) in memory_bytes
            .iter()
            .zip(code_file_bytes.iter())
            .enumerate()
        {
            if a != b {
                let offset = offset + i as u64;
                if errors
                    .last()
                    .map(|e| e.span().end() == offset)
                    .unwrap_or(false)
                {
                    let error = errors.last_mut().unwrap();
                    let len = error.len() as usize;
                    error.actual = &memory_bytes[i - len .. i + 1];
                    error.expected = &code_file_bytes[i - len .. i + 1];
                } else {
                    errors.push(Mismatch {
                        actual: &memory_bytes[i .. i + 1],
                        expected: &code_file_bytes[i .. i + 1],
                        offset,
                    });
                }
            }
        }

        if errors.is_empty() {
            continue;
        }
        found_errors = true;

        // Print out the errors.
        let error_count = errors.iter().map(|e| e.len()).fold(0, |sum, i| sum + i);

        println!(
            "{} mismatching byte{} found in {}",
            error_count,
            if error_count == 1 { "" } else { "s" },
            file
        );

        for error in errors {
            println!(
                "  0x{:08x} .. 0x{:08x} ({} byte{})",
                error.offset,
                error.span().end(),
                error.len(),
                if error.len() == 1 { "" } else { "s" },
            );
            print!("    [");
            for b in error.actual {
                print!(" {:02x}", b);
            }
            print!(" ] should be [");
            for b in error.expected {
                print!(" {:02x}", b);
            }
            println!(" ]");
        }
    }

    if !found_errors {
        println!("no errors found");
    }

    Ok(())
}

fn main() {
    let matches = App::new(crate_name!())
        .version(crate_version!())
        .about(crate_description!())
        .arg(
            Arg::with_name("symbol-cache")
                .help("directory to cache files downloaded from symbol servers")
                .takes_value(true)
                .long("symbol-cache")
        )
        .arg(
            Arg::with_name("symbol-server")
                .help("URL of symbol server to download binaries from")
                .takes_value(true)
                .multiple(true)
                .long("symbol-server")
        )
        .arg(
            Arg::with_name("MINIDUMP")
                .help("specifies the input minidump file")
                .index(1)
                .required(true)
        )
        .get_matches();

    let minidump_filename = matches.value_of("MINIDUMP").unwrap();
    let symbol_cache = matches.value_of("symbol-cache");
    let symbol_servers = matches
        .values_of("symbol-server")
        .map_or(vec![], |values| {
            values.collect()
        });

    if let Err(e) = run(minidump_filename, symbol_cache, &symbol_servers) {
        eprintln!("{}", e);
    }
}
