#[macro_use]
extern crate clap;
extern crate minidump;

use clap::{App, Arg};
use minidump::{Minidump, MinidumpMemory, MinidumpMemoryList, MinidumpModule};
use minidump::{MinidumpModuleList, Module};
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

#[derive(Clone, Copy)]
struct Span {
    offset: u64,
    len: u64,
}

impl Span {
    fn end(&self) -> u64 {
        self.offset + self.len
    }

    fn intersect(&self, other: Span) -> Option<Span> {
        if other.offset < self.offset {
            other.intersect(*self)
        } else if self.end() <= other.offset {
            None
        } else if self.end() >= other.end() {
            Some(other)
        } else {
            Some(Span {
                offset: other.offset,
                len: self.end() - other.offset,
            })
        }
    }
}

trait MemorySpan {
    fn span(&self) -> Span;
}

impl MemorySpan for MinidumpMemory {
    fn span(&self) -> Span {
        Span {
            offset: self.base_address,
            len: self.size,
        }
    }
}

impl MemorySpan for MinidumpModule {
    fn span(&self) -> Span {
        Span {
            offset: self.base_address(),
            len: self.size(),
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

fn run(minidump_filename: &str) -> Result<(), Error> {
    // Read the minidump file.
    let mut dump = Minidump::read_path(minidump_filename)?;

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

    Ok(())
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
