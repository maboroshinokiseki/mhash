use std::path::PathBuf;

use clap::{Parser, ValueEnum};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Check hash files specified by command line.
    #[arg(short, long, group = "check_output")]
    pub check: Option<Option<PathBuf>>,

    /// Update the hash file specified by the option.
    #[arg(short, long, group = "update_output")]
    pub update: Option<PathBuf>,

    /// Output the hash file specified by the option.
    #[arg(short, long, group = "check_output", group = "update_output")]
    pub output: Option<PathBuf>,

    /// Files to be hashed.
    pub paths: Vec<PathBuf>,

    /// How many blocks to be stored in memory at the same time.
    #[arg(long, default_value_t = 3)]
    pub block_count: usize,

    /// Block size in bytes, default unit is byte, case insensitive.
    #[arg(long, default_value_t = {"1MiB".to_owned()})]
    pub block_size: String,

    /// How many files to be hashed at the same time. [default: cpu core count / hasher count]
    #[arg(long)]
    pub file_count: Option<usize>,

    /// Recursively process directories.
    #[arg(short, long)]
    pub recursive: bool,

    /// Do not show progress bars, while calculating or checking sums.
    #[arg(short, long)]
    pub no_progress: bool,

    /// Follow symbolic links when processing files or directories recursively.
    #[arg(long)]
    pub follow: bool,

    /// Print format.
    #[arg(long, value_enum, default_value_t = Format::Auto)]
    pub format: Format,

    /// print header.
    #[arg(long)]
    pub header: bool,

    /// Sort.
    #[arg(short, long, value_enum)]
    pub sort: Vec<Sort>,

    /// Select CRC32 hash function.
    #[arg(long)]
    pub crc32: bool,

    /// Select CRC32C hash function.
    #[arg(long)]
    pub crc32_c: bool,

    /// Select MD5 hash function.
    #[arg(long)]
    pub md5: bool,

    /// Select SHA1 hash function.
    #[arg(long)]
    pub sha1: bool,

    /// Select SHA2-224 hash function.
    #[arg(long)]
    pub sha224: bool,

    /// Select SHA2-256 hash function.
    #[arg(long)]
    pub sha256: bool,

    /// Select SHA2-384 hash function.
    #[arg(long)]
    pub sha384: bool,

    /// Select SHA2-512 hash function.
    #[arg(long)]
    pub sha512: bool,

    /// Select SHA3-224 hash function.
    #[arg(long)]
    pub sha3_224: bool,

    /// Select SHA3-256 hash function.
    #[arg(long)]
    pub sha3_256: bool,

    /// Select SHA3-384 hash function.
    #[arg(long)]
    pub sha3_384: bool,

    /// Select SHA3-512 hash function.
    #[arg(long)]
    pub sha3_512: bool,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum Format {
    /// Uses CoreUtils when there's only one digest, otherwise SFV
    /// Or follow the original checksum file
    Auto,
    /// Digests on the left side
    CoreUtils,
    /// Digests on the right side
    Sfv,
    /// HashName(Digest) = Filename
    Bsd,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum Sort {
    Path,
    PathDec,
    Atime,
    AtimeDec,
    Ctime,
    CtimeDec,
    Mtime,
    MtimeDec,
    Size,
    SizeDec,
}
