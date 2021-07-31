use std::path::PathBuf;
use argh::FromArgs;

/// Options
#[derive(Debug, FromArgs)]
pub struct Opt {
    /// target executable
    #[argh(positional)]
    pub target: PathBuf,

    /// dll to inject into the target
    #[argh(positional)]
    pub dll: PathBuf
}