use crate::keychain::KeyChainError;
use crate::ssh_agent::ReadError;
use anyhow::Result;
use colored::{Color, Colorize};
use std::env;
use std::fs::File;
use std::io::Write;
use std::os::unix::net::UnixStream;

pub struct Log<'a> {
    file: Option<&'a File>,
    stream: Option<&'a UnixStream>,
}

pub fn string_log(emoji: &str, line: &str, color: Color) -> String {
    let name = match env::var("COLORTERM") {
        Ok(_e) => "creekey".truecolor(255, 148, 0).to_string(),
        Err(_) => "\x1b[38;5;202mcreekey\x1b[0;m".to_string(),
    };

    format!("{} {} \t{}", name, emoji, line.color(color))
}

impl<'a> Log<'a> {
    pub fn fail(&self, line: &str) -> Result<()> {
        self.println("❌", line, Color::Red)
    }

    pub fn panic(&self, line: &str) -> Result<()> {
        self.println("❌❌❌", line, Color::Red)
    }

    pub fn error(&self, line: &str) -> Result<()> {
        self.println("🚨", line, Color::Red)
    }

    pub fn waiting_on(&self, line: &str) -> Result<()> {
        self.println("⏳", line, Color::White)
    }

    pub fn success(&self, line: &str) -> Result<()> {
        self.println("🏁", line, Color::Green)
    }

    pub fn info(&self, line: &str) -> Result<()> {
        self.println("ℹ️", line, Color::White)
    }

    pub fn user_todo(&self, line: &str) -> Result<()> {
        self.println("➡️", line, Color::BrightCyan)
    }

    pub fn print(&self, emoji: &str, line: &str, color: Color) -> Result<()> {
        let string = string_log(emoji, line, color);
        if let Some(mut out) = self.file {
            out.write_all(string.as_bytes())?;
        }
        if let Some(mut out) = self.stream {
            out.write_all(string.as_bytes())?;
        }
        eprint!("{}", string);
        Ok(())
    }

    pub fn println(&self, emoji: &str, line: &str, color: Color) -> Result<()> {
        self.print(emoji, format!("{}\n", line).as_str(), color)
    }

    pub fn from_file<'b>(file: &'b File) -> Log<'b> {
        Log {
            file: Some(file),
            stream: None,
        }
    }

    pub fn from_stream<'b>(stream: &'b UnixStream) -> Log<'b> {
        Log {
            file: None,
            stream: Some(stream),
        }
    }
    pub const NONE: Log<'a> = Log {
        file: None,
        stream: None,
    };

    pub fn print_not_paired_error(&mut self, reason: String) -> Result<()> {
        self.println(
            "🚨",
            format!("{}. Did you pair yet?", reason).as_str(),
            Color::Red,
        )?;
        self.println("🚨", "Aborting...", Color::Red)?;
        return Ok(());
    }

    pub fn handle_keychain_error(&mut self, context: &str, error: KeyChainError) -> Result<()> {
        match error {
            KeyChainError::Missing => {
                self.print_not_paired_error(format!("Could not find {} in keychain", context))?;
            }
            e => {
                self.println(
                    "🚨",
                    format!("Could not Read {}: {}", context, e).as_str(),
                    Color::Red,
                )?;
            }
        }

        Ok(())
    }

    pub fn handle_read_error(&mut self, context: &str, error: ReadError) -> Result<()> {
        match error {
            ReadError::FileIsMissing => {
                self.print_not_paired_error(format!("Could not find {}", context))?;
            }
            e => {
                self.println(
                    "🚨",
                    format!("Could not Read {}: {}", context, e).as_str(),
                    Color::Red,
                )?;
            }
        }

        Ok(())
    }
}

pub fn check_color_tty() {
    colored::control::set_override(true);
    match env::var("NO_COLOR") {
        Ok(x) => {
            eprintln!("NO_COLOR found: {}", x);
            colored::control::set_override(false);
        }
        _ => {}
    };
}
