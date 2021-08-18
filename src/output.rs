use colored::{Color, Colorize};

pub fn string_log(line: &str, color: Color) -> String {
    format!("{} {}", "creekey".truecolor(255,148,0), line.color(color))
}


pub fn log(line: &str, color: Color) {
    eprintln!("{}", string_log(line, color))
}
