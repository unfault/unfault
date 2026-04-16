// unfault-ignore: rust.println_in_lib
use colored::Colorize;

use crate::exit_codes::{EXIT_ERROR, EXIT_SUCCESS};
use crate::fmt::{word_wrap, COL_WIDTH};

/// Execute `unfault info <id>`.
///
/// Prints the full SRE glossary entry for the given ID (e.g. "SLO-001"),
/// wrapping body text at 80 columns.
pub fn execute(id: &str) -> i32 {
    let id = id.to_uppercase();

    match unfault_analysis::sre::lookup_glossary(&id) {
        Some(entry) => {
            let indent = "  ";
            println!();
            println!(
                "  {}  {}",
                format!("[{}]", entry.id).bright_red().bold(),
                entry.aka.bold()
            );

            println!();
            println!("  {}", "The Hazard".bright_yellow().bold());
            for line in word_wrap(entry.hazard, indent, indent, COL_WIDTH) {
                println!("{}", line);
            }

            println!();
            println!("  {}", "How It Kills Services".bright_yellow().bold());
            for line in word_wrap(entry.mechanics, indent, indent, COL_WIDTH) {
                println!("{}", line);
            }

            println!();
            println!("  {}", "The Fix".bright_green().bold());
            for line in word_wrap(entry.fix, indent, indent, COL_WIDTH) {
                println!("{}", line);
            }

            println!();
            println!("  {}", "System Design Tradeoff".bright_yellow().bold());
            let gain_line = format!("+ Gain:  {}", entry.tradeoff.gain);
            let risk_line = format!("- Risk:  {}", entry.tradeoff.risk);
            for line in word_wrap(&gain_line, indent, "           ", COL_WIDTH) {
                println!("{}", line.green());
            }
            for line in word_wrap(&risk_line, indent, "           ", COL_WIDTH) {
                println!("{}", line.red());
            }

            println!();
            EXIT_SUCCESS
        }
        None => {
            eprintln!("  {} Unknown glossary ID: {}", "✗".bright_red(), id);
            eprintln!();
            eprintln!("  Available IDs: SLO-001 through SLO-006");
            eprintln!();
            EXIT_ERROR
        }
    }
}
