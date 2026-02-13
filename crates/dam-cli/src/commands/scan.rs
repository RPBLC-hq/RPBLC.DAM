use anyhow::Result;
use colored::Colorize;
use dam_detect::DetectionPipeline;
use std::io::Read;

pub async fn run(text: Option<String>) -> Result<()> {
    let config = super::load_config()?;
    let vault = super::open_vault(&config)?;
    let pipeline = DetectionPipeline::new(&config, vault);

    // Get text from argument or stdin
    let text = match text {
        Some(t) => t,
        None => {
            let mut buf = String::new();
            std::io::stdin().read_to_string(&mut buf)?;
            buf
        }
    };

    let result = pipeline.scan(&text, Some("cli"))?;

    println!("{}", "Redacted:".bold());
    println!("{}", result.redacted_text);

    if result.detections.is_empty() {
        println!("\n{}", "No PII detected.".dimmed());
    } else {
        println!("\n{} ({}):", "Detections".bold(), result.detections.len());
        for d in &result.detections {
            println!(
                "  {} → {} (confidence: {:.0}%)",
                d.pii_ref.display().yellow(),
                d.pii_type,
                d.confidence * 100.0
            );
        }
    }

    Ok(())
}
