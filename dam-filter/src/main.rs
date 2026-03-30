use anyhow::Result;
use clap::Parser;
use dam_core::Detection;
use dam_detect_pii::patterns as pii;
use dam_detect_secrets::patterns as secrets;
use serde_json::Value;
use std::io::{self, Read};

#[derive(Parser)]
#[command(
    name = "dam-filter",
    about = "Strip PII and secrets from coding sessions and traces"
)]
struct Cli {
    /// Input format: auto-detects JSON vs plain text
    #[arg(long, value_enum, default_value = "auto")]
    format: Format,

    /// Print a detection report to stderr
    #[arg(long)]
    report: bool,

    /// Input file (default: stdin)
    #[arg()]
    file: Option<String>,
}

#[derive(Clone, clap::ValueEnum)]
enum Format {
    Auto,
    Json,
    Text,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let input = match &cli.file {
        Some(path) => std::fs::read_to_string(path)?,
        None => {
            let mut buf = String::new();
            io::stdin().read_to_string(&mut buf)?;
            buf
        }
    };

    let is_json = match cli.format {
        Format::Json => true,
        Format::Text => false,
        Format::Auto => input.trim_start().starts_with('{') || input.trim_start().starts_with('['),
    };

    let mut total_detections: Vec<(String, Detection)> = Vec::new();

    let output = if is_json {
        let mut value: Value = serde_json::from_str(&input)?;
        redact_value(&mut value, &mut total_detections);
        serde_json::to_string_pretty(&value)?
    } else {
        let (redacted, detections) = redact_text(&input);
        for d in detections {
            total_detections.push((String::new(), d));
        }
        redacted
    };

    print!("{output}");

    if cli.report {
        eprintln!("\n--- dam-filter report ---");
        eprintln!("detections: {}", total_detections.len());
        for (path, det) in &total_detections {
            let loc = if path.is_empty() {
                String::new()
            } else {
                format!(" at {path}")
            };
            eprintln!(
                "  [{}] {:.*}...{loc}",
                det.data_type.tag(),
                4.min(det.value.len()),
                det.value,
            );
        }
    }

    Ok(())
}

/// Walk a JSON value, redacting all string leaves in place.
fn redact_value(value: &mut Value, detections: &mut Vec<(String, Detection)>) {
    redact_value_at(value, detections, "");
}

fn redact_value_at(value: &mut Value, detections: &mut Vec<(String, Detection)>, path: &str) {
    match value {
        Value::String(s) => {
            let (redacted, dets) = redact_text(s);
            for d in dets {
                detections.push((path.to_string(), d));
            }
            *s = redacted;
        }
        Value::Array(arr) => {
            for (i, item) in arr.iter_mut().enumerate() {
                let child_path = format!("{path}[{i}]");
                redact_value_at(item, detections, &child_path);
            }
        }
        Value::Object(map) => {
            for (key, val) in map.iter_mut() {
                let child_path = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                redact_value_at(val, detections, &child_path);
            }
        }
        _ => {}
    }
}

/// Detect PII and secrets in text, replace with `[DAM:TYPE]` placeholders.
fn redact_text(input: &str) -> (String, Vec<Detection>) {
    let mut detections = pii::detect_all(input);
    detections.extend(secrets::detect_all(input));

    // Dedup overlapping spans — keep highest confidence
    detections.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let mut kept: Vec<Detection> = Vec::new();
    for det in detections {
        if !kept.iter().any(|k| k.span.overlaps(&det.span)) {
            kept.push(det);
        }
    }

    // Sort by span start descending for safe replacement
    kept.sort_by(|a, b| b.span.start.cmp(&a.span.start));

    let mut output = input.to_string();
    for det in &kept {
        let tag = det.data_type.tag().to_ascii_uppercase();
        let placeholder = format!("[DAM:{tag}]");
        if det.span.start <= output.len() && det.span.end <= output.len() {
            output.replace_range(det.span.start..det.span.end, &placeholder);
        }
    }

    // Re-sort by position for the report
    kept.sort_by_key(|d| d.span.start);
    (output, kept)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_email_in_text() {
        let (out, dets) = redact_text("contact alice@example.com for details");
        assert!(out.contains("[DAM:EMAIL]"));
        assert!(!out.contains("alice@example.com"));
        assert_eq!(dets.len(), 1);
    }

    #[test]
    fn redact_multiple_types() {
        let (out, dets) = redact_text("email: user@test.com, ssn: 123-45-6789");
        assert!(out.contains("[DAM:EMAIL]"));
        assert!(out.contains("[DAM:SSN]"));
        assert!(!out.contains("user@test.com"));
        assert!(!out.contains("123-45-6789"));
        assert_eq!(dets.len(), 2);
    }

    #[test]
    fn redact_json_strings() {
        let mut val: Value =
            serde_json::from_str(r#"{"message": "my email is alice@test.com", "count": 42}"#)
                .unwrap();
        let mut dets = Vec::new();
        redact_value(&mut val, &mut dets);
        let s = val["message"].as_str().unwrap();
        assert!(s.contains("[DAM:EMAIL]"));
        assert!(!s.contains("alice@test.com"));
        assert_eq!(val["count"], 42);
    }

    #[test]
    fn redact_nested_json() {
        let mut val: Value = serde_json::from_str(
            r#"{"messages": [{"role": "user", "content": "ssn 123-45-6789"}]}"#,
        )
        .unwrap();
        let mut dets = Vec::new();
        redact_value(&mut val, &mut dets);
        let content = val["messages"][0]["content"].as_str().unwrap();
        assert!(content.contains("[DAM:SSN]"));
        assert_eq!(dets.len(), 1);
        assert!(dets[0].0.contains("messages"));
    }

    #[test]
    fn clean_text_unchanged() {
        let (out, dets) = redact_text("just a normal sentence");
        assert_eq!(out, "just a normal sentence");
        assert!(dets.is_empty());
    }

    #[test]
    fn api_key_detected() {
        let (out, dets) = redact_text(
            "key: sk-ant-api03-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz-AABBCCDD",
        );
        assert!(
            !dets.is_empty()
                || out
                    != "key: sk-ant-api03-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz-AABBCCDD"
        );
    }
}
