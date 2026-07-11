use crate::tools::hyalos::TailFilters;
use crate::tools::{hyalos, policy};
use serde_json::{json, Value};

pub fn command(args: &[String]) -> i32 {
    let command = match args {
        [verb, ..] => format!("hyalos {verb}"),
        [] => "hyalos".to_string(),
    };
    match policy::allows_command(&command) {
        Ok(true) => {}
        Ok(false) => {
            eprintln!("caduceus-public-action-not-allowed");
            return 2;
        }
        Err(err) => {
            eprintln!("{err}");
            return 1;
        }
    }

    let result = match args {
        [verb, organ, kind, message, rest @ ..] if verb == "reflect" => {
            let mut value = json!({
                "organ": organ,
                "kind": kind,
                "message": message,
                "ok": option_value(rest, "--ok").map(|value| value != "false").unwrap_or(true),
                "attributes_redacted": option_json(rest, "--payload").unwrap_or_else(|| json!({}))
            });
            for (flag, field) in [
                ("--body-id", "body_id"),
                ("--world", "world"),
                ("--level", "level"),
                ("--correlation-id", "correlation_id"),
                ("--session-id", "session_id"),
                ("--work-id", "work_id"),
                ("--review-id", "review_id"),
                ("--strike-id", "strike_id"),
            ] {
                if let Some(item) = option_value(rest, flag) {
                    value[field] = json!(item);
                }
            }
            hyalos::reflect_json(value)
        }
        [verb, event] if verb == "append" => serde_json::from_str::<Value>(event)
            .map_err(|err| format!("hyalos-channel-event-invalid: {err}"))
            .and_then(hyalos::append_json),
        [verb, rest @ ..] if verb == "tail" => parse_tail_filters(rest).and_then(hyalos::tail_json),
        _ => Err("caduceus-hyalos-command-invalid".to_string()),
    };

    match result {
        Ok(value) => {
            println!("{}", serde_json::to_string_pretty(&value).unwrap());
            0
        }
        Err(err) => {
            eprintln!("caduceus-hyalos-failed: {err}");
            1
        }
    }
}

pub fn reflect_json(value: Value) -> Result<Value, String> {
    hyalos::reflect_json(value)
}

pub fn append_json(value: Value) -> Result<Value, String> {
    hyalos::append_json(value)
}

pub fn tail_json(filters: TailFilters) -> Result<Value, String> {
    hyalos::tail_json(filters)
}

fn parse_tail_filters(args: &[String]) -> Result<TailFilters, String> {
    let mut count = 20usize;
    let mut saw_count = false;
    for arg in args {
        if !arg.starts_with("--") && !saw_count {
            count = arg
                .parse::<usize>()
                .map_err(|err| format!("hyalos-tail-count-invalid: {err}"))?;
            saw_count = true;
        }
    }
    Ok(TailFilters {
        count,
        kind: option_value(args, "--kind").map(str::to_string),
        organ: option_value(args, "--organ").map(str::to_string),
        world: option_value(args, "--world").map(str::to_string),
        correlation_id: option_value(args, "--correlation-id").map(str::to_string),
        level: option_value(args, "--level").map(str::to_string),
        ok: option_value(args, "--ok").map(|value| value != "false"),
    })
}

fn option_value<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|value| value == name)
        .and_then(|index| args.get(index + 1))
        .map(String::as_str)
}

fn option_json(args: &[String], name: &str) -> Option<Value> {
    option_value(args, name).and_then(|value| serde_json::from_str(value).ok())
}
