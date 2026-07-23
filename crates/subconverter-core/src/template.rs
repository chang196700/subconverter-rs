use std::collections::BTreeMap;

pub fn render_template(content: &str, vars: &BTreeMap<String, String>) -> String {
    render_variables(content, vars)
}

pub fn render_template_with_includes(
    content: &str,
    vars: &BTreeMap<String, String>,
    includes: &BTreeMap<String, String>,
) -> String {
    let expanded = expand_includes(content, includes, 0);
    render_variables(&expanded, vars)
}

fn render_variables(content: &str, vars: &BTreeMap<String, String>) -> String {
    let mut output = String::with_capacity(content.len());
    let mut rest = content;
    while let Some(start) = rest.find("{{") {
        let (before, after_start) = rest.split_at(start);
        output.push_str(before);
        let after_start = &after_start[2..];
        let Some(end) = after_start.find("}}") else {
            output.push_str("{{");
            output.push_str(after_start);
            return output;
        };
        let (expr, after_end) = after_start.split_at(end);
        if let Some(value) = vars.get(expr.trim()) {
            output.push_str(value);
        }
        rest = &after_end[2..];
    }
    output.push_str(rest);
    output
}

fn expand_includes(content: &str, includes: &BTreeMap<String, String>, depth: usize) -> String {
    if depth >= 8 {
        return content.to_string();
    }
    let mut output = String::with_capacity(content.len());
    let mut rest = content;
    while let Some(start) = rest.find("{%") {
        let (before, after_start) = rest.split_at(start);
        output.push_str(before);
        let after_start = &after_start[2..];
        let Some(end) = after_start.find("%}") else {
            output.push_str("{%");
            output.push_str(after_start);
            return output;
        };
        let (tag, after_end) = after_start.split_at(end);
        if let Some(name) = parse_include_name(tag.trim()) {
            if let Some(included) = includes.get(name) {
                output.push_str(&expand_includes(included, includes, depth + 1));
            }
        } else {
            output.push_str("{%");
            output.push_str(tag);
            output.push_str("%}");
        }
        rest = &after_end[2..];
    }
    output.push_str(rest);
    output
}

fn parse_include_name(tag: &str) -> Option<&str> {
    let rest = tag.strip_prefix("include")?.trim();
    let quote = rest.as_bytes().first().copied()?;
    if quote != b'"' && quote != b'\'' {
        return None;
    }
    let rest = &rest[1..];
    let end = rest.find(quote as char)?;
    Some(&rest[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_braced_variables() {
        let vars = BTreeMap::from([
            ("name".to_string(), "subconverter".to_string()),
            ("port".to_string(), "25500".to_string()),
        ]);
        assert_eq!(
            render_template("{{ name }}:{{port}}", &vars),
            "subconverter:25500"
        );
    }

    #[test]
    fn expands_include_tags_before_variables() {
        let vars = BTreeMap::from([("name".to_string(), "Rust".to_string())]);
        let includes = BTreeMap::from([("child.tpl".to_string(), "Hello {{ name }}".to_string())]);
        assert_eq!(
            render_template_with_includes("{% include \"child.tpl\" %}", &vars, &includes),
            "Hello Rust"
        );
    }
}
