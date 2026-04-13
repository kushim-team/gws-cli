// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Text extraction from binary document formats (DOCX, XLSX, PPTX, PDF).
//!
//! Used by the MCP server to convert binary API responses into text content
//! blocks that Claude can process, instead of returning `resource` blobs
//! that get silently discarded by the MCP client.

use std::collections::HashMap;
use std::io::Read;

/// Maximum character count (~100k tokens) before truncation.
const MAX_CHARS: usize = 400_000;

const TRUNCATION_NOTICE: &str = "\n\n[Content truncated: exceeded 100,000 token limit]";

#[derive(Debug, thiserror::Error)]
pub enum ExtractionError {
    #[error("ZIP archive error: {0}")]
    Zip(String),
    #[error("XML parsing error: {0}")]
    Xml(String),
    #[error("PDF extraction error: {0}")]
    Pdf(String),
}

/// Returns `true` when the MIME type is a format we can extract text from.
pub fn is_extractable_mime(mime: &str) -> bool {
    let base = mime.split(';').next().unwrap_or(mime).trim();
    matches!(
        base,
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            | "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            | "application/vnd.openxmlformats-officedocument.presentationml.presentation"
            | "application/pdf"
    )
}

/// Attempt to extract text from binary document bytes based on MIME type.
///
/// Returns `Ok(Some(text))` if extraction succeeds, `Ok(None)` if the MIME
/// type is not supported for extraction, and `Err(...)` if extraction was
/// attempted but failed.
pub fn extract_text(mime: &str, data: &[u8]) -> Result<Option<String>, ExtractionError> {
    let base = mime.split(';').next().unwrap_or(mime).trim();
    let text = match base {
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document" => {
            extract_docx(data)?
        }
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" => extract_xlsx(data)?,
        "application/vnd.openxmlformats-officedocument.presentationml.presentation" => {
            extract_pptx(data)?
        }
        "application/pdf" => extract_pdf(data)?,
        _ => return Ok(None),
    };
    Ok(Some(truncate_to_limit(text)))
}

// ---------------------------------------------------------------------------
// DOCX extraction
// ---------------------------------------------------------------------------

fn extract_docx(data: &[u8]) -> Result<String, ExtractionError> {
    let cursor = std::io::Cursor::new(data);
    let mut archive =
        zip::ZipArchive::new(cursor).map_err(|e| ExtractionError::Zip(e.to_string()))?;

    let mut xml_str = String::new();
    archive
        .by_name("word/document.xml")
        .map_err(|e| ExtractionError::Zip(e.to_string()))?
        .read_to_string(&mut xml_str)
        .map_err(|e| ExtractionError::Xml(e.to_string()))?;

    let mut reader = quick_xml::Reader::from_str(&xml_str);
    let mut result = String::new();
    let mut paragraph_text = String::new();
    let mut in_paragraph = false;
    let mut in_text_elem = false;

    loop {
        match reader.read_event() {
            Ok(quick_xml::events::Event::Start(ref e)) => {
                let local = e.local_name();
                if local.as_ref() == b"p" {
                    in_paragraph = true;
                    paragraph_text.clear();
                } else if local.as_ref() == b"t" && in_paragraph {
                    in_text_elem = true;
                }
            }
            Ok(quick_xml::events::Event::Text(ref e)) if in_text_elem => {
                if let Ok(text) = e.unescape() {
                    paragraph_text.push_str(&text);
                }
            }
            Ok(quick_xml::events::Event::End(ref e)) => {
                let local = e.local_name();
                if local.as_ref() == b"t" {
                    in_text_elem = false;
                } else if local.as_ref() == b"p" {
                    if !paragraph_text.is_empty() {
                        if !result.is_empty() {
                            result.push('\n');
                        }
                        result.push_str(&paragraph_text);
                    }
                    in_paragraph = false;
                }
            }
            Ok(quick_xml::events::Event::Eof) => break,
            Err(e) => return Err(ExtractionError::Xml(e.to_string())),
            _ => {}
        }
    }
    Ok(result)
}

// ---------------------------------------------------------------------------
// PPTX extraction
// ---------------------------------------------------------------------------

fn extract_pptx(data: &[u8]) -> Result<String, ExtractionError> {
    let cursor = std::io::Cursor::new(data);
    let mut archive =
        zip::ZipArchive::new(cursor).map_err(|e| ExtractionError::Zip(e.to_string()))?;

    let mut slide_names: Vec<String> = (0..archive.len())
        .filter_map(|i| {
            let name = archive.by_index(i).ok()?.name().to_string();
            if name.starts_with("ppt/slides/slide") && name.ends_with(".xml") {
                Some(name)
            } else {
                None
            }
        })
        .collect();
    slide_names.sort_by_key(|n| extract_slide_number(n));

    let mut result = String::new();
    for (i, slide_name) in slide_names.iter().enumerate() {
        let mut xml_str = String::new();
        archive
            .by_name(slide_name)
            .map_err(|e| ExtractionError::Zip(e.to_string()))?
            .read_to_string(&mut xml_str)
            .map_err(|e| ExtractionError::Xml(e.to_string()))?;

        let slide_text = extract_drawing_text(&xml_str)?;
        if !result.is_empty() {
            result.push('\n');
        }
        result.push_str(&format!("## Slide {}", i + 1));
        if slide_text.is_empty() {
            result.push_str("\n(no text)");
        } else {
            result.push('\n');
            result.push_str(&slide_text);
        }
        result.push('\n');
    }
    Ok(result)
}

fn extract_slide_number(path: &str) -> u32 {
    path.trim_start_matches("ppt/slides/slide")
        .trim_end_matches(".xml")
        .parse()
        .unwrap_or(u32::MAX)
}

/// Extract text from DrawingML XML (`<a:p>` / `<a:t>` elements).
fn extract_drawing_text(xml: &str) -> Result<String, ExtractionError> {
    let mut reader = quick_xml::Reader::from_str(xml);
    let mut result = String::new();
    let mut paragraph_text = String::new();
    let mut in_paragraph = false;
    let mut in_text_elem = false;

    loop {
        match reader.read_event() {
            Ok(quick_xml::events::Event::Start(ref e)) => {
                let local = e.local_name();
                if local.as_ref() == b"p" {
                    in_paragraph = true;
                    paragraph_text.clear();
                } else if local.as_ref() == b"t" && in_paragraph {
                    in_text_elem = true;
                }
            }
            Ok(quick_xml::events::Event::Text(ref e)) if in_text_elem => {
                if let Ok(text) = e.unescape() {
                    paragraph_text.push_str(&text);
                }
            }
            Ok(quick_xml::events::Event::End(ref e)) => {
                let local = e.local_name();
                if local.as_ref() == b"t" {
                    in_text_elem = false;
                } else if local.as_ref() == b"p" {
                    if !paragraph_text.is_empty() {
                        if !result.is_empty() {
                            result.push('\n');
                        }
                        result.push_str(&paragraph_text);
                    }
                    in_paragraph = false;
                }
            }
            Ok(quick_xml::events::Event::Eof) => break,
            Err(e) => return Err(ExtractionError::Xml(e.to_string())),
            _ => {}
        }
    }
    Ok(result)
}

// ---------------------------------------------------------------------------
// XLSX extraction
// ---------------------------------------------------------------------------

fn extract_xlsx(data: &[u8]) -> Result<String, ExtractionError> {
    let cursor = std::io::Cursor::new(data);
    let mut archive =
        zip::ZipArchive::new(cursor).map_err(|e| ExtractionError::Zip(e.to_string()))?;

    // 1. Parse shared strings
    let shared_strings = parse_shared_strings(&mut archive)?;

    // 2. Parse workbook relationships (rId → file path)
    let rel_map = parse_workbook_rels(&mut archive)?;

    // 3. Parse workbook to get ordered sheet list
    let sheets = parse_workbook_sheets(&mut archive, &rel_map)?;

    // 4. Extract each sheet as a Markdown table
    let mut output = String::new();
    for sheet in &sheets {
        let mut xml_str = String::new();
        let sheet_path = &sheet.path;
        match archive.by_name(sheet_path) {
            Ok(mut file) => {
                file.read_to_string(&mut xml_str)
                    .map_err(|e| ExtractionError::Xml(e.to_string()))?;
            }
            Err(_) => continue,
        }

        let rows = parse_sheet_rows(&xml_str, &shared_strings)?;
        if !output.is_empty() {
            output.push('\n');
        }
        output.push_str(&format!("## Sheet: {}\n", sheet.name));
        if rows.is_empty() {
            output.push_str("(empty sheet)\n");
            continue;
        }
        output.push_str(&format_rows_as_markdown(&rows));
        output.push('\n');
    }
    Ok(output)
}

fn parse_shared_strings(
    archive: &mut zip::ZipArchive<std::io::Cursor<&[u8]>>,
) -> Result<Vec<String>, ExtractionError> {
    let mut xml_str = String::new();
    match archive.by_name("xl/sharedStrings.xml") {
        Ok(mut file) => {
            file.read_to_string(&mut xml_str)
                .map_err(|e| ExtractionError::Xml(e.to_string()))?;
        }
        Err(_) => return Ok(Vec::new()),
    }

    let mut reader = quick_xml::Reader::from_str(&xml_str);
    let mut strings = Vec::new();
    let mut in_si = false;
    let mut in_t = false;
    let mut current = String::new();

    loop {
        match reader.read_event() {
            Ok(quick_xml::events::Event::Start(ref e)) => {
                let local = e.local_name();
                if local.as_ref() == b"si" {
                    in_si = true;
                    current.clear();
                } else if local.as_ref() == b"t" && in_si {
                    in_t = true;
                }
            }
            Ok(quick_xml::events::Event::Text(ref e)) if in_t => {
                if let Ok(text) = e.unescape() {
                    current.push_str(&text);
                }
            }
            Ok(quick_xml::events::Event::End(ref e)) => {
                let local = e.local_name();
                if local.as_ref() == b"t" {
                    in_t = false;
                } else if local.as_ref() == b"si" {
                    strings.push(std::mem::take(&mut current));
                    in_si = false;
                }
            }
            Ok(quick_xml::events::Event::Eof) => break,
            Err(e) => return Err(ExtractionError::Xml(e.to_string())),
            _ => {}
        }
    }
    Ok(strings)
}

fn parse_workbook_rels(
    archive: &mut zip::ZipArchive<std::io::Cursor<&[u8]>>,
) -> Result<HashMap<String, String>, ExtractionError> {
    let mut xml_str = String::new();
    archive
        .by_name("xl/_rels/workbook.xml.rels")
        .map_err(|e| ExtractionError::Zip(e.to_string()))?
        .read_to_string(&mut xml_str)
        .map_err(|e| ExtractionError::Xml(e.to_string()))?;

    let mut reader = quick_xml::Reader::from_str(&xml_str);
    let mut map = HashMap::new();

    loop {
        match reader.read_event() {
            Ok(quick_xml::events::Event::Start(ref e) | quick_xml::events::Event::Empty(ref e)) => {
                if e.local_name().as_ref() == b"Relationship" {
                    let mut id = None;
                    let mut target = None;
                    for attr in e.attributes().flatten() {
                        match attr.key.as_ref() {
                            b"Id" => id = Some(String::from_utf8_lossy(&attr.value).to_string()),
                            b"Target" => {
                                target = Some(String::from_utf8_lossy(&attr.value).to_string())
                            }
                            _ => {}
                        }
                    }
                    if let (Some(id), Some(target)) = (id, target) {
                        map.insert(id, target);
                    }
                }
            }
            Ok(quick_xml::events::Event::Eof) => break,
            Err(e) => return Err(ExtractionError::Xml(e.to_string())),
            _ => {}
        }
    }
    Ok(map)
}

struct SheetInfo {
    name: String,
    path: String,
}

fn parse_workbook_sheets(
    archive: &mut zip::ZipArchive<std::io::Cursor<&[u8]>>,
    rel_map: &HashMap<String, String>,
) -> Result<Vec<SheetInfo>, ExtractionError> {
    let mut xml_str = String::new();
    archive
        .by_name("xl/workbook.xml")
        .map_err(|e| ExtractionError::Zip(e.to_string()))?
        .read_to_string(&mut xml_str)
        .map_err(|e| ExtractionError::Xml(e.to_string()))?;

    let mut reader = quick_xml::Reader::from_str(&xml_str);
    let mut sheets = Vec::new();

    loop {
        match reader.read_event() {
            Ok(quick_xml::events::Event::Start(ref e) | quick_xml::events::Event::Empty(ref e)) => {
                if e.local_name().as_ref() == b"sheet" {
                    let mut name = None;
                    let mut r_id = None;
                    for attr in e.attributes().flatten() {
                        match attr.key.as_ref() {
                            b"name" => {
                                name = Some(String::from_utf8_lossy(&attr.value).to_string())
                            }
                            // r:id attribute — the local name is "id" with namespace prefix "r"
                            _ => {
                                let key = String::from_utf8_lossy(attr.key.as_ref());
                                if key == "r:id"
                                    || key.ends_with(":id") && attr.key.as_ref() != b"sheetId"
                                {
                                    r_id = Some(String::from_utf8_lossy(&attr.value).to_string());
                                }
                            }
                        }
                    }
                    if let (Some(name), Some(r_id)) = (name, r_id) {
                        if let Some(target) = rel_map.get(&r_id) {
                            if target.starts_with("worksheets/") {
                                sheets.push(SheetInfo {
                                    name,
                                    path: format!("xl/{target}"),
                                });
                            }
                        }
                    }
                }
            }
            Ok(quick_xml::events::Event::Eof) => break,
            Err(e) => return Err(ExtractionError::Xml(e.to_string())),
            _ => {}
        }
    }
    Ok(sheets)
}

fn col_to_index(col: &str) -> usize {
    let mut idx: usize = 0;
    for ch in col.bytes() {
        idx = idx * 26 + (ch.to_ascii_uppercase() - b'A') as usize + 1;
    }
    idx.saturating_sub(1)
}

fn parse_sheet_rows(
    xml: &str,
    shared_strings: &[String],
) -> Result<Vec<Vec<String>>, ExtractionError> {
    let mut reader = quick_xml::Reader::from_str(xml);
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut current_row: HashMap<usize, String> = HashMap::new();
    let mut max_col: usize = 0;
    let mut in_row = false;
    let mut cell_type: Option<String> = None;
    let mut cell_col: usize = 0;
    let mut in_cell = false;
    let mut in_v = false;
    let mut in_inline_t = false;
    let mut cell_value = String::new();

    loop {
        match reader.read_event() {
            Ok(quick_xml::events::Event::Start(ref e)) => {
                let local = e.local_name();
                match local.as_ref() {
                    b"row" => {
                        in_row = true;
                        current_row.clear();
                    }
                    b"c" if in_row => {
                        in_cell = true;
                        cell_type = None;
                        cell_col = 0;
                        cell_value.clear();
                        for attr in e.attributes().flatten() {
                            match attr.key.as_ref() {
                                b"r" => {
                                    let r = String::from_utf8_lossy(&attr.value);
                                    let col_str: String =
                                        r.chars().take_while(|c| c.is_ascii_alphabetic()).collect();
                                    if !col_str.is_empty() {
                                        cell_col = col_to_index(&col_str);
                                        if cell_col > max_col {
                                            max_col = cell_col;
                                        }
                                    }
                                }
                                b"t" => {
                                    cell_type =
                                        Some(String::from_utf8_lossy(&attr.value).to_string());
                                }
                                _ => {}
                            }
                        }
                    }
                    b"v" if in_cell => {
                        in_v = true;
                    }
                    b"t" if in_cell => {
                        // inline string <is><t>
                        in_inline_t = true;
                    }
                    _ => {}
                }
            }
            Ok(quick_xml::events::Event::Text(ref e)) => {
                if in_v || in_inline_t {
                    if let Ok(text) = e.unescape() {
                        cell_value.push_str(&text);
                    }
                }
            }
            Ok(quick_xml::events::Event::End(ref e)) => {
                let local = e.local_name();
                match local.as_ref() {
                    b"v" => in_v = false,
                    b"t" if in_inline_t => in_inline_t = false,
                    b"c" => {
                        if in_cell {
                            let value = if cell_type.as_deref() == Some("s") {
                                // Shared string reference
                                cell_value
                                    .parse::<usize>()
                                    .ok()
                                    .and_then(|idx| shared_strings.get(idx))
                                    .cloned()
                                    .unwrap_or_default()
                            } else {
                                std::mem::take(&mut cell_value)
                            };
                            current_row.insert(cell_col, value);
                            in_cell = false;
                        }
                    }
                    b"row" => {
                        if in_row && !current_row.is_empty() {
                            let width = max_col + 1;
                            let row: Vec<String> = (0..width)
                                .map(|i| current_row.get(&i).cloned().unwrap_or_default())
                                .collect();
                            rows.push(row);
                        }
                        in_row = false;
                    }
                    _ => {}
                }
            }
            Ok(quick_xml::events::Event::Eof) => break,
            Err(e) => return Err(ExtractionError::Xml(e.to_string())),
            _ => {}
        }
    }
    Ok(rows)
}

fn escape_markdown_cell(v: &str) -> String {
    v.replace('|', "\\|").replace('\n', " ")
}

fn format_rows_as_markdown(rows: &[Vec<String>]) -> String {
    if rows.is_empty() {
        return String::new();
    }
    let width = rows.iter().map(|r| r.len()).max().unwrap_or(0);
    if width == 0 {
        return String::new();
    }

    let mut output = String::new();

    // Header row
    let header: Vec<String> = (0..width)
        .map(|i| {
            rows[0]
                .get(i)
                .map(|v| escape_markdown_cell(v))
                .unwrap_or_default()
        })
        .collect();
    output.push_str("| ");
    output.push_str(&header.join(" | "));
    output.push_str(" |\n");

    // Separator
    output.push_str("| ");
    output.push_str(&vec!["---"; width].join(" | "));
    output.push_str(" |\n");

    // Data rows
    for row in rows.iter().skip(1) {
        let cells: Vec<String> = (0..width)
            .map(|i| {
                row.get(i)
                    .map(|v| escape_markdown_cell(v))
                    .unwrap_or_default()
            })
            .collect();
        output.push_str("| ");
        output.push_str(&cells.join(" | "));
        output.push_str(" |\n");
    }
    output
}

// ---------------------------------------------------------------------------
// PDF extraction
// ---------------------------------------------------------------------------

fn extract_pdf(data: &[u8]) -> Result<String, ExtractionError> {
    pdf_extract::extract_text_from_mem(data).map_err(|e| ExtractionError::Pdf(e.to_string()))
}

// ---------------------------------------------------------------------------
// Truncation
// ---------------------------------------------------------------------------

fn truncate_to_limit(text: String) -> String {
    if text.len() <= MAX_CHARS {
        // Fast path: byte length is always >= char count for UTF-8,
        // so if byte length fits, char count certainly fits.
        return text;
    }
    let char_count = text.chars().count();
    if char_count <= MAX_CHARS {
        return text;
    }
    let truncated: String = text.chars().take(MAX_CHARS).collect();
    format!("{truncated}{TRUNCATION_NOTICE}")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn build_test_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        use std::io::Write;
        let buf = Vec::new();
        let cursor = std::io::Cursor::new(buf);
        let mut writer = zip::ZipWriter::new(cursor);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        for (name, content) in entries {
            writer.start_file(name.to_string(), options).unwrap();
            writer.write_all(content).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    // -- is_extractable_mime --

    #[test]
    fn test_is_extractable_mime_supported() {
        assert!(is_extractable_mime(
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        ));
        assert!(is_extractable_mime(
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        ));
        assert!(is_extractable_mime(
            "application/vnd.openxmlformats-officedocument.presentationml.presentation"
        ));
        assert!(is_extractable_mime("application/pdf"));
    }

    #[test]
    fn test_is_extractable_mime_unsupported() {
        assert!(!is_extractable_mime("image/png"));
        assert!(!is_extractable_mime("text/plain"));
        assert!(!is_extractable_mime("application/octet-stream"));
        assert!(!is_extractable_mime("application/json"));
    }

    #[test]
    fn test_is_extractable_mime_with_params() {
        assert!(is_extractable_mime("application/pdf; charset=utf-8"));
    }

    // -- extract_text dispatch --

    #[test]
    fn test_extract_text_unsupported_returns_none() {
        assert!(extract_text("image/png", &[]).unwrap().is_none());
        assert!(extract_text("application/octet-stream", &[])
            .unwrap()
            .is_none());
    }

    #[test]
    fn test_extract_text_supported_invalid_data_returns_err() {
        assert!(extract_text("application/pdf", &[1, 2, 3]).is_err());
        assert!(extract_text(
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            &[1, 2, 3]
        )
        .is_err());
    }

    // -- truncation --

    #[test]
    fn test_truncate_short_text() {
        let text = "Hello, world!".to_string();
        assert_eq!(truncate_to_limit(text.clone()), text);
    }

    #[test]
    fn test_truncate_exceeds_limit() {
        let text = "a".repeat(MAX_CHARS + 100);
        let result = truncate_to_limit(text);
        assert!(result.ends_with(TRUNCATION_NOTICE));
        assert!(result.len() < MAX_CHARS + 200);
    }

    // -- DOCX tests --

    #[test]
    fn test_extract_docx_basic() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
        <w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
          <w:body>
            <w:p><w:r><w:t>Hello World</w:t></w:r></w:p>
            <w:p><w:r><w:t>Second paragraph</w:t></w:r></w:p>
          </w:body>
        </w:document>"#;
        let data = build_test_zip(&[("word/document.xml", xml.as_bytes())]);
        let result = extract_docx(&data).unwrap();
        assert_eq!(result, "Hello World\nSecond paragraph");
    }

    #[test]
    fn test_extract_docx_multiple_runs() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
        <w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
          <w:body>
            <w:p>
              <w:r><w:t>Hello </w:t></w:r>
              <w:r><w:t>World</w:t></w:r>
            </w:p>
          </w:body>
        </w:document>"#;
        let data = build_test_zip(&[("word/document.xml", xml.as_bytes())]);
        let result = extract_docx(&data).unwrap();
        assert_eq!(result, "Hello World");
    }

    #[test]
    fn test_extract_docx_empty() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
        <w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
          <w:body></w:body>
        </w:document>"#;
        let data = build_test_zip(&[("word/document.xml", xml.as_bytes())]);
        let result = extract_docx(&data).unwrap();
        assert_eq!(result, "");
    }

    #[test]
    fn test_extract_docx_invalid_zip() {
        assert!(extract_docx(&[0, 1, 2, 3]).is_err());
    }

    #[test]
    fn test_extract_docx_missing_document_xml() {
        let data = build_test_zip(&[("word/other.xml", b"<root/>")]);
        assert!(extract_docx(&data).is_err());
    }

    // -- PPTX tests --

    #[test]
    fn test_extract_pptx_basic() {
        let slide1 = r#"<?xml version="1.0" encoding="UTF-8"?>
        <p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
               xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
          <p:cSld><p:spTree>
            <p:sp><p:txBody>
              <a:p><a:r><a:t>Title Slide</a:t></a:r></a:p>
            </p:txBody></p:sp>
          </p:spTree></p:cSld>
        </p:sld>"#;
        let slide2 = r#"<?xml version="1.0" encoding="UTF-8"?>
        <p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
               xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
          <p:cSld><p:spTree>
            <p:sp><p:txBody>
              <a:p><a:r><a:t>Slide Two Content</a:t></a:r></a:p>
            </p:txBody></p:sp>
          </p:spTree></p:cSld>
        </p:sld>"#;
        let data = build_test_zip(&[
            ("ppt/slides/slide1.xml", slide1.as_bytes()),
            ("ppt/slides/slide2.xml", slide2.as_bytes()),
        ]);
        let result = extract_pptx(&data).unwrap();
        assert!(result.contains("## Slide 1"));
        assert!(result.contains("Title Slide"));
        assert!(result.contains("## Slide 2"));
        assert!(result.contains("Slide Two Content"));
    }

    #[test]
    fn test_extract_pptx_no_slides() {
        let data = build_test_zip(&[("ppt/other.xml", b"<root/>")]);
        let result = extract_pptx(&data).unwrap();
        assert_eq!(result, "");
    }

    #[test]
    fn test_extract_pptx_slide_ordering() {
        let slide = |text: &str| {
            format!(
                r#"<?xml version="1.0"?>
                <p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
                       xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
                  <p:cSld><p:spTree><p:sp><p:txBody>
                    <a:p><a:r><a:t>{text}</a:t></a:r></a:p>
                  </p:txBody></p:sp></p:spTree></p:cSld>
                </p:sld>"#
            )
        };
        // Insert in reverse order to test sorting
        let data = build_test_zip(&[
            ("ppt/slides/slide10.xml", slide("Ten").as_bytes()),
            ("ppt/slides/slide2.xml", slide("Two").as_bytes()),
            ("ppt/slides/slide1.xml", slide("One").as_bytes()),
        ]);
        let result = extract_pptx(&data).unwrap();
        let lines: Vec<&str> = result.lines().collect();
        let slide_headers: Vec<&&str> =
            lines.iter().filter(|l| l.starts_with("## Slide")).collect();
        assert_eq!(slide_headers.len(), 3);
        assert_eq!(*slide_headers[0], "## Slide 1");
        assert_eq!(*slide_headers[1], "## Slide 2");
        assert_eq!(*slide_headers[2], "## Slide 3");
    }

    // -- XLSX tests --

    #[test]
    fn test_extract_xlsx_basic() {
        let shared_strings = r#"<?xml version="1.0" encoding="UTF-8"?>
        <sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="3">
          <si><t>Name</t></si>
          <si><t>Age</t></si>
          <si><t>Alice</t></si>
        </sst>"#;
        let workbook = r#"<?xml version="1.0" encoding="UTF-8"?>
        <workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
                  xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
          <sheets>
            <sheet name="Sheet1" sheetId="1" r:id="rId1"/>
          </sheets>
        </workbook>"#;
        let rels = r#"<?xml version="1.0" encoding="UTF-8"?>
        <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
          <Relationship Id="rId1" Target="worksheets/sheet1.xml"
            Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet"/>
        </Relationships>"#;
        let sheet1 = r#"<?xml version="1.0" encoding="UTF-8"?>
        <worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
          <sheetData>
            <row r="1">
              <c r="A1" t="s"><v>0</v></c>
              <c r="B1" t="s"><v>1</v></c>
            </row>
            <row r="2">
              <c r="A2" t="s"><v>2</v></c>
              <c r="B2"><v>30</v></c>
            </row>
          </sheetData>
        </worksheet>"#;

        let data = build_test_zip(&[
            ("xl/sharedStrings.xml", shared_strings.as_bytes()),
            ("xl/workbook.xml", workbook.as_bytes()),
            ("xl/_rels/workbook.xml.rels", rels.as_bytes()),
            ("xl/worksheets/sheet1.xml", sheet1.as_bytes()),
        ]);
        let result = extract_xlsx(&data).unwrap();
        assert!(result.contains("## Sheet: Sheet1"));
        assert!(result.contains("Name"));
        assert!(result.contains("Age"));
        assert!(result.contains("Alice"));
        assert!(result.contains("30"));
    }

    #[test]
    fn test_extract_xlsx_no_shared_strings() {
        let workbook = r#"<?xml version="1.0" encoding="UTF-8"?>
        <workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
                  xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
          <sheets>
            <sheet name="Data" sheetId="1" r:id="rId1"/>
          </sheets>
        </workbook>"#;
        let rels = r#"<?xml version="1.0" encoding="UTF-8"?>
        <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
          <Relationship Id="rId1" Target="worksheets/sheet1.xml"
            Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet"/>
        </Relationships>"#;
        let sheet1 = r#"<?xml version="1.0" encoding="UTF-8"?>
        <worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
          <sheetData>
            <row r="1">
              <c r="A1"><v>100</v></c>
              <c r="B1"><v>200</v></c>
            </row>
          </sheetData>
        </worksheet>"#;

        let data = build_test_zip(&[
            ("xl/workbook.xml", workbook.as_bytes()),
            ("xl/_rels/workbook.xml.rels", rels.as_bytes()),
            ("xl/worksheets/sheet1.xml", sheet1.as_bytes()),
        ]);
        let result = extract_xlsx(&data).unwrap();
        assert!(result.contains("100"));
        assert!(result.contains("200"));
    }

    // -- col_to_index --

    #[test]
    fn test_col_to_index() {
        assert_eq!(col_to_index("A"), 0);
        assert_eq!(col_to_index("B"), 1);
        assert_eq!(col_to_index("Z"), 25);
        assert_eq!(col_to_index("AA"), 26);
        assert_eq!(col_to_index("AB"), 27);
    }

    // -- Markdown formatting --

    #[test]
    fn test_escape_markdown_cell() {
        assert_eq!(escape_markdown_cell("hello"), "hello");
        assert_eq!(escape_markdown_cell("a|b"), "a\\|b");
        assert_eq!(escape_markdown_cell("line1\nline2"), "line1 line2");
    }

    #[test]
    fn test_format_rows_as_markdown() {
        let rows = vec![
            vec!["A".to_string(), "B".to_string()],
            vec!["1".to_string(), "2".to_string()],
        ];
        let md = format_rows_as_markdown(&rows);
        assert!(md.contains("| A | B |"));
        assert!(md.contains("| --- | --- |"));
        assert!(md.contains("| 1 | 2 |"));
    }
}
