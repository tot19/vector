use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    fs,
    path::{Path, PathBuf},
};

const MAX_MIB_FILE_COUNT: usize = 16_384;
const MAX_MIB_DIRECTORY_DEPTH: usize = 32;
const MAX_MIB_FILE_BYTES: u64 = 8 * 1024 * 1024;
const MIB_FILE_EXTENSIONS: &[&str] = &["mib", "my", "smi", "txt"];

#[derive(Clone, Debug, Default)]
pub(super) struct MibResolver {
    names_by_oid: BTreeMap<Vec<u32>, MibSymbol>,
}

#[derive(Clone, Debug)]
struct MibSymbol {
    module: Option<String>,
    name: String,
    prefix_resolves: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct OidResolution {
    pub name: String,
    pub module: Option<String>,
    pub symbol: String,
    pub instance: Option<String>,
}

#[derive(Clone, Debug)]
struct RawDefinition {
    module: Option<String>,
    name: String,
    prefix_resolves: bool,
    elements: Vec<OidElement>,
}

#[derive(Clone, Debug)]
struct MibFile {
    path: PathBuf,
    required: bool,
}

#[derive(Clone, Debug)]
enum OidElement {
    Symbol(String),
    Number(u32),
    NamedNumber(String, u32),
}

impl MibResolver {
    pub(super) fn from_paths(paths: &[PathBuf]) -> crate::Result<Self> {
        let mut resolver = Self::with_builtin_symbols();
        let mut definitions = Vec::new();

        for path in paths {
            for file in mib_files(path)? {
                match read_mib_file(&file.path) {
                    Ok(contents) => definitions.extend(parse_definitions(&contents)),
                    Err(error) if file.required => return Err(error),
                    Err(error) => {
                        warn!(
                            message = "Skipping unreadable MIB file discovered while scanning directory.",
                            path = %file.path.display(),
                            error = %error,
                        );
                    }
                }
            }
        }

        resolver.resolve_definitions(definitions);
        Ok(resolver)
    }

    pub(super) fn with_builtin_symbols() -> Self {
        let mut resolver = Self::default();
        resolver.insert_builtin("SNMPv2-SMI", "ccitt", &[0], false);
        resolver.insert_builtin("SNMPv2-SMI", "iso", &[1], false);
        resolver.insert_builtin("SNMPv2-SMI", "joint-iso-ccitt", &[2], false);
        resolver.insert_builtin("SNMPv2-SMI", "org", &[1, 3], false);
        resolver.insert_builtin("SNMPv2-SMI", "dod", &[1, 3, 6], false);
        resolver.insert_builtin("SNMPv2-SMI", "internet", &[1, 3, 6, 1], false);
        resolver.insert_builtin("SNMPv2-SMI", "directory", &[1, 3, 6, 1, 1], false);
        resolver.insert_builtin("SNMPv2-SMI", "mgmt", &[1, 3, 6, 1, 2], false);
        resolver.insert_builtin("SNMPv2-SMI", "mib-2", &[1, 3, 6, 1, 2, 1], false);
        resolver.insert_builtin("SNMPv2-SMI", "experimental", &[1, 3, 6, 1, 3], false);
        resolver.insert_builtin("SNMPv2-SMI", "private", &[1, 3, 6, 1, 4], false);
        resolver.insert_builtin("SNMPv2-SMI", "enterprises", &[1, 3, 6, 1, 4, 1], false);
        resolver.insert_builtin("SNMPv2-SMI", "security", &[1, 3, 6, 1, 5], false);
        resolver.insert_builtin("SNMPv2-SMI", "snmpV2", &[1, 3, 6, 1, 6], false);
        resolver.insert_builtin("SNMPv2-SMI", "snmpModules", &[1, 3, 6, 1, 6, 3], false);
        resolver.insert_builtin("SNMPv2-MIB", "system", &[1, 3, 6, 1, 2, 1, 1], false);
        resolver.insert_builtin("SNMPv2-MIB", "sysUpTime", &[1, 3, 6, 1, 2, 1, 1, 3], true);
        resolver.insert_builtin(
            "SNMPv2-MIB",
            "snmpTrap",
            &[1, 3, 6, 1, 6, 3, 1, 1, 4],
            false,
        );
        resolver.insert_builtin(
            "SNMPv2-MIB",
            "snmpTrapOID",
            &[1, 3, 6, 1, 6, 3, 1, 1, 4, 1],
            true,
        );
        resolver.insert_builtin(
            "SNMPv2-MIB",
            "snmpTraps",
            &[1, 3, 6, 1, 6, 3, 1, 1, 5],
            false,
        );
        resolver.insert_builtin(
            "SNMPv2-MIB",
            "coldStart",
            &[1, 3, 6, 1, 6, 3, 1, 1, 5, 1],
            false,
        );
        resolver.insert_builtin(
            "SNMPv2-MIB",
            "warmStart",
            &[1, 3, 6, 1, 6, 3, 1, 1, 5, 2],
            false,
        );
        resolver.insert_builtin("IF-MIB", "linkDown", &[1, 3, 6, 1, 6, 3, 1, 1, 5, 3], false);
        resolver.insert_builtin("IF-MIB", "linkUp", &[1, 3, 6, 1, 6, 3, 1, 1, 5, 4], false);
        resolver.insert_builtin(
            "SNMPv2-MIB",
            "authenticationFailure",
            &[1, 3, 6, 1, 6, 3, 1, 1, 5, 5],
            false,
        );
        resolver
    }

    pub(super) fn resolve(&self, oid: &str) -> Option<OidResolution> {
        let oid = parse_numeric_oid(oid)?;

        if let Some(symbol) = self.names_by_oid.get(&oid) {
            return Some(resolution(symbol, None));
        }

        self.names_by_oid
            .range(..=oid.clone())
            .rev()
            .find_map(|(prefix, symbol)| {
                if symbol.prefix_resolves && oid.starts_with(prefix) && oid.len() > prefix.len() {
                    let instance = oid[prefix.len()..]
                        .iter()
                        .map(u32::to_string)
                        .collect::<Vec<_>>()
                        .join(".");
                    Some(resolution(symbol, Some(instance)))
                } else {
                    None
                }
            })
    }

    fn insert_builtin(&mut self, module: &str, name: &str, oid: &[u32], prefix_resolves: bool) {
        self.names_by_oid.insert(
            oid.to_vec(),
            MibSymbol {
                module: Some(module.to_string()),
                name: name.to_string(),
                prefix_resolves,
            },
        );
    }

    fn resolve_definitions(&mut self, definitions: Vec<RawDefinition>) {
        let mut symbols = self.symbols_by_name();
        let mut waiting_by_symbol: HashMap<String, Vec<RawDefinition>> = HashMap::new();
        let mut ready_symbols = VecDeque::new();

        for definition in definitions {
            self.resolve_or_queue_definition(
                definition,
                &mut symbols,
                &mut waiting_by_symbol,
                &mut ready_symbols,
            );
        }

        while let Some(symbol) = ready_symbols.pop_front() {
            let Some(waiting) = waiting_by_symbol.remove(&symbol) else {
                continue;
            };

            for definition in waiting {
                self.resolve_or_queue_definition(
                    definition,
                    &mut symbols,
                    &mut waiting_by_symbol,
                    &mut ready_symbols,
                );
            }
        }
    }

    fn resolve_or_queue_definition(
        &mut self,
        definition: RawDefinition,
        symbols: &mut HashMap<String, Vec<u32>>,
        waiting_by_symbol: &mut HashMap<String, Vec<RawDefinition>>,
        ready_symbols: &mut VecDeque<String>,
    ) {
        if let Some(oid) = resolve_elements(&definition.elements, symbols) {
            let symbol = MibSymbol {
                module: definition.module.clone(),
                name: definition.name.clone(),
                prefix_resolves: definition.prefix_resolves,
            };

            symbols.insert(definition.name.clone(), oid.clone());
            ready_symbols.push_back(definition.name.clone());
            if let Some(module) = &definition.module {
                let qualified_name = format!("{module}::{}", definition.name);
                symbols.insert(qualified_name.clone(), oid.clone());
                ready_symbols.push_back(qualified_name);
            }
            self.names_by_oid.insert(oid, symbol);
        } else if let Some(symbol) = first_unresolved_symbol(&definition.elements, symbols) {
            waiting_by_symbol
                .entry(symbol)
                .or_default()
                .push(definition);
        }
    }

    fn symbols_by_name(&self) -> HashMap<String, Vec<u32>> {
        let mut symbols = HashMap::new();
        for (oid, symbol) in &self.names_by_oid {
            symbols.insert(symbol.name.clone(), oid.clone());
            if let Some(module) = &symbol.module {
                symbols.insert(format!("{module}::{}", symbol.name), oid.clone());
            }
        }
        symbols
    }

    #[cfg(test)]
    pub(super) fn from_str(contents: &str) -> Self {
        let mut resolver = Self::with_builtin_symbols();
        resolver.resolve_definitions(parse_definitions(contents));
        resolver
    }
}

fn mib_files(path: &Path) -> crate::Result<Vec<MibFile>> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("Failed to read MIB path {}: {error}", path.display()))?;

    if metadata.file_type().is_symlink() {
        let target_metadata = fs::metadata(path).map_err(|error| {
            format!(
                "Failed to read symlinked MIB path {}: {error}",
                path.display()
            )
        })?;
        if target_metadata.is_file() {
            return Ok(vec![MibFile {
                path: path.to_path_buf(),
                required: true,
            }]);
        }

        if target_metadata.is_dir() {
            return Err(format!(
                "MIB path {} is a symlinked directory; symlinked directories are not followed",
                path.display()
            )
            .into());
        }

        return Err(format!("MIB path {} is not a file or directory", path.display()).into());
    }

    if metadata.is_file() {
        return Ok(vec![MibFile {
            path: path.to_path_buf(),
            required: true,
        }]);
    }

    if !metadata.is_dir() {
        return Err(format!("MIB path {} is not a file or directory", path.display()).into());
    }

    let mut files = Vec::new();
    let mut canonical_files = HashSet::new();
    collect_mib_files(path, 0, &mut files, &mut canonical_files)?;
    files.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(files)
}

fn collect_mib_files(
    path: &Path,
    depth: usize,
    files: &mut Vec<MibFile>,
    canonical_files: &mut HashSet<PathBuf>,
) -> crate::Result<()> {
    if depth > MAX_MIB_DIRECTORY_DEPTH {
        return Err(format!(
            "MIB directory {} exceeds maximum recursive scan depth of {}",
            path.display(),
            MAX_MIB_DIRECTORY_DEPTH
        )
        .into());
    }

    for entry in fs::read_dir(path)
        .map_err(|error| format!("Failed to read MIB directory {}: {error}", path.display()))?
    {
        let entry = entry.map_err(|error| {
            format!(
                "Failed to read MIB directory entry in {}: {error}",
                path.display()
            )
        })?;
        let file_type = entry.file_type().map_err(|error| {
            format!(
                "Failed to read MIB directory entry type in {}: {error}",
                path.display()
            )
        })?;
        let path = entry.path();
        if file_type.is_symlink() {
            let Ok(target_metadata) = fs::metadata(&path) else {
                warn!(
                    message = "Skipping unreadable symlinked MIB path.",
                    path = %path.display(),
                );
                continue;
            };

            if target_metadata.is_file() {
                push_mib_file(files, canonical_files, path, false)?;
            }
            continue;
        }

        if file_type.is_dir() {
            collect_mib_files(&path, depth + 1, files, canonical_files)?;
        } else if file_type.is_file() {
            push_mib_file(files, canonical_files, path, false)?;
        }
    }
    Ok(())
}

fn push_mib_file(
    files: &mut Vec<MibFile>,
    canonical_files: &mut HashSet<PathBuf>,
    path: PathBuf,
    required: bool,
) -> crate::Result<()> {
    if !required && !has_mib_file_extension(&path) {
        return Ok(());
    }

    let canonical = fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
    if !canonical_files.insert(canonical) {
        return Ok(());
    }

    if files.len() >= MAX_MIB_FILE_COUNT {
        return Err(format!(
            "MIB path scan exceeded maximum file count of {}",
            MAX_MIB_FILE_COUNT
        )
        .into());
    }

    files.push(MibFile { path, required });
    Ok(())
}

fn has_mib_file_extension(path: &Path) -> bool {
    let Some(extension) = path.extension().and_then(|extension| extension.to_str()) else {
        return true;
    };

    MIB_FILE_EXTENSIONS
        .iter()
        .any(|allowed| extension.eq_ignore_ascii_case(allowed))
}

fn read_mib_file(path: &Path) -> crate::Result<String> {
    let metadata = fs::metadata(path)
        .map_err(|error| format!("Failed to read MIB file {}: {error}", path.display()))?;
    if metadata.len() > MAX_MIB_FILE_BYTES {
        return Err(format!(
            "MIB file {} is larger than the maximum supported size of {} bytes",
            path.display(),
            MAX_MIB_FILE_BYTES
        )
        .into());
    }

    fs::read_to_string(path)
        .map_err(|error| format!("Failed to read MIB file {}: {error}", path.display()).into())
}

fn parse_definitions(contents: &str) -> Vec<RawDefinition> {
    let tokens = tokenize(&strip_comments_and_strings(contents));
    let module = module_name(&tokens);
    let mut definitions = Vec::new();

    for index in 0..tokens.len().saturating_sub(1) {
        if !is_identifier(&tokens[index]) {
            continue;
        }

        let Some((width, prefix_resolves)) = oid_definition(&tokens, index + 1) else {
            continue;
        };

        if let Some(elements) = assignment_elements(&tokens, index + 1 + width) {
            definitions.push(RawDefinition {
                module: module.clone(),
                name: tokens[index].clone(),
                prefix_resolves,
                elements,
            });
        }
    }

    definitions
}

fn strip_comments_and_strings(contents: &str) -> String {
    let mut output = String::with_capacity(contents.len());
    let mut chars = contents.chars().peekable();

    while let Some(character) = chars.next() {
        if character == '-' && chars.peek() == Some(&'-') {
            let _ = chars.next();
            for comment_char in chars.by_ref() {
                if comment_char == '\n' {
                    output.push('\n');
                    break;
                }
            }
        } else if character == '"' {
            output.push(' ');
            for string_char in chars.by_ref() {
                if string_char == '"' {
                    break;
                }
            }
            output.push(' ');
        } else {
            output.push(character);
        }
    }

    output
}

fn tokenize(contents: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut chars = contents.chars().peekable();

    while let Some(character) = chars.next() {
        if character.is_ascii_alphanumeric() || character == '_' || character == '-' {
            let mut token = String::from(character);
            while let Some(next) = chars.peek() {
                if next.is_ascii_alphanumeric() || *next == '_' || *next == '-' {
                    token.push(*next);
                    let _ = chars.next();
                } else {
                    break;
                }
            }
            tokens.push(token);
        } else if character == ':' && chars.peek() == Some(&':') {
            let _ = chars.next();
            if chars.peek() == Some(&'=') {
                let _ = chars.next();
                tokens.push("::=".to_string());
            }
        } else if matches!(character, '{' | '}' | '(' | ')' | ',' | ';') {
            tokens.push(character.to_string());
        }
    }

    tokens
}

fn module_name(tokens: &[String]) -> Option<String> {
    tokens
        .windows(2)
        .find(|window| window[1] == "DEFINITIONS")
        .map(|window| window[0].clone())
}

fn oid_definition(tokens: &[String], index: usize) -> Option<(usize, bool)> {
    match tokens.get(index).map(String::as_str) {
        Some("OBJECT-TYPE") => Some((1, true)),
        Some("MODULE-IDENTITY" | "OBJECT-IDENTITY" | "NOTIFICATION-TYPE") => Some((1, false)),
        Some("OBJECT")
            if tokens
                .get(index + 1)
                .is_some_and(|token| token == "IDENTIFIER") =>
        {
            Some((2, false))
        }
        _ => None,
    }
}

fn assignment_elements(tokens: &[String], start: usize) -> Option<Vec<OidElement>> {
    let assign_index = tokens[start..]
        .iter()
        .position(|token| token == "::=")
        .map(|position| start + position)?;

    if tokens.get(assign_index + 1)? != "{" {
        return None;
    }

    let mut end = assign_index + 2;
    while tokens.get(end).is_some_and(|token| token != "}") {
        end += 1;
    }

    parse_oid_elements(&tokens[assign_index + 2..end])
}

fn parse_oid_elements(tokens: &[String]) -> Option<Vec<OidElement>> {
    let mut elements = Vec::new();
    let mut index = 0;

    while index < tokens.len() {
        let token = &tokens[index];
        if token == "," || token == ";" {
            index += 1;
            continue;
        }

        if let Ok(number) = token.parse::<u32>() {
            elements.push(OidElement::Number(number));
            index += 1;
        } else if tokens.get(index + 1).is_some_and(|token| token == "(")
            && let Some(number) = tokens.get(index + 2).and_then(|token| token.parse().ok())
            && tokens.get(index + 3).is_some_and(|token| token == ")")
        {
            elements.push(OidElement::NamedNumber(token.clone(), number));
            index += 4;
        } else if is_identifier(token) {
            elements.push(OidElement::Symbol(token.clone()));
            index += 1;
        } else {
            return None;
        }
    }

    Some(elements)
}

fn resolve_elements(
    elements: &[OidElement],
    symbols: &HashMap<String, Vec<u32>>,
) -> Option<Vec<u32>> {
    let mut oid = Vec::new();

    for element in elements {
        match element {
            OidElement::Number(number) => oid.push(*number),
            OidElement::Symbol(symbol) => {
                if symbol.contains('-') && oid.is_empty() && !symbols.contains_key(symbol) {
                    continue;
                }

                let resolved = symbols.get(symbol)?;
                if oid.is_empty() || resolved.starts_with(&oid) {
                    oid = resolved.clone();
                } else {
                    return None;
                }
            }
            OidElement::NamedNumber(symbol, number) => {
                if oid.is_empty() {
                    if let Some(resolved) = symbols.get(symbol) {
                        oid = resolved.clone();
                        if oid.last() != Some(number) {
                            oid.push(*number);
                        }
                    } else {
                        oid.push(*number);
                    }
                } else {
                    oid.push(*number);
                }
            }
        }
    }

    (!oid.is_empty()).then_some(oid)
}

fn first_unresolved_symbol(
    elements: &[OidElement],
    symbols: &HashMap<String, Vec<u32>>,
) -> Option<String> {
    let mut oid_is_empty = true;

    for element in elements {
        match element {
            OidElement::Number(_) => {
                oid_is_empty = false;
            }
            OidElement::Symbol(symbol) => {
                if symbol.contains('-') && oid_is_empty && !symbols.contains_key(symbol) {
                    continue;
                }

                if !symbols.contains_key(symbol) {
                    return Some(symbol.clone());
                }
                oid_is_empty = false;
            }
            OidElement::NamedNumber(_, _) => {
                oid_is_empty = false;
            }
        }
    }

    None
}

fn parse_numeric_oid(oid: &str) -> Option<Vec<u32>> {
    if oid.is_empty() || oid.split('.').any(str::is_empty) {
        return None;
    }

    oid.split('.')
        .map(str::parse)
        .collect::<Result<_, _>>()
        .ok()
}

fn resolution(symbol: &MibSymbol, instance: Option<String>) -> OidResolution {
    let name = if let Some(module) = &symbol.module {
        format!("{module}::{}", symbol.name)
    } else {
        symbol.name.clone()
    };
    let name = if let Some(instance) = &instance {
        format!("{name}.{instance}")
    } else {
        name
    };

    OidResolution {
        name,
        module: symbol.module.clone(),
        symbol: symbol.name.clone(),
        instance,
    }
}

fn is_identifier(token: &str) -> bool {
    token
        .as_bytes()
        .first()
        .is_some_and(|byte| byte.is_ascii_alphabetic())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MIB: &str = r#"
TEST-MIB DEFINITIONS ::= BEGIN

IMPORTS
    enterprises, OBJECT-TYPE, NOTIFICATION-TYPE
        FROM SNMPv2-SMI;

testRoot OBJECT IDENTIFIER ::= { enterprises 8072 }
testNotifications OBJECT IDENTIFIER ::= { testRoot 2 }
testNotificationPrefix OBJECT IDENTIFIER ::= { testNotifications 3 }
testSpecificNotifications OBJECT IDENTIFIER ::= { testNotificationPrefix 0 }

testTrap NOTIFICATION-TYPE
    OBJECTS { testValue }
    STATUS current
    DESCRIPTION "A test notification."
    ::= { testSpecificNotifications 1 }

testObjects OBJECT IDENTIFIER ::= { testNotifications 4 }
testValue OBJECT-TYPE
    SYNTAX Integer32
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "A test value."
    ::= { testObjects 1 }

END
"#;

    #[test]
    fn resolves_exact_and_instance_oids() {
        let resolver = MibResolver::from_str(TEST_MIB);

        assert_eq!(
            resolver.resolve("1.3.6.1.4.1.8072.2.3.0.1").unwrap().name,
            "TEST-MIB::testTrap"
        );
        assert_eq!(
            resolver.resolve("1.3.6.1.4.1.8072.2.4.1.0").unwrap(),
            OidResolution {
                name: "TEST-MIB::testValue.0".to_string(),
                module: Some("TEST-MIB".to_string()),
                symbol: "testValue".to_string(),
                instance: Some("0".to_string()),
            }
        );
        assert!(resolver.resolve("1.3.6.1.4.1.8072.2.3.2.1").is_none());
    }

    #[test]
    fn resolves_builtin_notification_oids() {
        let resolver = MibResolver::with_builtin_symbols();
        assert_eq!(
            resolver.resolve("1.3.6.1.2.1.1.3.0").unwrap().name,
            "SNMPv2-MIB::sysUpTime.0"
        );
        assert!(resolver.resolve("1.3.6.1.4.1.8072.1").is_none());
    }

    #[test]
    fn loads_single_mib_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mib_path = temp_dir.path().join("TEST-MIB.txt");
        fs::write(&mib_path, TEST_MIB).unwrap();

        let resolver = MibResolver::from_paths(&[mib_path]).unwrap();

        assert_eq!(
            resolver.resolve("1.3.6.1.4.1.8072.2.3.0.1").unwrap().name,
            "TEST-MIB::testTrap"
        );
    }

    #[test]
    fn loads_mib_files_recursively() {
        let temp_dir = tempfile::tempdir().unwrap();
        let nested_dir = temp_dir.path().join("vendor").join("devices");
        fs::create_dir_all(&nested_dir).unwrap();
        fs::write(nested_dir.join("TEST-MIB.txt"), TEST_MIB).unwrap();

        let resolver = MibResolver::from_paths(&[temp_dir.path().to_path_buf()]).unwrap();

        assert_eq!(
            resolver.resolve("1.3.6.1.4.1.8072.2.4.1.0").unwrap().name,
            "TEST-MIB::testValue.0"
        );
    }

    #[test]
    fn skips_non_mib_extensions_in_directories() {
        let temp_dir = tempfile::tempdir().unwrap();
        fs::write(temp_dir.path().join("TEST-MIB.txt"), TEST_MIB).unwrap();
        fs::write(temp_dir.path().join("README.md"), "not a mib").unwrap();
        fs::write(temp_dir.path().join("archive.bin"), [0xff, 0x00, 0xff]).unwrap();

        let resolver = MibResolver::from_paths(&[temp_dir.path().to_path_buf()]).unwrap();

        assert_eq!(
            resolver.resolve("1.3.6.1.4.1.8072.2.3.0.1").unwrap().name,
            "TEST-MIB::testTrap"
        );
    }

    #[test]
    fn rejects_oversized_explicit_mib_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mib_path = temp_dir.path().join("TOO-LARGE-MIB.txt");
        let file = fs::File::create(&mib_path).unwrap();
        file.set_len(MAX_MIB_FILE_BYTES + 1).unwrap();

        let error = MibResolver::from_paths(&[mib_path]).unwrap_err();

        assert!(error.to_string().contains("maximum supported size"));
    }

    #[test]
    fn skips_oversized_mib_files_discovered_in_directories() {
        let temp_dir = tempfile::tempdir().unwrap();
        fs::write(temp_dir.path().join("TEST-MIB.txt"), TEST_MIB).unwrap();
        let file = fs::File::create(temp_dir.path().join("TOO-LARGE-MIB.txt")).unwrap();
        file.set_len(MAX_MIB_FILE_BYTES + 1).unwrap();

        let resolver = MibResolver::from_paths(&[temp_dir.path().to_path_buf()]).unwrap();

        assert_eq!(
            resolver.resolve("1.3.6.1.4.1.8072.2.3.0.1").unwrap().name,
            "TEST-MIB::testTrap"
        );
    }

    #[test]
    fn rejects_too_deep_mib_directories() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut path = temp_dir.path().to_path_buf();
        for index in 0..=MAX_MIB_DIRECTORY_DEPTH {
            path = path.join(format!("level-{index}"));
            fs::create_dir(&path).unwrap();
        }

        let error = MibResolver::from_paths(&[temp_dir.path().to_path_buf()]).unwrap_err();

        assert!(error.to_string().contains("maximum recursive scan depth"));
    }

    #[cfg(unix)]
    #[test]
    fn skips_symlinked_directories() {
        use std::os::unix::fs::symlink;

        let temp_dir = tempfile::tempdir().unwrap();
        let mib_path = temp_dir.path().join("TEST-MIB.txt");
        fs::write(&mib_path, TEST_MIB).unwrap();
        symlink(temp_dir.path(), temp_dir.path().join("loop")).unwrap();

        let resolver = MibResolver::from_paths(&[temp_dir.path().to_path_buf()]).unwrap();

        assert_eq!(
            resolver.resolve("1.3.6.1.4.1.8072.2.3.0.1").unwrap().name,
            "TEST-MIB::testTrap"
        );
    }

    #[cfg(unix)]
    #[test]
    fn follows_symlinked_mib_files() {
        use std::os::unix::fs::symlink;

        let temp_dir = tempfile::tempdir().unwrap();
        let target_path = temp_dir.path().join("TEST-MIB.txt");
        let link_path = temp_dir.path().join("TEST-MIB.my");
        fs::write(&target_path, TEST_MIB).unwrap();
        symlink(&target_path, &link_path).unwrap();

        let resolver = MibResolver::from_paths(&[link_path]).unwrap();

        assert_eq!(
            resolver.resolve("1.3.6.1.4.1.8072.2.3.0.1").unwrap().name,
            "TEST-MIB::testTrap"
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_root_directories() {
        use std::os::unix::fs::symlink;

        let temp_dir = tempfile::tempdir().unwrap();
        let target_dir = temp_dir.path().join("target");
        let link_dir = temp_dir.path().join("link");
        fs::create_dir(&target_dir).unwrap();
        symlink(&target_dir, &link_dir).unwrap();

        let error = MibResolver::from_paths(&[link_dir]).unwrap_err();

        assert!(error.to_string().contains("symlinked directory"));
    }

    #[test]
    fn rejects_missing_mib_paths() {
        let temp_dir = tempfile::tempdir().unwrap();
        let missing = temp_dir.path().join("missing");

        let error = MibResolver::from_paths(&[missing]).unwrap_err();

        assert!(error.to_string().contains("Failed to read MIB path"));
    }

    #[test]
    fn rejects_malformed_numeric_oids() {
        let resolver = MibResolver::with_builtin_symbols();

        for oid in ["", ".", ".1.3.6", "1.3.6.", "1..3.6", "1.3.x"] {
            assert!(resolver.resolve(oid).is_none(), "{oid} should not resolve");
        }
    }

    #[test]
    fn parses_qualified_references_and_ignores_text_blocks() {
        let resolver = MibResolver::from_str(
            r#"
QUALIFIED-MIB DEFINITIONS ::= BEGIN

testRoot OBJECT IDENTIFIER ::= { SNMPv2-SMI::enterprises 8072 } -- trailing comment

testObject OBJECT-TYPE
    SYNTAX Integer32
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "Ignore braces and assignment-looking text: ::= { broken 1 }"
    ::= { QUALIFIED-MIB::testRoot 7 }

END
"#,
        );

        assert_eq!(
            resolver.resolve("1.3.6.1.4.1.8072.7.0").unwrap(),
            OidResolution {
                name: "QUALIFIED-MIB::testObject.0".to_string(),
                module: Some("QUALIFIED-MIB".to_string()),
                symbol: "testObject".to_string(),
                instance: Some("0".to_string()),
            }
        );
    }
}
