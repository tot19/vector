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

/// A reference to another OID value, qualified with the module it is expected to come from when
/// that can be determined from the referencing module's own definitions or its `IMPORTS`.
#[derive(Clone, Debug)]
struct SymbolRef {
    module: Option<String>,
    name: String,
}

#[derive(Clone, Debug)]
enum OidElement {
    Symbol(SymbolRef),
    Number(u32),
    NamedNumber(String, u32),
}

/// Outcome of trying to resolve a definition against the symbols known so far.
enum ElementResolution {
    Resolved(Vec<u32>),
    /// The definition is waiting for the symbol stored under this key to be resolved.
    Waiting(String),
    Invalid,
}

impl MibResolver {
    pub(super) fn from_paths(paths: &[PathBuf]) -> crate::Result<Self> {
        let mut resolver = Self::with_builtin_symbols();
        let mut definitions = Vec::new();

        for path in paths {
            for file in mib_files(path)? {
                match read_mib_file(&file.path) {
                    Ok(contents) => {
                        let parsed = parse_definitions(&contents);
                        if parsed.is_empty() {
                            warn!(
                                message = "MIB file produced no definitions; OID names from this file will not resolve. Verify the file is a valid SMIv1/v2 module.",
                                path = %file.path.display(),
                            );
                        }
                        definitions.extend(parsed);
                    }
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

        let unresolved = resolver.resolve_definitions(definitions);
        for (symbol, definitions) in unresolved {
            let total = definitions.len();
            let mut sample: Vec<String> = definitions
                .into_iter()
                .take(5)
                .map(|definition| match definition.module {
                    Some(module) => format!("{module}::{}", definition.name),
                    None => definition.name,
                })
                .collect();
            if total > sample.len() {
                sample.push(format!("... and {} more", total - sample.len()));
            }
            warn!(
                message = "MIB definitions reference an unresolved symbol; affected names will not resolve. Load the MIB module that defines this symbol.",
                symbol = %symbol,
                affected_definitions = total,
                sample = ?sample,
            );
        }

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

        // Walk the OID's own prefixes from longest to shortest so lookups stay proportional to the
        // OID length rather than to the number of loaded definitions.
        (1..oid.len()).rev().find_map(|prefix_len| {
            let symbol = self.names_by_oid.get(&oid[..prefix_len])?;
            symbol.prefix_resolves.then(|| {
                let instance = oid[prefix_len..]
                    .iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join(".");
                resolution(symbol, Some(instance))
            })
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

    fn resolve_definitions(
        &mut self,
        definitions: Vec<RawDefinition>,
    ) -> HashMap<String, Vec<RawDefinition>> {
        let loaded_modules: HashSet<String> = definitions
            .iter()
            .filter_map(|definition| definition.module.clone())
            .collect();
        let mut state = ResolutionState {
            symbols: self.symbols_by_name(),
            loaded_modules,
            waiting_by_symbol: HashMap::new(),
            ready_symbols: VecDeque::new(),
            strict: true,
        };

        for definition in definitions {
            self.resolve_or_queue_definition(definition, &mut state);
        }
        self.drain_ready_symbols(&mut state);

        // Some modules import a symbol from a module that does not actually define it. Retry
        // whatever is still waiting while allowing references to fall back to any module.
        state.strict = false;
        let waiting: Vec<_> = std::mem::take(&mut state.waiting_by_symbol)
            .into_values()
            .flatten()
            .collect();
        for definition in waiting {
            self.resolve_or_queue_definition(definition, &mut state);
        }
        self.drain_ready_symbols(&mut state);

        state.waiting_by_symbol
    }

    fn drain_ready_symbols(&mut self, state: &mut ResolutionState) {
        while let Some(symbol) = state.ready_symbols.pop_front() {
            let Some(waiting) = state.waiting_by_symbol.remove(&symbol) else {
                continue;
            };

            for definition in waiting {
                self.resolve_or_queue_definition(definition, state);
            }
        }
    }

    fn resolve_or_queue_definition(
        &mut self,
        definition: RawDefinition,
        state: &mut ResolutionState,
    ) {
        match state.resolve_elements(&definition.elements) {
            ElementResolution::Resolved(oid) => {
                state.symbols.insert(definition.name.clone(), oid.clone());
                state.ready_symbols.push_back(definition.name.clone());
                if let Some(module) = &definition.module {
                    let qualified_name = qualified_name(module, &definition.name);
                    state.symbols.insert(qualified_name.clone(), oid.clone());
                    state.ready_symbols.push_back(qualified_name);
                }
                self.names_by_oid.insert(
                    oid,
                    MibSymbol {
                        module: definition.module,
                        name: definition.name,
                        prefix_resolves: definition.prefix_resolves,
                    },
                );
            }
            ElementResolution::Waiting(symbol) => {
                state
                    .waiting_by_symbol
                    .entry(symbol)
                    .or_default()
                    .push(definition);
            }
            ElementResolution::Invalid => {}
        }
    }

    fn symbols_by_name(&self) -> HashMap<String, Vec<u32>> {
        let mut symbols = HashMap::new();
        for (oid, symbol) in &self.names_by_oid {
            symbols.insert(symbol.name.clone(), oid.clone());
            if let Some(module) = &symbol.module {
                symbols.insert(qualified_name(module, &symbol.name), oid.clone());
            }
        }
        symbols
    }

    #[cfg(test)]
    pub(super) fn from_str(contents: &str) -> Self {
        let mut resolver = Self::with_builtin_symbols();
        let _ = resolver.resolve_definitions(parse_definitions(contents));
        resolver
    }
}

struct ResolutionState {
    symbols: HashMap<String, Vec<u32>>,
    loaded_modules: HashSet<String>,
    waiting_by_symbol: HashMap<String, Vec<RawDefinition>>,
    ready_symbols: VecDeque<String>,
    /// When set, a reference qualified with a loaded module only resolves against that module.
    strict: bool,
}

impl ResolutionState {
    /// Looks up a referenced symbol, returning the key to wait on when it is not yet known.
    fn lookup(&self, symbol: &SymbolRef) -> Result<&Vec<u32>, String> {
        if let Some(module) = &symbol.module {
            let qualified = qualified_name(module, &symbol.name);
            if let Some(oid) = self.symbols.get(&qualified) {
                return Ok(oid);
            }
            // Only accept a same-named symbol from another module when the expected module is not
            // being loaded at all (for example, SMIv1 imports from `RFC1155-SMI`).
            if self.strict && self.loaded_modules.contains(module) {
                return Err(qualified);
            }
        }

        self.symbols
            .get(&symbol.name)
            .ok_or_else(|| symbol.name.clone())
    }

    fn resolve_elements(&self, elements: &[OidElement]) -> ElementResolution {
        let mut oid = Vec::new();

        for element in elements {
            match element {
                OidElement::Number(number) => oid.push(*number),
                OidElement::Symbol(symbol) => {
                    let resolved = match self.lookup(symbol) {
                        Ok(resolved) => resolved,
                        Err(key) => return ElementResolution::Waiting(key),
                    };
                    if oid.is_empty() || resolved.starts_with(&oid) {
                        oid.clone_from(resolved);
                    } else {
                        return ElementResolution::Invalid;
                    }
                }
                OidElement::NamedNumber(symbol, number) => {
                    if oid.is_empty()
                        && let Some(resolved) = self.symbols.get(symbol)
                    {
                        oid.clone_from(resolved);
                        if oid.last() != Some(number) {
                            oid.push(*number);
                        }
                    } else {
                        oid.push(*number);
                    }
                }
            }
        }

        if oid.is_empty() {
            ElementResolution::Invalid
        } else {
            ElementResolution::Resolved(oid)
        }
    }
}

fn qualified_name(module: &str, name: &str) -> String {
    format!("{module}::{name}")
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
        return Err(
            format!("MIB path scan exceeded maximum file count of {MAX_MIB_FILE_COUNT}").into(),
        );
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

    // Vendor MIBs frequently contain Latin-1 text in descriptions, so decode lossily instead of
    // rejecting files that are not valid UTF-8.
    let bytes = fs::read(path)
        .map_err(|error| format!("Failed to read MIB file {}: {error}", path.display()))?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn parse_definitions(contents: &str) -> Vec<RawDefinition> {
    let tokens = tokenize(&strip_comments_and_strings(contents));

    // A file can contain several modules; each one starts with `<ModuleName> DEFINITIONS`.
    let module_starts: Vec<usize> = tokens
        .windows(2)
        .enumerate()
        .filter(|(_, window)| window[1] == "DEFINITIONS" && is_module_reference(&window[0]))
        .map(|(index, _)| index)
        .collect();

    if module_starts.is_empty() {
        return parse_module_definitions(None, &tokens);
    }

    module_starts
        .iter()
        .enumerate()
        .flat_map(|(position, &start)| {
            let end = module_starts
                .get(position + 1)
                .copied()
                .unwrap_or(tokens.len());
            parse_module_definitions(Some(tokens[start].clone()), &tokens[start..end])
        })
        .collect()
}

fn parse_module_definitions(module: Option<String>, tokens: &[String]) -> Vec<RawDefinition> {
    let imports = module_imports(tokens);
    let local_names: HashSet<&str> = (0..tokens.len())
        .filter(|&index| {
            is_value_name(&tokens[index]) && oid_definition(tokens, index + 1).is_some()
        })
        .map(|index| tokens[index].as_str())
        .collect();
    let scope = ModuleScope {
        module: module.as_deref(),
        imports: &imports,
        local_names: &local_names,
    };

    let mut definitions = Vec::new();
    for index in 0..tokens.len().saturating_sub(1) {
        if !is_value_name(&tokens[index]) {
            continue;
        }

        let Some(definition) = oid_definition(tokens, index + 1) else {
            continue;
        };

        let elements = match definition {
            OidDefinition::Braced {
                width,
                prefix_resolves: _,
            } => assignment_elements(tokens, index + 1 + width, &scope),
            OidDefinition::TrapType => trap_type_elements(tokens, index + 2, &scope),
        };

        if let Some(elements) = elements {
            definitions.push(RawDefinition {
                module: module.clone(),
                name: tokens[index].clone(),
                prefix_resolves: matches!(
                    definition,
                    OidDefinition::Braced {
                        prefix_resolves: true,
                        ..
                    }
                ),
                elements,
            });
        }
    }

    definitions
}

/// The information needed to qualify symbol references made inside one module.
struct ModuleScope<'a> {
    module: Option<&'a str>,
    imports: &'a HashMap<String, String>,
    local_names: &'a HashSet<&'a str>,
}

impl ModuleScope<'_> {
    fn symbol_ref(&self, name: &str, explicit_module: Option<&str>) -> SymbolRef {
        let module = explicit_module
            .or_else(|| {
                self.local_names
                    .contains(name)
                    .then_some(self.module)
                    .flatten()
            })
            .or_else(|| self.imports.get(name).map(String::as_str));

        SymbolRef {
            module: module.map(str::to_string),
            name: name.to_string(),
        }
    }
}

/// Maps each imported symbol to the module it is imported from.
fn module_imports(tokens: &[String]) -> HashMap<String, String> {
    let mut imports = HashMap::new();
    let Some(start) = tokens.iter().position(|token| token == "IMPORTS") else {
        return imports;
    };

    let mut pending = Vec::new();
    let mut index = start + 1;
    while let Some(token) = tokens.get(index) {
        match token.as_str() {
            ";" => break,
            "FROM" => {
                let Some(module) = tokens.get(index + 1) else {
                    break;
                };
                for symbol in pending.drain(..) {
                    imports.insert(symbol, module.clone());
                }
                index += 1;
            }
            "," => {}
            _ => pending.push(token.clone()),
        }
        index += 1;
    }

    imports
}

fn strip_comments_and_strings(contents: &str) -> String {
    let mut output = String::with_capacity(contents.len());
    let mut chars = contents.chars().peekable();

    while let Some(character) = chars.next() {
        if character == '-' && chars.peek() == Some(&'-') {
            let _ = chars.next();
            // ASN.1 comments end at the end of the line or at the next `--`.
            while let Some(comment_char) = chars.next() {
                if comment_char == '\n' {
                    output.push('\n');
                    break;
                }
                if comment_char == '-' && chars.peek() == Some(&'-') {
                    let _ = chars.next();
                    output.push(' ');
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

#[derive(Clone, Copy, Debug)]
enum OidDefinition {
    /// A definition whose value is a braced OID, `::= { parent 1 }`, starting `width` tokens after
    /// the definition name.
    Braced { width: usize, prefix_resolves: bool },
    /// An SMIv1 `TRAP-TYPE` definition, `ENTERPRISE parent ... ::= 1`.
    TrapType,
}

fn oid_definition(tokens: &[String], index: usize) -> Option<OidDefinition> {
    match tokens.get(index).map(String::as_str) {
        Some("OBJECT-TYPE") => Some(OidDefinition::Braced {
            width: 1,
            prefix_resolves: true,
        }),
        Some("MODULE-IDENTITY" | "OBJECT-IDENTITY" | "NOTIFICATION-TYPE") => {
            Some(OidDefinition::Braced {
                width: 1,
                prefix_resolves: false,
            })
        }
        Some("TRAP-TYPE") => Some(OidDefinition::TrapType),
        Some("OBJECT")
            if tokens
                .get(index + 1)
                .is_some_and(|token| token == "IDENTIFIER") =>
        {
            Some(OidDefinition::Braced {
                width: 2,
                prefix_resolves: false,
            })
        }
        _ => None,
    }
}

fn assignment_elements(
    tokens: &[String],
    start: usize,
    scope: &ModuleScope<'_>,
) -> Option<Vec<OidElement>> {
    let assign_index = tokens
        .get(start..)?
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

    parse_oid_elements(tokens.get(assign_index + 2..end)?, scope)
}

/// Builds the RFC 3584 section 3 notification OID for an SMIv1 `TRAP-TYPE`:
/// `<enterprise>.0.<specific-trap>`.
fn trap_type_elements(
    tokens: &[String],
    start: usize,
    scope: &ModuleScope<'_>,
) -> Option<Vec<OidElement>> {
    let assign_index = tokens
        .get(start..)?
        .iter()
        .position(|token| token == "::=")
        .map(|position| start + position)?;
    let specific_trap = tokens.get(assign_index + 1)?.parse::<u32>().ok()?;

    let clauses = &tokens[start..assign_index];
    let enterprise_index = clauses.iter().position(|token| token == "ENTERPRISE")?;
    let enterprise = clauses.get(enterprise_index + 1)?;
    let enterprise = if enterprise == "{" {
        let end = clauses[enterprise_index + 2..]
            .iter()
            .position(|token| token == "}")
            .map(|position| enterprise_index + 2 + position)?;
        parse_oid_elements(&clauses[enterprise_index + 2..end], scope)?
    } else if is_value_name(enterprise) {
        vec![OidElement::Symbol(scope.symbol_ref(enterprise, None))]
    } else {
        return None;
    };

    let mut elements = enterprise;
    elements.push(OidElement::Number(0));
    elements.push(OidElement::Number(specific_trap));
    Some(elements)
}

fn parse_oid_elements(tokens: &[String], scope: &ModuleScope<'_>) -> Option<Vec<OidElement>> {
    let mut elements = Vec::new();
    let mut index = 0;
    // A module reference such as `SNMPv2-SMI` in `{ SNMPv2-SMI::enterprises 1 }` qualifies the
    // symbol that follows it.
    let mut explicit_module = None;

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
        } else if is_module_reference(token) && explicit_module.is_none() {
            explicit_module = Some(token.as_str());
            index += 1;
            continue;
        } else if is_value_name(token) {
            elements.push(OidElement::Symbol(
                scope.symbol_ref(token, explicit_module.take()),
            ));
            index += 1;
        } else {
            return None;
        }

        if explicit_module.is_some() {
            // A module reference must be immediately followed by the symbol it qualifies.
            return None;
        }
    }

    (explicit_module.is_none()).then_some(elements)
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
        qualified_name(module, &symbol.name)
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

/// ASN.1 value references (OID names) start with a lowercase letter.
fn is_value_name(token: &str) -> bool {
    token.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
}

/// ASN.1 module and type references start with an uppercase letter.
fn is_module_reference(token: &str) -> bool {
    token.as_bytes().first().is_some_and(u8::is_ascii_uppercase)
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

    #[test]
    fn parse_returns_empty_for_non_mib_content() {
        let parsed = parse_definitions("this is just a README file, not a MIB module at all.\n");
        assert!(
            parsed.is_empty(),
            "expected no definitions from non-MIB text, got {} definition(s)",
            parsed.len()
        );
    }

    #[test]
    fn resolve_definitions_returns_unresolved_imports() {
        let mut resolver = MibResolver::with_builtin_symbols();
        let definitions = parse_definitions(
            r#"
NEEDS-IMPORT-MIB DEFINITIONS ::= BEGIN

dependentObject OBJECT IDENTIFIER ::= { unknownSymbol 1 }

END
"#,
        );

        let unresolved = resolver.resolve_definitions(definitions);

        let stuck = unresolved
            .get("unknownSymbol")
            .expect("unknownSymbol should appear in the unresolved map");
        assert_eq!(stuck.len(), 1);
        assert_eq!(stuck[0].name, "dependentObject");
    }

    #[test]
    fn from_paths_keeps_loading_when_a_file_is_not_a_mib() {
        let temp_dir = tempfile::tempdir().unwrap();
        fs::write(temp_dir.path().join("VALID-MIB.txt"), TEST_MIB).unwrap();
        fs::write(
            temp_dir.path().join("NOT-A-MIB.txt"),
            "just some plain text, no MIB module here\n",
        )
        .unwrap();

        let resolver = MibResolver::from_paths(&[temp_dir.path().to_path_buf()]).unwrap();

        assert_eq!(
            resolver.resolve("1.3.6.1.4.1.8072.2.3.0.1").unwrap().name,
            "TEST-MIB::testTrap"
        );
    }

    #[test]
    fn from_paths_keeps_loading_when_a_definition_has_an_unknown_import() {
        let temp_dir = tempfile::tempdir().unwrap();
        fs::write(temp_dir.path().join("VALID-MIB.txt"), TEST_MIB).unwrap();
        fs::write(
            temp_dir.path().join("DEPENDS-ON-MISSING.txt"),
            r#"
DEPENDS-ON-MISSING DEFINITIONS ::= BEGIN

needsMissing OBJECT IDENTIFIER ::= { unloadedRoot 99 }

END
"#,
        )
        .unwrap();

        let resolver = MibResolver::from_paths(&[temp_dir.path().to_path_buf()]).unwrap();

        assert_eq!(
            resolver.resolve("1.3.6.1.4.1.8072.2.3.0.1").unwrap().name,
            "TEST-MIB::testTrap"
        );
    }

    #[test]
    fn cross_mib_imports_resolution() {
        let temp_dir = tempfile::tempdir().unwrap();

        // MIB-A defines a root object under enterprises
        fs::write(
            temp_dir.path().join("MIB-A.txt"),
            r#"
MIB-A DEFINITIONS ::= BEGIN

IMPORTS
    enterprises
        FROM SNMPv2-SMI;

vendorRoot OBJECT IDENTIFIER ::= { enterprises 99999 }

END
"#,
        )
        .unwrap();

        // MIB-B references vendorRoot defined in MIB-A
        fs::write(
            temp_dir.path().join("MIB-B.txt"),
            r#"
MIB-B DEFINITIONS ::= BEGIN

IMPORTS
    OBJECT-TYPE
        FROM SNMPv2-SMI;

deviceStatus OBJECT-TYPE
    SYNTAX Integer32
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "Device status."
    ::= { vendorRoot 1 }

END
"#,
        )
        .unwrap();

        let resolver = MibResolver::from_paths(&[temp_dir.path().to_path_buf()]).unwrap();

        // vendorRoot = enterprises.99999 = 1.3.6.1.4.1.99999
        assert_eq!(
            resolver.resolve("1.3.6.1.4.1.99999").unwrap().name,
            "MIB-A::vendorRoot"
        );

        // deviceStatus = vendorRoot.1 = 1.3.6.1.4.1.99999.1
        let resolution = resolver.resolve("1.3.6.1.4.1.99999.1.0").unwrap();
        assert_eq!(resolution.name, "MIB-B::deviceStatus.0");
        assert_eq!(resolution.module.as_deref(), Some("MIB-B"));
        assert_eq!(resolution.symbol, "deviceStatus");
        assert_eq!(resolution.instance.as_deref(), Some("0"));
    }

    #[test]
    fn same_name_in_different_modules_resolves_both() {
        let temp_dir = tempfile::tempdir().unwrap();
        for (module, number) in [("FIRST-MIB", 11111), ("SECOND-MIB", 22222)] {
            fs::write(
                temp_dir.path().join(format!("{module}.txt")),
                format!(
                    "{module} DEFINITIONS ::= BEGIN\n\
                     IMPORTS enterprises FROM SNMPv2-SMI;\n\
                     sharedName OBJECT IDENTIFIER ::= {{ enterprises {number} }}\n\
                     childName OBJECT IDENTIFIER ::= {{ sharedName 1 }}\n\
                     END\n"
                ),
            )
            .unwrap();
        }

        let resolver = MibResolver::from_paths(&[temp_dir.path().to_path_buf()]).unwrap();

        assert_eq!(
            resolver.resolve("1.3.6.1.4.1.11111.1").unwrap().name,
            "FIRST-MIB::childName"
        );
        assert_eq!(
            resolver.resolve("1.3.6.1.4.1.22222.1").unwrap().name,
            "SECOND-MIB::childName"
        );
    }

    #[test]
    fn syntax_object_identifier_does_not_shadow_object_name() {
        let resolver = MibResolver::from_str(
            r#"
PTR-MIB DEFINITIONS ::= BEGIN
ptrRoot OBJECT IDENTIFIER ::= { enterprises 99 }
ptrValue OBJECT-TYPE
    SYNTAX OBJECT IDENTIFIER
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "An object whose syntax is an OID."
    ::= { ptrRoot 1 }
END
"#,
        );

        assert_eq!(
            resolver.resolve("1.3.6.1.4.1.99.1.0").unwrap().name,
            "PTR-MIB::ptrValue.0"
        );
    }

    #[test]
    fn waits_for_hyphenated_parent_defined_later() {
        let resolver = MibResolver::from_str(
            r#"
HYPHEN-MIB DEFINITIONS ::= BEGIN
childNode OBJECT IDENTIFIER ::= { acme-root 5 }
acme-root OBJECT IDENTIFIER ::= { enterprises 77 }
END
"#,
        );

        assert!(resolver.resolve("5").is_none());
        assert_eq!(
            resolver.resolve("1.3.6.1.4.1.77.5").unwrap().name,
            "HYPHEN-MIB::childNode"
        );
    }

    #[test]
    fn resolves_references_within_the_referencing_module() {
        let resolver = MibResolver::from_str(
            r#"
FIRST-MIB DEFINITIONS ::= BEGIN
firstThing OBJECT IDENTIFIER ::= { root 1 }
root OBJECT IDENTIFIER ::= { enterprises 1 }
END

SECOND-MIB DEFINITIONS ::= BEGIN
root OBJECT IDENTIFIER ::= { enterprises 2 }
END

THIRD-MIB DEFINITIONS ::= BEGIN
IMPORTS root FROM FIRST-MIB;
thirdThing OBJECT IDENTIFIER ::= { root 3 }
END
"#,
        );

        assert_eq!(
            resolver.resolve("1.3.6.1.4.1.1.1").unwrap().name,
            "FIRST-MIB::firstThing"
        );
        assert_eq!(
            resolver.resolve("1.3.6.1.4.1.1.3").unwrap().name,
            "THIRD-MIB::thirdThing"
        );
        assert!(resolver.resolve("1.3.6.1.4.1.2.1").is_none());
    }

    #[test]
    fn resolves_smiv1_trap_type_definitions() {
        let resolver = MibResolver::from_str(
            r#"
V1-MIB DEFINITIONS ::= BEGIN
IMPORTS enterprises FROM RFC1155-SMI
        TRAP-TYPE FROM RFC-1215;
v1Root OBJECT IDENTIFIER ::= { enterprises 4 }
v1Trap TRAP-TYPE
    ENTERPRISE v1Root
    VARIABLES { v1Root }
    DESCRIPTION "An enterprise-specific trap."
    ::= 7
END
"#,
        );

        assert_eq!(
            resolver.resolve("1.3.6.1.4.1.4.0.7").unwrap().name,
            "V1-MIB::v1Trap"
        );
    }

    #[test]
    fn comments_can_end_before_the_end_of_line() {
        let resolver = MibResolver::from_str(
            "COMMENT-MIB DEFINITIONS ::= BEGIN\n\
             commentRoot OBJECT IDENTIFIER -- inline -- ::= { enterprises 6 }\n\
             END\n",
        );

        assert_eq!(
            resolver.resolve("1.3.6.1.4.1.6").unwrap().name,
            "COMMENT-MIB::commentRoot"
        );
    }

    #[test]
    fn loads_mib_files_that_are_not_utf8() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mib_path = temp_dir.path().join("LATIN1-MIB.txt");
        let mut contents =
            b"LATIN1-MIB DEFINITIONS ::= BEGIN\nlatinRoot OBJECT IDENTIFIER ::= { enterprises 5 }\n-- caf"
                .to_vec();
        contents.push(0xe9);
        contents.extend_from_slice(b"\nEND\n");
        fs::write(&mib_path, contents).unwrap();

        let resolver = MibResolver::from_paths(&[mib_path]).unwrap();

        assert_eq!(
            resolver.resolve("1.3.6.1.4.1.5").unwrap().name,
            "LATIN1-MIB::latinRoot"
        );
    }

    #[test]
    fn prefix_lookup_does_not_scan_unrelated_definitions() {
        let mut contents = String::from(
            "BULK-MIB DEFINITIONS ::= BEGIN\nbulkRoot OBJECT IDENTIFIER ::= { enterprises 3 }\n",
        );
        for index in 0..50_000 {
            contents.push_str(&format!(
                "bulk{index} OBJECT IDENTIFIER ::= {{ bulkRoot {index} }}\n"
            ));
        }
        contents.push_str("END\n");
        let resolver = MibResolver::from_str(&contents);

        let started = std::time::Instant::now();
        for _ in 0..10_000 {
            assert!(resolver.resolve("1.3.6.1.4.1.3.99999999.1").is_none());
        }
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "unresolved lookups took {:?}",
            started.elapsed()
        );
    }
}
