use super::display::{BaseSyntax, ValueSyntax};
use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

const MAX_MIB_FILE_COUNT: usize = 16_384;
const MAX_MIB_DIRECTORY_DEPTH: usize = 32;
const MAX_MIB_FILE_BYTES: u64 = 8 * 1024 * 1024;
const MIB_FILE_EXTENSIONS: &[&str] = &["mib", "my", "smi", "txt"];
/// Textual conventions are resolved through at most this many levels of indirection.
const MAX_TYPE_DEPTH: usize = 16;

/// Core SNMPv2-TC (RFC 2579) textual conventions, used when SNMPv2-TC itself is not loaded, so that
/// common types display like Net-SNMP, which always has this module loaded.
const BUILTIN_TEXTUAL_CONVENTIONS: &str = r#"
SNMPv2-TC DEFINITIONS ::= BEGIN
DisplayString ::= TEXTUAL-CONVENTION DISPLAY-HINT "255a" SYNTAX OCTET STRING
PhysAddress ::= TEXTUAL-CONVENTION DISPLAY-HINT "1x:" SYNTAX OCTET STRING
MacAddress ::= TEXTUAL-CONVENTION DISPLAY-HINT "1x:" SYNTAX OCTET STRING
TruthValue ::= TEXTUAL-CONVENTION SYNTAX INTEGER { true(1), false(2) }
TestAndIncr ::= TEXTUAL-CONVENTION SYNTAX INTEGER
AutonomousType ::= TEXTUAL-CONVENTION SYNTAX OBJECT IDENTIFIER
InstancePointer ::= TEXTUAL-CONVENTION SYNTAX OBJECT IDENTIFIER
VariablePointer ::= TEXTUAL-CONVENTION SYNTAX OBJECT IDENTIFIER
RowPointer ::= TEXTUAL-CONVENTION SYNTAX OBJECT IDENTIFIER
RowStatus ::= TEXTUAL-CONVENTION SYNTAX INTEGER { active(1), notInService(2), notReady(3),
    createAndGo(4), createAndWait(5), destroy(6) }
TimeStamp ::= TEXTUAL-CONVENTION SYNTAX TimeTicks
TimeInterval ::= TEXTUAL-CONVENTION SYNTAX INTEGER
DateAndTime ::= TEXTUAL-CONVENTION DISPLAY-HINT "2d-1d-1d,1d:1d:1d.1d,1a1d:1d" SYNTAX OCTET STRING
StorageType ::= TEXTUAL-CONVENTION SYNTAX INTEGER { other(1), volatile(2), nonVolatile(3),
    permanent(4), readOnly(5) }
TDomain ::= TEXTUAL-CONVENTION SYNTAX OBJECT IDENTIFIER
TAddress ::= TEXTUAL-CONVENTION SYNTAX OCTET STRING
END
"#;

#[derive(Clone, Debug, Default)]
pub(super) struct MibResolver {
    names_by_oid: BTreeMap<Vec<u32>, MibSymbol>,
}

#[derive(Clone, Debug)]
struct MibSymbol {
    module: Option<String>,
    name: String,
    /// Whether the defining module uses SMIv2 (has a `MODULE-IDENTITY`).
    smiv2: bool,
    /// The modules the defining module imports from.
    dependencies: Arc<HashSet<String>>,
    /// The value syntax of an `OBJECT-TYPE`.
    syntax: Option<Arc<ValueSyntax>>,
}

impl MibSymbol {
    /// Decides which definition names an OID that several modules define, following Net-SNMP:
    /// SMIv2 modules such as IF-MIB supersede SMIv1 modules such as RFC1213-MIB, a module never
    /// overrides a definition from a module it imports, and otherwise the first definition wins.
    fn supersedes(&self, existing: &MibSymbol) -> bool {
        if self.smiv2 != existing.smiv2 {
            return self.smiv2;
        }
        self.module
            .as_ref()
            .is_some_and(|module| existing.dependencies.contains(module))
    }
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
    smiv2: bool,
    dependencies: Arc<HashSet<String>>,
    elements: Vec<OidElement>,
    syntax: Option<SyntaxSpec>,
    /// The `UNITS` of an `OBJECT-TYPE`.
    units: Option<String>,
}

/// The definitions and type assignments parsed from MIB files.
#[derive(Debug, Default)]
struct ParsedMib {
    definitions: Vec<RawDefinition>,
    types: Vec<RawType>,
}

impl ParsedMib {
    fn extend(&mut self, other: ParsedMib) {
        self.definitions.extend(other.definitions);
        self.types.extend(other.types);
    }
}

/// A type assignment, such as a `TEXTUAL-CONVENTION` or `DisplayString ::= OCTET STRING`.
#[derive(Clone, Debug)]
struct RawType {
    module: Option<String>,
    name: String,
    display_hint: Option<String>,
    syntax: SyntaxSpec,
}

/// A `SYNTAX` clause before textual conventions are resolved.
#[derive(Clone, Debug)]
struct SyntaxSpec {
    kind: SyntaxKind,
    named_numbers: Vec<(i64, String)>,
}

#[derive(Clone, Debug)]
enum SyntaxKind {
    Base(BaseSyntax),
    Type(SymbolRef),
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
        let mut parsed_mibs = ParsedMib::default();

        for path in paths {
            for file in mib_files(path)? {
                match read_mib_file(&file.path) {
                    Ok(contents) => {
                        let parsed = parse_definitions(&contents);
                        if parsed.definitions.is_empty() && parsed.types.is_empty() {
                            warn!(
                                message = "MIB file produced no definitions; OID names from this file will not resolve. Verify the file is a valid SMIv1/v2 module.",
                                path = %file.path.display(),
                            );
                        }
                        parsed_mibs.extend(parsed);
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

        let unresolved = resolver.resolve_definitions(parsed_mibs);
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
        resolver.insert_builtin("SNMPv2-SMI", "ccitt", &[0]);
        resolver.insert_builtin("SNMPv2-SMI", "iso", &[1]);
        resolver.insert_builtin("SNMPv2-SMI", "joint-iso-ccitt", &[2]);
        resolver.insert_builtin("SNMPv2-SMI", "org", &[1, 3]);
        resolver.insert_builtin("SNMPv2-SMI", "dod", &[1, 3, 6]);
        resolver.insert_builtin("SNMPv2-SMI", "internet", &[1, 3, 6, 1]);
        resolver.insert_builtin("SNMPv2-SMI", "directory", &[1, 3, 6, 1, 1]);
        resolver.insert_builtin("SNMPv2-SMI", "mgmt", &[1, 3, 6, 1, 2]);
        resolver.insert_builtin("SNMPv2-SMI", "mib-2", &[1, 3, 6, 1, 2, 1]);
        resolver.insert_builtin("SNMPv2-SMI", "experimental", &[1, 3, 6, 1, 3]);
        resolver.insert_builtin("SNMPv2-SMI", "private", &[1, 3, 6, 1, 4]);
        resolver.insert_builtin("SNMPv2-SMI", "enterprises", &[1, 3, 6, 1, 4, 1]);
        resolver.insert_builtin("SNMPv2-SMI", "security", &[1, 3, 6, 1, 5]);
        resolver.insert_builtin("SNMPv2-SMI", "snmpV2", &[1, 3, 6, 1, 6]);
        resolver.insert_builtin("SNMPv2-SMI", "snmpModules", &[1, 3, 6, 1, 6, 3]);
        resolver.insert_builtin("SNMPv2-MIB", "system", &[1, 3, 6, 1, 2, 1, 1]);
        resolver.insert_builtin("SNMPv2-MIB", "sysUpTime", &[1, 3, 6, 1, 2, 1, 1, 3]);
        resolver.insert_builtin("SNMPv2-MIB", "snmpTrap", &[1, 3, 6, 1, 6, 3, 1, 1, 4]);
        resolver.insert_builtin("SNMPv2-MIB", "snmpTrapOID", &[1, 3, 6, 1, 6, 3, 1, 1, 4, 1]);
        resolver.insert_builtin("SNMPv2-MIB", "snmpTraps", &[1, 3, 6, 1, 6, 3, 1, 1, 5]);
        resolver.insert_builtin("SNMPv2-MIB", "coldStart", &[1, 3, 6, 1, 6, 3, 1, 1, 5, 1]);
        resolver.insert_builtin("SNMPv2-MIB", "warmStart", &[1, 3, 6, 1, 6, 3, 1, 1, 5, 2]);
        resolver.insert_builtin("IF-MIB", "linkDown", &[1, 3, 6, 1, 6, 3, 1, 1, 5, 3]);
        resolver.insert_builtin("IF-MIB", "linkUp", &[1, 3, 6, 1, 6, 3, 1, 1, 5, 4]);
        resolver.insert_builtin(
            "SNMPv2-MIB",
            "authenticationFailure",
            &[1, 3, 6, 1, 6, 3, 1, 1, 5, 5],
        );
        resolver
    }

    pub(super) fn resolve(&self, oid: &str) -> Option<OidResolution> {
        let (symbol, instance) = self.lookup(oid)?;
        Some(resolution(symbol, instance))
    }

    /// Returns the value syntax of the object that an OID names, such as `IF-MIB::ifOperStatus`
    /// for `1.3.6.1.2.1.2.2.1.8.3`.
    pub(super) fn value_syntax(&self, oid: &str) -> Option<Arc<ValueSyntax>> {
        self.lookup(oid)?.0.syntax.clone()
    }

    fn lookup(&self, oid: &str) -> Option<(&MibSymbol, Option<String>)> {
        let oid = parse_numeric_oid(oid)?;

        if let Some(symbol) = self.names_by_oid.get(&oid) {
            return Some((symbol, None));
        }

        // Like Net-SNMP, name the OID after its longest known prefix and append the remaining
        // arcs, for example `SNMPv2-SMI::enterprises.8072.1`. Walking the OID's own prefixes keeps
        // lookups proportional to the OID length rather than to the number of loaded definitions.
        (1..oid.len()).rev().find_map(|prefix_len| {
            let symbol = self.names_by_oid.get(&oid[..prefix_len])?;
            let instance = oid[prefix_len..]
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(".");
            Some((symbol, Some(instance)))
        })
    }

    fn insert_builtin(&mut self, module: &str, name: &str, oid: &[u32]) {
        self.names_by_oid.insert(
            oid.to_vec(),
            MibSymbol {
                module: Some(module.to_string()),
                name: name.to_string(),
                smiv2: true,
                dependencies: Arc::default(),
                syntax: None,
            },
        );
    }

    fn resolve_definitions(&mut self, parsed: ParsedMib) -> HashMap<String, Vec<RawDefinition>> {
        let ParsedMib { definitions, types } = parsed;
        let loaded_modules: HashSet<String> = definitions
            .iter()
            .filter_map(|definition| definition.module.clone())
            .collect();
        let mut state = ResolutionState {
            types: TypeTable::new(types),
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
                let syntax = definition.syntax.as_ref().map(|syntax| {
                    Arc::new(ValueSyntax {
                        units: definition.units.clone(),
                        ..state.types.resolve(syntax)
                    })
                });
                let symbol = MibSymbol {
                    module: definition.module,
                    name: definition.name,
                    smiv2: definition.smiv2,
                    dependencies: definition.dependencies,
                    syntax,
                };
                let replace = self
                    .names_by_oid
                    .get(&oid)
                    .is_none_or(|existing| symbol.supersedes(existing));
                if replace {
                    self.names_by_oid.insert(oid, symbol);
                }
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
    types: TypeTable,
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
                    // A symbolic arc after other arcs must extend the OID built so far.
                    if resolved.starts_with(&oid) {
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

/// Type assignments from all loaded MIBs, keyed by qualified and bare type name.
struct TypeTable {
    types: HashMap<String, RawType>,
}

impl TypeTable {
    fn new(types: Vec<RawType>) -> Self {
        let mut table = HashMap::new();
        let builtin = parse_definitions(BUILTIN_TEXTUAL_CONVENTIONS).types;
        for raw_type in builtin.into_iter().chain(types) {
            // Bare names keep the first definition, while loaded modules replace the built-in
            // SNMPv2-TC definitions under their qualified names.
            table
                .entry(raw_type.name.clone())
                .or_insert_with(|| raw_type.clone());
            if let Some(module) = &raw_type.module {
                table.insert(qualified_name(module, &raw_type.name), raw_type);
            }
        }
        Self { types: table }
    }

    fn get(&self, reference: &SymbolRef) -> Option<&RawType> {
        reference
            .module
            .as_ref()
            .and_then(|module| self.types.get(&qualified_name(module, &reference.name)))
            .or_else(|| self.types.get(&reference.name))
    }

    /// Resolves textual conventions down to a base syntax. The outermost display hint and named
    /// numbers win, so refinements such as `SYNTAX InetAddressType { ipv4(1) }` apply.
    fn resolve(&self, syntax: &SyntaxSpec) -> ValueSyntax {
        let mut named_numbers = syntax.named_numbers.clone();
        let mut display_hint = None;
        let mut kind = syntax.kind.clone();

        for _ in 0..MAX_TYPE_DEPTH {
            match kind {
                SyntaxKind::Base(base) => {
                    return ValueSyntax {
                        base,
                        named_numbers,
                        display_hint,
                        units: None,
                    };
                }
                SyntaxKind::Type(reference) => {
                    let Some(raw_type) = self.get(&reference) else {
                        break;
                    };
                    if display_hint.is_none() {
                        display_hint.clone_from(&raw_type.display_hint);
                    }
                    if named_numbers.is_empty() {
                        named_numbers.clone_from(&raw_type.syntax.named_numbers);
                    }
                    kind = raw_type.syntax.kind.clone();
                }
            }
        }

        // Unknown or circular types are displayed from the value alone.
        ValueSyntax {
            base: BaseSyntax::Opaque,
            named_numbers: Vec::new(),
            display_hint: None,
            units: None,
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

fn parse_definitions(contents: &str) -> ParsedMib {
    let tokens = tokenize(contents);

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

    let mut parsed = ParsedMib::default();
    for (position, &start) in module_starts.iter().enumerate() {
        let end = module_starts
            .get(position + 1)
            .copied()
            .unwrap_or(tokens.len());
        parsed.extend(parse_module_definitions(
            Some(tokens[start].clone()),
            &tokens[start..end],
        ));
    }
    parsed
}

fn parse_module_definitions(module: Option<String>, tokens: &[String]) -> ParsedMib {
    let imports = module_imports(tokens);
    let smiv2 = tokens.iter().any(|token| token == "MODULE-IDENTITY");
    let dependencies: Arc<HashSet<String>> = Arc::new(imports.values().cloned().collect());
    let local_names: HashSet<&str> = (0..tokens.len())
        .filter(|&index| {
            is_value_name(&tokens[index]) && oid_definition(tokens, index + 1).is_some()
        })
        .map(|index| tokens[index].as_str())
        .collect();
    let local_types: HashSet<&str> = (0..tokens.len())
        .filter(|&index| is_type_assignment(tokens, index))
        .map(|index| tokens[index].as_str())
        .collect();
    let scope = ModuleScope {
        module: module.as_deref(),
        imports: &imports,
        local_names: &local_names,
        local_types: &local_types,
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
            OidDefinition::Braced => assignment_elements(tokens, index + 1, &scope),
            OidDefinition::TrapType => trap_type_elements(tokens, index + 1, &scope),
        };
        let object_type = tokens[index + 1] == "OBJECT-TYPE";
        let syntax = object_type
            .then(|| object_type_syntax(tokens, index + 2, &scope))
            .flatten();
        let units = object_type
            .then(|| object_type_units(tokens, index + 2))
            .flatten();

        if let Some(elements) = elements {
            definitions.push(RawDefinition {
                module: module.clone(),
                name: tokens[index].clone(),
                smiv2,
                dependencies: Arc::clone(&dependencies),
                elements,
                syntax,
                units,
            });
        }
    }

    let types = (0..tokens.len())
        .filter(|&index| is_type_assignment(tokens, index))
        .filter_map(|index| type_assignment(tokens, index, module.as_deref(), &scope))
        .collect();

    ParsedMib { definitions, types }
}

/// Whether the token at `index` starts a type assignment such as `DisplayString ::= ...`.
fn is_type_assignment(tokens: &[String], index: usize) -> bool {
    is_module_reference(&tokens[index]) && tokens.get(index + 1).is_some_and(|token| token == "::=")
}

fn type_assignment(
    tokens: &[String],
    index: usize,
    module: Option<&str>,
    scope: &ModuleScope<'_>,
) -> Option<RawType> {
    let body = index + 2;
    let (display_hint, syntax) = if tokens.get(body)? == "TEXTUAL-CONVENTION" {
        let end = next_definition(tokens, body + 1);
        let clauses = &tokens[body + 1..end];
        let display_hint = clauses
            .iter()
            .position(|token| token == "DISPLAY-HINT")
            .and_then(|position| clauses.get(position + 1))
            .and_then(|token| string_token(token))
            .map(str::to_string);
        let syntax_index = clauses.iter().position(|token| token == "SYNTAX")?;
        (
            display_hint,
            parse_syntax(clauses, syntax_index + 1, scope)?,
        )
    } else {
        (None, parse_syntax(tokens, body, scope)?)
    };

    Some(RawType {
        module: module.map(str::to_string),
        name: tokens[index].clone(),
        display_hint,
        syntax,
    })
}

/// Parses the `SYNTAX` clause of an `OBJECT-TYPE` whose clauses start at `start`.
fn object_type_syntax(
    tokens: &[String],
    start: usize,
    scope: &ModuleScope<'_>,
) -> Option<SyntaxSpec> {
    let end = tokens[start..]
        .iter()
        .position(|token| token == "::=")
        .map_or(tokens.len(), |position| start + position);
    let clauses = &tokens[start..end];
    let syntax_index = clauses.iter().position(|token| token == "SYNTAX")?;
    parse_syntax(clauses, syntax_index + 1, scope)
}

/// Returns the `UNITS` of an `OBJECT-TYPE` whose clauses start at `start`.
fn object_type_units(tokens: &[String], start: usize) -> Option<String> {
    let clauses = &tokens[start..next_definition(tokens, start)];
    clauses
        .iter()
        .position(|token| token == "UNITS")
        .and_then(|position| clauses.get(position + 1))
        .and_then(|token| string_token(token))
        .map(str::to_string)
}

/// Returns the index of the next `::=` assignment, which bounds the clauses of a macro such as
/// `TEXTUAL-CONVENTION`.
fn next_definition(tokens: &[String], start: usize) -> usize {
    tokens[start..]
        .iter()
        .position(|token| token == "::=")
        .map_or(tokens.len(), |position| start + position)
}

fn parse_syntax(tokens: &[String], start: usize, scope: &ModuleScope<'_>) -> Option<SyntaxSpec> {
    let token = tokens.get(start)?.as_str();
    let next = tokens.get(start + 1).map(String::as_str);
    let (kind, rest) = match (token, next) {
        ("INTEGER" | "Integer32", _) => (SyntaxKind::Base(BaseSyntax::Integer), start + 1),
        ("Unsigned32" | "Gauge32" | "Gauge", _) => {
            (SyntaxKind::Base(BaseSyntax::Unsigned), start + 1)
        }
        ("Counter32" | "Counter64" | "Counter", _) => {
            (SyntaxKind::Base(BaseSyntax::Counter), start + 1)
        }
        ("TimeTicks", _) => (SyntaxKind::Base(BaseSyntax::TimeTicks), start + 1),
        ("IpAddress", _) => (SyntaxKind::Base(BaseSyntax::IpAddress), start + 1),
        ("NetworkAddress", _) => (SyntaxKind::Base(BaseSyntax::NetworkAddress), start + 1),
        ("Opaque", _) => (SyntaxKind::Base(BaseSyntax::Opaque), start + 1),
        ("BITS", _) => (SyntaxKind::Base(BaseSyntax::Bits), start + 1),
        ("OCTET", Some("STRING")) => (SyntaxKind::Base(BaseSyntax::OctetString), start + 2),
        ("OBJECT", Some("IDENTIFIER")) => {
            (SyntaxKind::Base(BaseSyntax::ObjectIdentifier), start + 2)
        }
        ("SEQUENCE" | "CHOICE", _) => return None,
        (token, Some(name))
            if is_module_reference(token)
                && is_module_reference(name)
                && scope.is_module(token) =>
        {
            (
                SyntaxKind::Type(scope.type_ref(name, Some(token))),
                start + 2,
            )
        }
        (token, _) if is_module_reference(token) => {
            (SyntaxKind::Type(scope.type_ref(token, None)), start + 1)
        }
        _ => return None,
    };

    let named_numbers = if tokens.get(rest).is_some_and(|token| token == "{") {
        parse_named_numbers(&tokens[rest + 1..])
    } else {
        Vec::new()
    };

    Some(SyntaxSpec {
        kind,
        named_numbers,
    })
}

/// Parses `name(number), ...` up to the closing brace of an enumeration or BITS definition.
fn parse_named_numbers(tokens: &[String]) -> Vec<(i64, String)> {
    let mut named_numbers = Vec::new();
    let mut index = 0;
    while let Some(token) = tokens.get(index) {
        if token == "}" {
            break;
        }
        if is_value_name(token)
            && tokens.get(index + 1).is_some_and(|token| token == "(")
            && let Some(number) = tokens.get(index + 2).and_then(|token| token.parse().ok())
            && tokens.get(index + 3).is_some_and(|token| token == ")")
        {
            named_numbers.push((number, token.clone()));
            index += 4;
        } else {
            index += 1;
        }
    }
    named_numbers
}

/// Returns the contents of a quoted string token.
fn string_token(token: &str) -> Option<&str> {
    token.strip_prefix('"')
}

/// The information needed to qualify symbol references made inside one module.
struct ModuleScope<'a> {
    module: Option<&'a str>,
    imports: &'a HashMap<String, String>,
    local_names: &'a HashSet<&'a str>,
    local_types: &'a HashSet<&'a str>,
}

impl ModuleScope<'_> {
    fn type_ref(&self, name: &str, explicit_module: Option<&str>) -> SymbolRef {
        let module = explicit_module
            .or_else(|| {
                self.local_types
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

    /// Whether a token names a module this module refers to, as in `SNMPv2-TC.DisplayString`.
    fn is_module(&self, token: &str) -> bool {
        self.module == Some(token) || self.imports.values().any(|module| module == token)
    }

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

/// Splits MIB source into tokens. Comments are dropped, and each quoted string becomes a single
/// token that starts with `"` and holds the string's contents, so text inside descriptions is
/// never mistaken for definitions.
fn tokenize(contents: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut chars = contents.chars().peekable();

    while let Some(character) = chars.next() {
        if character == '-' && chars.peek() == Some(&'-') {
            let _ = chars.next();
            // ASN.1 comments end at the end of the line or at the next `--`.
            while let Some(comment_char) = chars.next() {
                if comment_char == '\n' {
                    break;
                }
                if comment_char == '-' && chars.peek() == Some(&'-') {
                    let _ = chars.next();
                    break;
                }
            }
        } else if character == '"' {
            let mut token = String::from('"');
            for string_char in chars.by_ref() {
                if string_char == '"' {
                    break;
                }
                token.push(string_char);
            }
            tokens.push(token);
        } else if character.is_ascii_alphanumeric() || character == '_' || character == '-' {
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
    /// A definition whose value is a braced OID, `::= { parent 1 }`.
    Braced,
    /// An SMIv1 `TRAP-TYPE` definition, `ENTERPRISE parent ... ::= 1`.
    TrapType,
}

fn oid_definition(tokens: &[String], index: usize) -> Option<OidDefinition> {
    match tokens.get(index).map(String::as_str) {
        Some("OBJECT-TYPE") => Some(OidDefinition::Braced),
        Some(
            "MODULE-IDENTITY" | "OBJECT-IDENTITY" | "NOTIFICATION-TYPE" | "OBJECT-GROUP"
            | "NOTIFICATION-GROUP" | "MODULE-COMPLIANCE" | "AGENT-CAPABILITIES",
        ) => Some(OidDefinition::Braced),
        Some("TRAP-TYPE") => Some(OidDefinition::TrapType),
        // A value assignment is immediately followed by `::=`. This also skips SEQUENCE members
        // such as `ifSpecific OBJECT IDENTIFIER,` in a table's row type.
        Some("OBJECT")
            if tokens
                .get(index + 1)
                .is_some_and(|token| token == "IDENTIFIER")
                && tokens.get(index + 2).is_some_and(|token| token == "::=") =>
        {
            Some(OidDefinition::Braced)
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
        assert_eq!(
            resolver.resolve("1.3.6.1.4.1.8072.2.3.2.1").unwrap().name,
            "TEST-MIB::testNotificationPrefix.2.1"
        );
    }

    #[test]
    fn resolves_builtin_notification_oids() {
        let resolver = MibResolver::with_builtin_symbols();
        assert_eq!(
            resolver.resolve("1.3.6.1.2.1.1.3.0").unwrap().name,
            "SNMPv2-MIB::sysUpTime.0"
        );
        assert_eq!(
            resolver.resolve("1.3.6.1.4.1.8072.1").unwrap(),
            OidResolution {
                name: "SNMPv2-SMI::enterprises.8072.1".to_string(),
                module: Some("SNMPv2-SMI".to_string()),
                symbol: "enterprises".to_string(),
                instance: Some("8072.1".to_string()),
            }
        );
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
        fs::write(
            temp_dir.path().join("IGNORED-MIB.json"),
            "IGNORED-MIB DEFINITIONS ::= BEGIN\nignoredRoot OBJECT IDENTIFIER ::= { enterprises 404 }\nEND\n",
        )
        .unwrap();

        let resolver = MibResolver::from_paths(&[temp_dir.path().to_path_buf()]).unwrap();

        assert_eq!(
            resolver.resolve("1.3.6.1.4.1.8072.2.3.0.1").unwrap().name,
            "TEST-MIB::testTrap"
        );
        assert_eq!(
            resolver.resolve("1.3.6.1.4.1.404").unwrap().name,
            "SNMPv2-SMI::enterprises.404"
        );
    }

    #[test]
    fn mib_file_size_limit_is_eight_mebibytes() {
        let temp_dir = tempfile::tempdir().unwrap();
        let at_limit = temp_dir.path().join("AT-LIMIT-MIB.txt");
        let mut contents = TEST_MIB.as_bytes().to_vec();
        contents.resize(8 * 1024 * 1024, b' ');
        fs::write(&at_limit, &contents).unwrap();
        let over_limit = temp_dir.path().join("OVER-LIMIT-MIB.txt");
        contents.push(b' ');
        fs::write(&over_limit, &contents).unwrap();

        let resolver = MibResolver::from_paths(&[at_limit]).unwrap();
        assert!(resolver.resolve("1.3.6.1.4.1.8072.2.3.0.1").is_some());
        assert!(MibResolver::from_paths(&[over_limit]).is_err());
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
    fn accepts_mib_directories_at_the_maximum_depth() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut path = temp_dir.path().to_path_buf();
        for index in 0..MAX_MIB_DIRECTORY_DEPTH {
            path = path.join(format!("level-{index}"));
            fs::create_dir(&path).unwrap();
        }
        fs::write(path.join("TEST-MIB.txt"), TEST_MIB).unwrap();

        let resolver = MibResolver::from_paths(&[temp_dir.path().to_path_buf()]).unwrap();

        assert!(resolver.resolve("1.3.6.1.4.1.8072.2.3.0.1").is_some());
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
            parsed.definitions.is_empty() && parsed.types.is_empty(),
            "expected no definitions from non-MIB text, got {parsed:?}"
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
        assert_eq!(
            resolver.resolve("1.3.6.1.4.1.2.1").unwrap().name,
            "SECOND-MIB::root.1"
        );
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
            assert_eq!(
                resolver
                    .resolve("1.3.6.1.4.1.3.99999999.1")
                    .unwrap()
                    .instance
                    .as_deref(),
                Some("99999999.1")
            );
        }
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "prefix lookups took {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn resolves_conformance_definitions() {
        let resolver = MibResolver::from_str(
            r#"
CONF-MIB DEFINITIONS ::= BEGIN
confRoot OBJECT IDENTIFIER ::= { enterprises 12 }
confGroup OBJECT-GROUP
    OBJECTS { confRoot }
    STATUS current
    DESCRIPTION "A group."
    ::= { confRoot 1 }
confNotifications NOTIFICATION-GROUP
    NOTIFICATIONS { confRoot }
    STATUS current
    DESCRIPTION "A notification group."
    ::= { confRoot 2 }
confCompliance MODULE-COMPLIANCE
    STATUS current
    DESCRIPTION "A compliance statement."
    MODULE
        MANDATORY-GROUPS { confGroup }
    ::= { confRoot 3 }
confCapabilities AGENT-CAPABILITIES
    PRODUCT-RELEASE "1.0"
    STATUS current
    DESCRIPTION "Capabilities."
    ::= { confRoot 4 }
END
"#,
        );

        for (oid, name) in [
            ("1.3.6.1.4.1.12.1", "CONF-MIB::confGroup"),
            ("1.3.6.1.4.1.12.2", "CONF-MIB::confNotifications"),
            ("1.3.6.1.4.1.12.3", "CONF-MIB::confCompliance"),
            ("1.3.6.1.4.1.12.4", "CONF-MIB::confCapabilities"),
        ] {
            assert_eq!(resolver.resolve(oid).unwrap().name, name);
        }
    }

    #[test]
    fn smiv2_definitions_supersede_smiv1_definitions_in_any_load_order() {
        const SMIV1: &str = r#"
OLD-MIB DEFINITIONS ::= BEGIN
IMPORTS mgmt FROM RFC1155-SMI OBJECT-TYPE FROM RFC-1212;
sharedObject OBJECT-TYPE
    SYNTAX INTEGER
    ACCESS read-only
    STATUS mandatory
    ::= { mgmt 99 1 }
END
"#;
        const SMIV2: &str = r#"
NEW-MIB DEFINITIONS ::= BEGIN
IMPORTS MODULE-IDENTITY, OBJECT-TYPE, mgmt FROM SNMPv2-SMI;
newMib MODULE-IDENTITY
    LAST-UPDATED "202601010000Z"
    ORGANIZATION "Example"
    CONTACT-INFO "Example"
    DESCRIPTION "Example"
    ::= { mgmt 98 }
sharedObject OBJECT-TYPE
    SYNTAX Integer32
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "Example"
    ::= { mgmt 99 1 }
END
"#;

        for contents in [format!("{SMIV1}\n{SMIV2}"), format!("{SMIV2}\n{SMIV1}")] {
            let resolver = MibResolver::from_str(&contents);
            assert_eq!(
                resolver.resolve("1.3.6.1.2.99.1.0").unwrap().name,
                "NEW-MIB::sharedObject.0"
            );
        }
    }

    #[test]
    fn resolves_smiv1_named_number_oids() {
        let resolver = MibResolver::from_str(
            "NAMED-MIB DEFINITIONS ::= BEGIN\n\
             namedRoot OBJECT IDENTIFIER ::= { iso(1) org(3) dod(6) internet(1) private(4) enterprises(1) 42 }\n\
             unknownRoot OBJECT IDENTIFIER ::= { unknownArc(9) 1 }\n\
             END\n",
        );

        assert_eq!(
            resolver.resolve("1.3.6.1.4.1.42").unwrap().name,
            "NAMED-MIB::namedRoot"
        );
        assert_eq!(
            resolver.resolve("9.1").unwrap().name,
            "NAMED-MIB::unknownRoot"
        );
    }

    #[test]
    fn resolves_chains_of_symbolic_arcs() {
        let resolver = MibResolver::from_str(
            "CHAIN-MIB DEFINITIONS ::= BEGIN\n\
             chainRoot OBJECT IDENTIFIER ::= { iso org dod internet private enterprises 43 }\n\
             brokenChain OBJECT IDENTIFIER ::= { enterprises mgmt 1 }\n\
             END\n",
        );

        assert_eq!(
            resolver.resolve("1.3.6.1.4.1.43").unwrap().name,
            "CHAIN-MIB::chainRoot"
        );
        // `mgmt` does not extend `enterprises`, so `brokenChain` must not claim mgmt's OID.
        assert_eq!(
            resolver.resolve("1.3.6.1.2").unwrap().name,
            "SNMPv2-SMI::mgmt"
        );
    }

    #[test]
    fn falls_back_when_an_import_names_the_wrong_module() {
        let resolver = MibResolver::from_str(
            r#"
DEFINER-MIB DEFINITIONS ::= BEGIN
definedRoot OBJECT IDENTIFIER ::= { enterprises 44 }
END

WRONG-MIB DEFINITIONS ::= BEGIN
otherRoot OBJECT IDENTIFIER ::= { enterprises 45 }
END

IMPORTER-MIB DEFINITIONS ::= BEGIN
IMPORTS definedRoot FROM WRONG-MIB;
importedChild OBJECT IDENTIFIER ::= { definedRoot 1 }
END
"#,
        );

        assert_eq!(
            resolver.resolve("1.3.6.1.4.1.44.1").unwrap().name,
            "IMPORTER-MIB::importedChild"
        );
    }

    #[test]
    fn ignores_definitions_inside_comments() {
        let resolver = MibResolver::from_str(
            "COMMENTED-MIB DEFINITIONS ::= BEGIN\n\
             -- hiddenRoot OBJECT IDENTIFIER ::= { enterprises 1 }\n\
             realRoot OBJECT IDENTIFIER ::= { enterprises 7 } -- a-b hidden2 OBJECT IDENTIFIER ::= { enterprises 8 }\n\
             -- closed -- afterRoot OBJECT IDENTIFIER ::= { enterprises 9 }\n\
             END\n",
        );

        assert_eq!(
            resolver.resolve("1.3.6.1.4.1.1").unwrap().name,
            "SNMPv2-SMI::enterprises.1"
        );
        assert_eq!(
            resolver.resolve("1.3.6.1.4.1.8").unwrap().name,
            "SNMPv2-SMI::enterprises.8"
        );
        assert_eq!(
            resolver.resolve("1.3.6.1.4.1.7").unwrap().name,
            "COMMENTED-MIB::realRoot"
        );
        assert_eq!(
            resolver.resolve("1.3.6.1.4.1.9").unwrap().name,
            "COMMENTED-MIB::afterRoot"
        );
    }

    #[test]
    fn imported_definitions_are_not_overridden_by_importing_modules() {
        const DEFINER: &str = r#"
BASE-MIB DEFINITIONS ::= BEGIN
IMPORTS MODULE-IDENTITY, enterprises FROM SNMPv2-SMI;
baseMib MODULE-IDENTITY
    LAST-UPDATED "202601010000Z"
    ORGANIZATION "Example"
    CONTACT-INFO "Example"
    DESCRIPTION "Example"
    ::= { enterprises 46 }
baseTypes OBJECT IDENTIFIER ::= { baseMib 1 }
END
"#;
        const IMPORTER: &str = r#"
AAA-TYPES-MIB DEFINITIONS ::= BEGIN
IMPORTS MODULE-IDENTITY FROM SNMPv2-SMI baseMib FROM BASE-MIB;
typesMib MODULE-IDENTITY
    LAST-UPDATED "202601010000Z"
    ORGANIZATION "Example"
    CONTACT-INFO "Example"
    DESCRIPTION "Example"
    ::= { baseMib 2 }
baseTypes OBJECT IDENTIFIER ::= { baseMib 1 }
END
"#;

        for contents in [
            format!("{DEFINER}\n{IMPORTER}"),
            format!("{IMPORTER}\n{DEFINER}"),
        ] {
            let resolver = MibResolver::from_str(&contents);
            assert_eq!(
                resolver.resolve("1.3.6.1.4.1.46.1").unwrap().name,
                "BASE-MIB::baseTypes"
            );
        }
    }

    #[test]
    fn first_definition_wins_between_unrelated_modules() {
        let resolver = MibResolver::from_str(
            "FIRST-MIB DEFINITIONS ::= BEGIN\n\
             sharedArc OBJECT IDENTIFIER ::= { enterprises 47 }\n\
             END\n\
             SECOND-MIB DEFINITIONS ::= BEGIN\n\
             otherArc OBJECT IDENTIFIER ::= { enterprises 47 }\n\
             END\n",
        );

        assert_eq!(
            resolver.resolve("1.3.6.1.4.1.47").unwrap().name,
            "FIRST-MIB::sharedArc"
        );
    }

    #[test]
    fn sequence_members_are_not_definitions() {
        let resolver = MibResolver::from_str(
            r#"
TABLE-MIB DEFINITIONS ::= BEGIN
tableEntry OBJECT IDENTIFIER ::= { enterprises 48 1 1 }
TableEntry ::= SEQUENCE {
    firstColumn  Integer32,
    oidColumn    OBJECT IDENTIFIER
}
firstColumn OBJECT-TYPE
    SYNTAX Integer32
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "First column."
    ::= { tableEntry 1 }
oidColumn OBJECT-TYPE
    SYNTAX OBJECT IDENTIFIER
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "Second column."
    ::= { tableEntry 2 }
END
"#,
        );

        assert_eq!(
            resolver.resolve("1.3.6.1.4.1.48.1.1.1.7").unwrap().name,
            "TABLE-MIB::firstColumn.7"
        );
        assert_eq!(
            resolver.resolve("1.3.6.1.4.1.48.1.1.2.7").unwrap().name,
            "TABLE-MIB::oidColumn.7"
        );
    }

    const SYNTAX_MIB: &str = r#"
SYNTAX-MIB DEFINITIONS ::= BEGIN
IMPORTS
    MODULE-IDENTITY, OBJECT-TYPE, Integer32, enterprises FROM SNMPv2-SMI
    TEXTUAL-CONVENTION, DisplayString, MacAddress FROM SNMPv2-TC;

syntaxMib MODULE-IDENTITY
    LAST-UPDATED "202601010000Z"
    ORGANIZATION "Example"
    CONTACT-INFO "Example"
    DESCRIPTION "SYNTAX \"quoted\" -- not a comment ::= { enterprises 1 }"
    ::= { enterprises 49 }

Status ::= TEXTUAL-CONVENTION
    STATUS current
    DESCRIPTION "Operational state."
    SYNTAX INTEGER { up(1), down(2), unknown(-1) }

Tenths ::= TEXTUAL-CONVENTION
    DISPLAY-HINT "d-1"
    STATUS current
    DESCRIPTION "Tenths of a unit."
    SYNTAX Integer32

Label ::= TEXTUAL-CONVENTION
    DISPLAY-HINT "255t"
    STATUS current
    DESCRIPTION "A label that refines DisplayString."
    SYNTAX DisplayString

LegacyString ::= OCTET STRING

statusObject OBJECT-TYPE
    SYNTAX Status
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "Uses a local textual convention."
    ::= { syntaxMib 1 }

refinedStatus OBJECT-TYPE
    SYNTAX Status { up(1) }
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "Refines the enumeration."
    ::= { syntaxMib 2 }

temperature OBJECT-TYPE
    SYNTAX Tenths
    UNITS "degrees"
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "Uses a hinted integer with units."
    ::= { syntaxMib 3 }

macObject OBJECT-TYPE
    SYNTAX MacAddress
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "Uses a built-in SNMPv2-TC convention."
    ::= { syntaxMib 4 }

labelObject OBJECT-TYPE
    SYNTAX Label (SIZE (0..32))
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "The outer display hint wins."
    ::= { syntaxMib 5 }

flags OBJECT-TYPE
    SYNTAX BITS { first(0), second(1) }
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "BITS labels."
    ::= { syntaxMib 6 }

legacyObject OBJECT-TYPE
    SYNTAX LegacyString
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "An SMIv1-style type assignment."
    ::= { syntaxMib 7 }

unknownType OBJECT-TYPE
    SYNTAX NotDefinedAnywhere
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "An unresolvable type."
    ::= { syntaxMib 8 }

END
"#;

    fn syntax_of(resolver: &MibResolver, oid: &str) -> ValueSyntax {
        resolver
            .value_syntax(oid)
            .map(|syntax| (*syntax).clone())
            .unwrap_or_else(|| panic!("no syntax for {oid}"))
    }

    #[test]
    fn resolves_object_syntax_through_textual_conventions() {
        let resolver = MibResolver::from_str(SYNTAX_MIB);
        let named = |pairs: &[(i64, &str)]| {
            pairs
                .iter()
                .map(|(number, label)| (*number, (*label).to_string()))
                .collect::<Vec<_>>()
        };

        let status = syntax_of(&resolver, "1.3.6.1.4.1.49.1.0");
        assert_eq!(status.base, BaseSyntax::Integer);
        assert_eq!(
            status.named_numbers,
            named(&[(1, "up"), (2, "down"), (-1, "unknown")])
        );

        let refined = syntax_of(&resolver, "1.3.6.1.4.1.49.2.0");
        assert_eq!(refined.named_numbers, named(&[(1, "up")]));

        let temperature = syntax_of(&resolver, "1.3.6.1.4.1.49.3.0");
        assert_eq!(temperature.base, BaseSyntax::Integer);
        assert_eq!(temperature.display_hint.as_deref(), Some("d-1"));
        assert_eq!(temperature.units.as_deref(), Some("degrees"));

        let mac = syntax_of(&resolver, "1.3.6.1.4.1.49.4.0");
        assert_eq!(mac.base, BaseSyntax::OctetString);
        assert_eq!(mac.display_hint.as_deref(), Some("1x:"));

        let label = syntax_of(&resolver, "1.3.6.1.4.1.49.5.0");
        assert_eq!(label.base, BaseSyntax::OctetString);
        assert_eq!(label.display_hint.as_deref(), Some("255t"));

        let flags = syntax_of(&resolver, "1.3.6.1.4.1.49.6.0");
        assert_eq!(flags.base, BaseSyntax::Bits);
        assert_eq!(flags.named_numbers, named(&[(0, "first"), (1, "second")]));

        let legacy = syntax_of(&resolver, "1.3.6.1.4.1.49.7.0");
        assert_eq!(legacy.base, BaseSyntax::OctetString);
        assert_eq!(legacy.display_hint, None);

        let unknown = syntax_of(&resolver, "1.3.6.1.4.1.49.8.0");
        assert_eq!(unknown.base, BaseSyntax::Opaque);

        // Only objects carry a syntax, and OIDs below a non-object have none.
        assert!(resolver.value_syntax("1.3.6.1.4.1.49").is_none());
        assert!(resolver.value_syntax("1.3.6.1.4.1.50.1").is_none());
    }

    #[test]
    fn strings_in_descriptions_do_not_create_definitions() {
        let resolver = MibResolver::from_str(SYNTAX_MIB);
        assert_eq!(
            resolver.resolve("1.3.6.1.4.1.1").unwrap().name,
            "SNMPv2-SMI::enterprises.1"
        );
        assert_eq!(
            resolver.resolve("1.3.6.1.4.1.49").unwrap().name,
            "SYNTAX-MIB::syntaxMib"
        );
    }

    #[test]
    fn loaded_textual_conventions_replace_builtin_ones() {
        let resolver = MibResolver::from_str(
            r#"
SNMPv2-TC DEFINITIONS ::= BEGIN
MacAddress ::= TEXTUAL-CONVENTION
    DISPLAY-HINT "1x-"
    STATUS current
    DESCRIPTION "Overridden for the test."
    SYNTAX OCTET STRING (SIZE (6))
END

USER-MIB DEFINITIONS ::= BEGIN
IMPORTS OBJECT-TYPE, enterprises FROM SNMPv2-SMI MacAddress FROM SNMPv2-TC;
userMac OBJECT-TYPE
    SYNTAX MacAddress
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "Uses the loaded convention."
    ::= { enterprises 50 1 }
END
"#,
        );

        assert_eq!(
            syntax_of(&resolver, "1.3.6.1.4.1.50.1.0")
                .display_hint
                .as_deref(),
            Some("1x-")
        );
    }

    #[test]
    fn circular_textual_conventions_do_not_loop() {
        let resolver = MibResolver::from_str(
            r#"
LOOP-MIB DEFINITIONS ::= BEGIN
First ::= TEXTUAL-CONVENTION STATUS current DESCRIPTION "" SYNTAX Second
Second ::= TEXTUAL-CONVENTION STATUS current DESCRIPTION "" SYNTAX First
loopObject OBJECT-TYPE
    SYNTAX First
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "A circular type."
    ::= { enterprises 51 }
END
"#,
        );

        assert_eq!(
            syntax_of(&resolver, "1.3.6.1.4.1.51.0").base,
            BaseSyntax::Opaque
        );
    }

    #[test]
    fn resolves_application_types_tables_and_qualified_types() {
        let resolver = MibResolver::from_str(
            r#"
TYPES-MIB DEFINITIONS ::= BEGIN
IMPORTS OBJECT-TYPE, Unsigned32, Gauge32, enterprises FROM SNMPv2-SMI
        DisplayString FROM SNMPv2-TC
        NetworkAddress FROM RFC1155-SMI;
unsignedObject OBJECT-TYPE SYNTAX Unsigned32 { low(1) } MAX-ACCESS read-only STATUS current DESCRIPTION "" ::= { enterprises 53 1 }
gaugeObject OBJECT-TYPE SYNTAX Gauge32 MAX-ACCESS read-only STATUS current DESCRIPTION "" ::= { enterprises 53 2 }
addressObject OBJECT-TYPE SYNTAX NetworkAddress ACCESS read-only STATUS mandatory ::= { enterprises 53 3 }
tableObject OBJECT-TYPE SYNTAX SEQUENCE OF TableEntry MAX-ACCESS not-accessible STATUS current DESCRIPTION "" ::= { enterprises 53 4 }
qualifiedObject OBJECT-TYPE SYNTAX SNMPv2-TC.DisplayString MAX-ACCESS read-only STATUS current DESCRIPTION "" ::= { enterprises 53 5 }
localQualified OBJECT-TYPE SYNTAX TYPES-MIB.LocalHex MAX-ACCESS read-only STATUS current DESCRIPTION "" ::= { enterprises 53 6 }
LocalHex ::= TEXTUAL-CONVENTION DISPLAY-HINT "1x" STATUS current DESCRIPTION "" SYNTAX OCTET STRING
END
"#,
        );

        let unsigned = syntax_of(&resolver, "1.3.6.1.4.1.53.1.0");
        assert_eq!(unsigned.base, BaseSyntax::Unsigned);
        assert_eq!(unsigned.named_numbers, vec![(1, "low".to_string())]);
        assert_eq!(
            syntax_of(&resolver, "1.3.6.1.4.1.53.2.0").base,
            BaseSyntax::Unsigned
        );
        assert_eq!(
            syntax_of(&resolver, "1.3.6.1.4.1.53.3.0").base,
            BaseSyntax::NetworkAddress
        );
        assert!(resolver.value_syntax("1.3.6.1.4.1.53.4").is_none());
        assert_eq!(
            syntax_of(&resolver, "1.3.6.1.4.1.53.5.0")
                .display_hint
                .as_deref(),
            Some("255a")
        );
        assert_eq!(
            syntax_of(&resolver, "1.3.6.1.4.1.53.6.0")
                .display_hint
                .as_deref(),
            Some("1x")
        );
    }
}
