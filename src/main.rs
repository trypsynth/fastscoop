#![warn(clippy::all, clippy::cargo, clippy::nursery, clippy::pedantic)]

use std::{
	collections::{HashMap, HashSet},
	env,
	error::Error,
	ffi::OsStr,
	fs,
	path::{Path, PathBuf},
	process, string,
	time::{Duration, SystemTime, UNIX_EPOCH},
};

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use ureq::Agent;

const GITHUB_CACHE_TTL: Duration = Duration::from_secs(3 * 60 * 60);

#[derive(Deserialize)]
struct Manifest {
	#[serde(default)]
	version: Option<String>,
	#[serde(default)]
	bin: Option<Value>,
}

#[derive(Clone)]
struct SearchResult {
	name: String,
	version: String,
	bucket: String,
	binaries: String,
}

#[derive(Clone)]
struct RemoteResult {
	name: String,
	bucket: String,
}

#[derive(Clone, Deserialize, Serialize)]
struct GitHubTree {
	tree: Vec<GitHubTreeEntry>,
}

#[derive(Clone, Deserialize, Serialize)]
struct GitHubTreeEntry {
	path: String,
}

#[derive(Deserialize)]
struct GitHubRateLimit {
	resources: GitHubResources,
}

#[derive(Deserialize)]
struct GitHubResources {
	core: GitHubRateLimitCore,
}

#[derive(Deserialize)]
struct GitHubRateLimitCore {
	remaining: u32,
}

#[derive(Deserialize)]
struct ScoopConfig {
	cache_path: Option<String>,
	gh_token: Option<String>,
}

#[derive(Deserialize, Serialize)]
struct GitHubTreeCache {
	fetched_at: u64,
	tree: GitHubTree,
}

fn scoop_root() -> PathBuf {
	if let Ok(root) = env::var("SCOOP")
		&& !root.is_empty()
	{
		return PathBuf::from(root);
	}
	match env::var("USERPROFILE") {
		Ok(home) if !home.is_empty() => PathBuf::from(home).join("scoop"),
		_ => {
			eprintln!("fastscoop: cannot determine home directory");
			process::exit(1);
		}
	}
}

fn buckets_dir() -> PathBuf {
	scoop_root().join("buckets")
}

fn scoop_config_path() -> Option<PathBuf> {
	let config_home = env::var("XDG_CONFIG_HOME")
		.or_else(|_| env::var("USERPROFILE").map(|p| format!("{p}\\.config")))
		.ok()
		.filter(|p| !p.is_empty())?;
	let default_path = PathBuf::from(config_home).join("scoop").join("config.json");
	let portable_path = scoop_root().join("config.json");
	if portable_path.exists() { Some(portable_path) } else { Some(default_path) }
}

fn scoop_config() -> Option<ScoopConfig> {
	let path = scoop_config_path()?;
	let data = fs::read(path).ok()?;
	serde_json::from_slice(&data).ok()
}

fn scoop_cache_dir() -> PathBuf {
	if let Ok(path) = env::var("SCOOP_CACHE")
		&& !path.is_empty()
	{
		return PathBuf::from(path);
	}
	if let Some(config) = scoop_config()
		&& let Some(path) = config.cache_path
		&& !path.is_empty()
	{
		return PathBuf::from(path);
	}
	scoop_root().join("cache")
}

fn github_cache_dir() -> PathBuf {
	scoop_cache_dir().join("fastscoop").join("github")
}

fn known_buckets() -> Option<Vec<String>> {
	let path = scoop_root().join("apps").join("scoop").join("current").join("buckets.json");
	let data = fs::read(&path).ok()?;
	let v: Value = serde_json::from_slice(&data).ok()?;
	let obj = v.as_object()?;
	let mut keys = Vec::with_capacity(obj.len());
	for (k, _) in obj {
		keys.push(k.clone());
	}
	Some(keys)
}

fn known_bucket_repos() -> Option<HashMap<String, String>> {
	let path = scoop_root().join("apps").join("scoop").join("current").join("buckets.json");
	let data = fs::read(&path).ok()?;
	let v: Value = serde_json::from_slice(&data).ok()?;
	let obj = v.as_object()?;
	let mut repos = HashMap::with_capacity(obj.len());
	for (name, url) in obj {
		if let Some(url_str) = url.as_str() {
			repos.insert(name.clone(), url_str.to_string());
		}
	}
	Some(repos)
}

fn github_token() -> Option<String> {
	if let Ok(token) = env::var("SCOOP_GH_TOKEN")
		&& !token.is_empty()
	{
		return Some(token);
	}
	if let Ok(token) = env::var("GH_TOKEN")
		&& !token.is_empty()
	{
		return Some(token);
	}
	if let Ok(token) = env::var("GITHUB_TOKEN")
		&& !token.is_empty()
	{
		return Some(token);
	}
	scoop_config()?.gh_token.filter(|s| !s.is_empty())
}

fn create_agent() -> Agent {
	Agent::new_with_defaults()
}

fn github_request(agent: &Agent, url: &str) -> Result<ureq::Body, ureq::Error> {
	let mut req = agent.get(url).header("User-Agent", "fastscoop");
	if let Some(token) = github_token() {
		req = req.header("Authorization", &format!("Bearer {token}"));
	}
	Ok(req.call()?.into_body())
}

fn github_rate_limit_ok(agent: &Agent) -> bool {
	let Ok(mut body) = github_request(agent, "https://api.github.com/rate_limit") else {
		return false;
	};
	let Ok(rate_limit) = body.read_json::<GitHubRateLimit>() else {
		return false;
	};
	rate_limit.resources.core.remaining > 0
}

fn parse_github_repo(url: &str) -> Option<(String, String)> {
	let url = url.trim_end_matches(".git");
	let parts: Vec<&str> = url.split('/').collect();
	if parts.len() >= 2 {
		let repo = parts[parts.len() - 1].to_string();
		let user = parts[parts.len() - 2].to_string();
		if !user.is_empty() && !repo.is_empty() {
			return Some((user, repo));
		}
	}
	None
}

fn github_cache_key(value: &str) -> String {
	value.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' { c } else { '_' }).collect()
}

fn github_cache_path(user: &str, repo: &str) -> PathBuf {
	let file_name = format!("{}__{}.json", github_cache_key(user), github_cache_key(repo));
	github_cache_dir().join(file_name)
}

fn unix_timestamp() -> Option<u64> {
	SystemTime::now().duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs())
}

fn read_cached_tree(path: &Path) -> Option<GitHubTree> {
	let data = fs::read(path).ok()?;
	let cache: GitHubTreeCache = serde_json::from_slice(&data).ok()?;
	let now = unix_timestamp()?;
	if now.saturating_sub(cache.fetched_at) <= GITHUB_CACHE_TTL.as_secs() { Some(cache.tree) } else { None }
}

fn write_cached_tree(path: &Path, tree: GitHubTree) {
	let Some(now) = unix_timestamp() else {
		return;
	};
	let cache = GitHubTreeCache { fetched_at: now, tree };
	let Ok(data) = serde_json::to_vec(&cache) else {
		return;
	};
	if let Some(parent) = path.parent() {
		let _ = fs::create_dir_all(parent);
	}
	let _ = fs::write(path, data);
}

fn github_tree_cached(agent: &Agent, user: &str, repo: &str) -> Option<GitHubTree> {
	let cache_path = github_cache_path(user, repo);
	if let Some(tree) = read_cached_tree(&cache_path) {
		return Some(tree);
	}
	let api_url = format!("https://api.github.com/repos/{user}/{repo}/git/trees/HEAD?recursive=1");
	let mut body = github_request(agent, &api_url).ok()?;
	let tree = body.read_json::<GitHubTree>().ok()?;
	write_cached_tree(&cache_path, tree.clone());
	Some(tree)
}

fn github_cache_fresh_for_repo(user: &str, repo: &str) -> bool {
	let cache_path = github_cache_path(user, repo);
	read_cached_tree(&cache_path).is_some()
}

fn remote_cache_needed(local_buckets: &[String]) -> bool {
	let Some(known_repos) = known_bucket_repos() else {
		return true;
	};
	let local_set: HashSet<&str> = local_buckets.iter().map(String::as_str).collect();
	for (bucket, url) in &known_repos {
		if local_set.contains(bucket.as_str()) {
			continue;
		}
		let Some((user, repo)) = parse_github_repo(url) else {
			return true;
		};
		if !github_cache_fresh_for_repo(&user, &repo) {
			return true;
		}
	}
	false
}

fn search_remote_bucket(agent: &Agent, bucket: &str, url: &str, re: &Regex) -> Vec<RemoteResult> {
	let mut results = Vec::new();
	let Some((user, repo)) = parse_github_repo(url) else {
		return results;
	};
	let Some(tree) = github_tree_cached(agent, &user, &repo) else {
		return results;
	};
	for entry in tree.tree {
		if let Some(name) = entry.path.strip_prefix("bucket/").and_then(|p| p.strip_suffix(".json"))
			&& re.is_match(name)
		{
			results.push(RemoteResult { name: name.to_string(), bucket: bucket.to_string() });
		}
	}
	results
}

fn search_remote_buckets(agent: &Agent, local_buckets: &[String], re: &Regex) -> Vec<RemoteResult> {
	let Some(known_repos) = known_bucket_repos() else {
		return Vec::new();
	};
	let local_set: HashSet<&str> = local_buckets.iter().map(String::as_str).collect();
	let mut results = Vec::new();
	for (bucket, url) in &known_repos {
		if local_set.contains(bucket.as_str()) {
			continue;
		}
		results.extend(search_remote_bucket(agent, bucket, url, re));
	}
	results.sort_by(|a, b| a.bucket.cmp(&b.bucket).then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase())));
	results
}

fn local_buckets() -> Result<Vec<String>, Box<dyn Error>> {
	let mut bucket_names: Vec<String> = Vec::new();
	for entry in fs::read_dir(buckets_dir())? {
		let entry = entry?;
		if entry.file_type()?.is_dir()
			&& let Some(name) = entry.file_name().to_str()
		{
			bucket_names.push(name.to_string());
		}
	}
	bucket_names.sort();
	let known = known_buckets().unwrap_or_default();
	if known.is_empty() {
		return Ok(bucket_names);
	}
	let present: HashSet<&str> = bucket_names.iter().map(string::String::as_str).collect();
	let mut seen: HashSet<String> = HashSet::new();
	let mut ordered: Vec<String> = Vec::with_capacity(bucket_names.len());
	for name in known {
		if present.contains(name.as_str()) {
			ordered.push(name.clone());
			seen.insert(name);
		}
	}
	for b in bucket_names {
		if !seen.contains(&b) {
			ordered.push(b);
		}
	}
	Ok(ordered)
}

fn load_manifest(path: &Path) -> Option<(String, String, Option<Value>)> {
	let file_name = path.file_name()?.to_str()?;
	if !Path::new(file_name).extension().is_some_and(|ext| ext.eq_ignore_ascii_case("json")) {
		return None;
	}
	let stem = file_name.strip_suffix(".json")?.to_string();
	let data = fs::read(path).ok()?;
	let m: Manifest = serde_json::from_slice(&data).ok()?;
	let version = m.version.unwrap_or_default();
	Some((stem, version, m.bin))
}

fn match_bin_string(bin: &str, re: &Regex) -> Option<String> {
	let base = Path::new(bin).file_name().and_then(|s| s.to_str()).unwrap_or(bin);
	let ext = Path::new(base).extension().and_then(|s| s.to_str()).unwrap_or("");
	let name = if ext.is_empty() { base } else { base.strip_suffix(&format!(".{ext}")).unwrap_or(base) };
	if re.is_match(name) { Some(base.to_string()) } else { None }
}

fn match_bins(bin: Option<&Value>, re: &Regex) -> Vec<String> {
	let mut matches: Vec<String> = Vec::new();
	let Some(v) = bin else {
		return matches;
	};
	match v {
		Value::String(s) => {
			if let Some(m) = match_bin_string(s, re) {
				matches.push(m);
			}
		}
		Value::Array(arr) => {
			for item in arr {
				match item {
					Value::String(s) => {
						if let Some(m) = match_bin_string(s, re) {
							matches.push(m);
						}
					}
					Value::Array(args) => {
						if let Some(Value::String(exe)) = args.first()
							&& let Some(m) = match_bin_string(exe, re)
						{
							matches.push(m);
							continue;
						}
						if let Some(Value::String(alias)) = args.get(1)
							&& re.is_match(alias)
						{
							matches.push(alias.clone());
						}
					}
					_ => {}
				}
			}
		}
		_ => {}
	}
	matches
}

fn walk_manifests(buckets: &[String], mut f: impl FnMut(&str, &Path)) {
	let buckets_path = buckets_dir();
	for bucket in buckets {
		let bucket_path = buckets_path.join(bucket).join("bucket");
		let Ok(entries) = fs::read_dir(&bucket_path) else {
			continue;
		};
		for entry in entries.flatten() {
			let path = entry.path();
			if path.extension() == Some(OsStr::new("json")) {
				f(bucket, &path);
			}
		}
	}
}

fn sort_results(results: &mut [SearchResult], bucket_order: &[String]) {
	if results.len() < 2 {
		return;
	}
	let mut order_index: HashMap<&str, usize> = HashMap::with_capacity(bucket_order.len());
	for (i, b) in bucket_order.iter().enumerate() {
		order_index.insert(b.as_str(), i);
	}
	let unknown_index = bucket_order.len() + 1;
	results.sort_by(|a, b| {
		let ai = order_index.get(a.bucket.as_str()).copied().unwrap_or(unknown_index);
		let bi = order_index.get(b.bucket.as_str()).copied().unwrap_or(unknown_index);
		ai.cmp(&bi).then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase())).then_with(|| a.name.cmp(&b.name))
	});
}

fn print_results(results: &[SearchResult], show_header: bool) {
	if show_header {
		println!("Results from local buckets...\n");
	}
	let name_h = "Name";
	let version_h = "Version";
	let source_h = "Source";
	let binaries_h = "Binaries";
	let mut name_w = name_h.len();
	let mut version_w = version_h.len();
	let mut source_w = source_h.len();
	let mut binaries_w = binaries_h.len();
	for r in results {
		name_w = name_w.max(r.name.len());
		version_w = version_w.max(r.version.len());
		source_w = source_w.max(r.bucket.len());
		binaries_w = binaries_w.max(r.binaries.len());
	}
	println!("{name_h:<name_w$}  {version_h:<version_w$}  {source_h:<source_w$}  {binaries_h:<binaries_w$}");
	println!(
		"{:<name_w$}  {:<version_w$}  {:<source_w$}  {:<binaries_w$}",
		"-".repeat(name_h.len()),
		"-".repeat(version_h.len()),
		"-".repeat(source_h.len()),
		"-".repeat(binaries_h.len()),
		name_w = name_w,
		version_w = version_w,
		source_w = source_w,
		binaries_w = binaries_w
	);
	for r in results {
		println!(
			"{:<name_w$}  {:<version_w$}  {:<source_w$}  {:<binaries_w$}",
			r.name,
			r.version,
			r.bucket,
			r.binaries,
			name_w = name_w,
			version_w = version_w,
			source_w = source_w,
			binaries_w = binaries_w
		);
	}
}

fn print_remote_results(results: &[RemoteResult]) {
	println!("\nResults from other known buckets...");
	println!("(add them using 'scoop bucket add <bucket name>')\n");
	let name_h = "Name";
	let source_h = "Source";
	let mut name_w = name_h.len();
	let mut source_w = source_h.len();
	for r in results {
		name_w = name_w.max(r.name.len());
		source_w = source_w.max(r.bucket.len());
	}
	println!("{name_h:<name_w$}  {source_h:<source_w$}");
	println!(
		"{:<name_w$}  {:<source_w$}",
		"-".repeat(name_h.len()),
		"-".repeat(source_h.len()),
		name_w = name_w,
		source_w = source_w
	);
	for r in results {
		println!("{:<name_w$}  {:<source_w$}", r.name, r.bucket, name_w = name_w, source_w = source_w);
	}
}

fn run() -> Result<i32, Box<dyn Error>> {
	let args: Vec<String> = env::args().collect();
	if args.len() < 2 || args[1] != "search" {
		println!("usage: fastscoop search [query]");
		return Ok(1);
	}
	let bucket_order = local_buckets()?;
	let mut results: Vec<SearchResult> = Vec::with_capacity(128);
	let query = args.get(2);
	let re = match query {
		Some(q) => Some(Regex::new(&format!("(?i){q}")).map_err(|e| format!("Invalid regular expression: {e}"))?),
		None => None,
	};
	walk_manifests(&bucket_order, |bucket, path| {
		let Some((name, version, bin)) = load_manifest(path) else {
			return;
		};
		match &re {
			Some(re) => {
				if re.is_match(&name) {
					results.push(SearchResult { name, version, bucket: bucket.to_string(), binaries: String::new() });
					return;
				}
				let bins = match_bins(bin.as_ref(), re);
				if !bins.is_empty() {
					results.push(SearchResult {
						name,
						version,
						bucket: bucket.to_string(),
						binaries: bins.join(" | "),
					});
				}
			}
			None => {
				results.push(SearchResult { name, version, bucket: bucket.to_string(), binaries: String::new() });
			}
		}
	});
	sort_results(&mut results, &bucket_order);
	let has_local_results = !results.is_empty();
	if has_local_results {
		print_results(&results, query.is_some());
		return Ok(0);
	}
	if let Some(q) = query {
		let re = Regex::new(&format!("(?i){q}"))?;
		let agent = create_agent();
		if remote_cache_needed(&bucket_order) && !github_rate_limit_ok(&agent) {
			eprintln!("GitHub API rate limit exceeded. Set GH_TOKEN or GITHUB_TOKEN for higher limits.");
			println!("No matches found.");
			return Ok(1);
		}
		let remote_results = search_remote_buckets(&agent, &bucket_order, &re);
		if !remote_results.is_empty() {
			print_remote_results(&remote_results);
			return Ok(0);
		}
	}
	println!("No matches found.");
	Ok(1)
}

fn main() {
	match run() {
		Ok(code) => process::exit(code),
		Err(err) => {
			eprintln!("{err}");
			process::exit(1);
		}
	}
}
