// SPDX-FileCopyrightText: The kube-custom-resources-rs Authors
// SPDX-License-Identifier: 0BSD

use std::{env, fs};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use anyhow::Context;
use clap::Parser;
use itertools::Itertools;
use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
use k8s_openapi::serde::Deserialize;
use reqwest::Client;
use serde_yaml::Value;
use tokio::io::AsyncWriteExt;
use code_generator::catalog;
use code_generator::catalog::UpstreamSource;

#[derive(Debug, Clone, Parser)]
struct Args {
    filter: Option<String>,
}


#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let client = Client::new();
    let mut extracted_crds = vec![];

    let args = Args::parse();

    let source_root = root.join("crd-catalog");

    for source in catalog::CRD_V1_SOURCES {
        extracted_crds.extend(fetch_source(&source_root, client.clone(), source, args.filter.clone()).await.with_context(|| format!("Fetching project {}", source.project_name))?)
    }

    let crd_root = root.join("kube-custom-resources-rs").join("src");

    for extracted_crd in &extracted_crds {
        generate_custom_resource(&crd_root, extracted_crd).await?;
    }

    create_mod_rs_files(&crd_root, &extracted_crds)?;

    if extracted_crds.is_empty() {
        std::process::exit(1);
    }
    Ok(())
}

async fn quote_yaml_strings(contents: String) -> anyhow::Result<Vec<u8>> {
    // ensure that yaml files can be read with yaml 1.1 compliant parsers (like Go's sigs.k8s.io/yaml)
    let mut child = tokio::process::Command::new("yq").args([
        r#"(.. | select(tag == "!!str") ) style="double""#,
    ]).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn()?;
    child.stdin.take().unwrap().write_all(contents.as_bytes()).await?;
    let output = child.wait_with_output().await?;
    Ok(output.stdout)
}

async fn generate_custom_resource(root: &Path, extracted_crd: &ExtractedCRD) -> anyhow::Result<()> {
    let output_path = root.join(extracted_crd.rust_path());
    println!("Output path: {output_path:?}");
    let mut child = tokio::process::Command::new("kopium").args([
        "--docs",
        "--filename",
        "-",
        "--derive=Default",
        "--derive=PartialEq",
        "--smart-derive-elision"
    ]).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn()?;
    child.stdin.take().unwrap().write_all(&extracted_crd.contents).await?;
    let output = child.wait_with_output().await?;

    let decoded = std::str::from_utf8(&output.stdout)?;
    fs::write(&output_path, decoded)?;
    println!("Wrote to {}", output_path.display());

    Ok(())
}

fn create_mod_rs_files(root: &Path, extracted_crds: &[ExtractedCRD]) -> anyhow::Result<()> {
    let crds_by_group = extracted_crds.iter().sorted_by_key(|c| c.rust_cargo_group_directory()).chunk_by(|a| a.rust_cargo_group_directory());

    for (group, group_crds) in &crds_by_group {
        let group_crds = group_crds.collect_vec();
        let mut version_mod = String::new();

        let group_path = root.join(group);

        for (version, crd_versions) in &group_crds.iter().sorted_by_key(|c| &c.version).chunk_by(|c| &c.version) {
            let crd_versions = crd_versions.into_iter().map(|c| {
                format!("pub mod {};\n", c.plural_name)
            }).join("\n");

            fs::write(&group_path.join(version).join("mod.rs"), crd_versions)?;

            version_mod.push_str(&format!("pub mod {};\n", version));
        }

        fs::write(group_path.join("mod.rs"), version_mod)?;
    }
    Ok(())
}

struct ExtractedCRD {
    project_name: String,
    group: String,
    version: String,
    plural_name: String,
    contents: Vec<u8>,
}

impl ExtractedCRD {
    fn raw_path(&self) -> PathBuf {
        Path::new(&self.project_name).join(&self.group).join(&self.version).join(format!("{}.yaml", self.plural_name))
    }

    fn rust_cargo_group_directory(&self) -> String {
        self.group.replace('.', "_")
    }

    fn rust_path(&self) -> PathBuf {
        let resource_filename = self.plural_name.replace('.', "_");
        Path::new(&self.rust_cargo_group_directory()).join(&self.version).join(format!("{}.rs", resource_filename))
    }
}

async fn fetch_source(root: &Path, client: Client, source: &UpstreamSource<'_>, filter: Option<String>) -> anyhow::Result<Vec<ExtractedCRD>> {
    let mut extracted_crds = vec![];
    for url in source.urls {
        if let Some(filter) = &filter {
            if !url.contains(filter) {
                continue;
            }
        }
        let raw_url = gitlab_url(github_url(url));
        println!("Downloading {}", raw_url);
        let response = client.get(raw_url).send().await?.error_for_status()?;
        let content = response.text().await?;
        for crd in parse_crds(content) {
            if source.ignores.iter().any(|&ignore| ignore.group == crd.spec.group && ignore.version == crd.spec.versions[0].name) {
                println!("  Ignoring {}/{}", crd.spec.group, crd.spec.versions[0].name);
                continue;
            }
            let data = serde_yaml::to_string(&crd)?;
            let quoted_data = quote_yaml_strings(data).await?;

            let extracted = ExtractedCRD {
                project_name: source.project_name.to_string(),
                group: crd.spec.group.to_string(),
                version: crd.spec.versions[0].name.to_string(),
                plural_name: crd.spec.names.plural.to_string(),
                contents: quoted_data,
            };
            let file = root.join(extracted.raw_path());

            fs::create_dir_all(file.parent().unwrap())?;

            fs::write(&file, &extracted.contents)?;
            extracted_crds.push(extracted);
        }
    }
    Ok(extracted_crds)
}


fn parse_crds(content: String) -> Vec<CustomResourceDefinition> {
    let mut crds: Vec<CustomResourceDefinition> = vec![];

    for document in serde_yaml::Deserializer::from_str(&content) {
        if let Ok(yaml) = Value::deserialize(document) {
            if let Ok(crd) = serde_yaml::from_value::<CustomResourceDefinition>(yaml) {
                for version in &crd.spec.versions {
                    let mut cloned = crd.clone();
                    cloned.spec.versions = vec![version.to_owned()];
                    crds.push(cloned);
                }
            }
        }
    }

    crds
}

fn github_url(url: &str) -> String {
    if !url.starts_with("https://github.com")
        || url.starts_with("https://raw.githubusercontent.com")
        || url.starts_with("https://github.com") && url.contains("releases/latest/download")
    {
        url.to_owned()
    } else {
        let mut raw: String = String::from(url);
        if url.starts_with("https://github.com") {
            raw = url.replacen("github.com", "raw.githubusercontent.com", 1);
        } else if url.starts_with("https://www.github.com") {
            raw = url.replacen("www.github.com", "raw.githubusercontent.com", 1);
        }

        raw.replacen("/blob", "", 1)
    }
}

fn gitlab_url(url: String) -> String {
    if !url.starts_with("https://gitlab.com") {
        url
    } else {
        url.replacen("/blob/", "/raw/", 1)
    }
}
