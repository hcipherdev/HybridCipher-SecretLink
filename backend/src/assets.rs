use crate::{repo_public_dir, repo_src_dir, AppError};
use axum::http::HeaderValue;
use mime_guess::from_path;
use std::path::PathBuf;

pub struct Asset {
    pub content_type: HeaderValue,
    pub body: Vec<u8>,
}

#[derive(Clone)]
pub struct AssetCatalog {
    web_dev_dir: Option<PathBuf>,
}

impl AssetCatalog {
    pub fn new(web_dev_dir: Option<PathBuf>) -> Self {
        let resolved = web_dev_dir.or_else(|| {
            let repo_dir = repo_public_dir();
            if cfg!(debug_assertions) && repo_dir.exists() {
                Some(repo_dir)
            } else {
                None
            }
        });
        Self {
            web_dev_dir: resolved,
        }
    }

    pub async fn read(&self, name: &str) -> Result<Option<Asset>, AppError> {
        if !matches!(
            name,
            "src/app.js" | "src/api.js" | "src/crypto.js" | "src/router.js" | "styles.css"
        ) {
            return Ok(None);
        }

        if let Some(dir) = &self.web_dev_dir {
            let path = if name.starts_with("src/") {
                dir.parent()
                    .map(|parent| parent.join("src").join(name.trim_start_matches("src/")))
                    .unwrap_or_else(|| repo_src_dir().join(name.trim_start_matches("src/")))
            } else {
                dir.join(name)
            };
            if path.exists() {
                let bytes = tokio::fs::read(&path)
                    .await
                    .map_err(|error| AppError::internal(error.to_string()))?;
                return Ok(Some(Asset {
                    content_type: content_type_for(name),
                    body: bytes,
                }));
            }
        }

        Ok(embedded_asset(name))
    }

    pub async fn index_html(&self) -> Result<String, AppError> {
        if let Some(dir) = &self.web_dev_dir {
            let path = dir.join("index.html");
            if path.exists() {
                return tokio::fs::read_to_string(path)
                    .await
                    .map_err(|error| AppError::internal(error.to_string()));
            }
        }

        Ok(include_str!("../../frontend/public/index.html").to_string())
    }
}

fn embedded_asset(name: &str) -> Option<Asset> {
    let body = match name {
        "src/app.js" => include_str!("../../frontend/src/app.js")
            .as_bytes()
            .to_vec(),
        "src/api.js" => include_str!("../../frontend/src/api.js")
            .as_bytes()
            .to_vec(),
        "src/crypto.js" => include_str!("../../frontend/src/crypto.js")
            .as_bytes()
            .to_vec(),
        "src/router.js" => include_str!("../../frontend/src/router.js")
            .as_bytes()
            .to_vec(),
        "styles.css" => include_str!("../../frontend/public/styles.css")
            .as_bytes()
            .to_vec(),
        _ => return None,
    };

    Some(Asset {
        content_type: content_type_for(name),
        body,
    })
}

fn content_type_for(name: &str) -> HeaderValue {
    let mime = from_path(name).first_or_octet_stream();
    HeaderValue::from_str(mime.as_ref()).expect("mime header value")
}
