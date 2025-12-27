use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct ServiceSettings {
    #[serde(default)]
    pub proxies: Vec<ProxySettings>,
}

#[derive(Debug, Deserialize)]
pub struct ProxySettings {
    #[serde(rename = "appNames", default)]
    pub app_names: Vec<String>,
    pub endpoint: String,
}
