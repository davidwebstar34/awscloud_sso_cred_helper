//! # awscloud_sso_cred_helper
//!
//! A crate for managing AWS Single Sign-On (SSO) workflows.
//!
//! This crate provides utilities for retrieving AWS credentials for multiple accounts and roles via AWS SSO. It integrates with the AWS SSO OIDC workflow and fetches temporary credentials for accounts and roles assigned to a user.
//!
//! ## Requirements
//!
//! - AWS SSO must be enabled for your AWS organization.
//! - A valid AWS SSO start URL and region are required.
//! - The `~/.aws/credentials` file will be updated with the fetched credentials.
//! - Access to the device authorization page via a web browser.
//!
//! ## Examples
//!
//! ### Interactive Usage
//!
//! ```no_run
//! use awscloud_sso_cred_helper::AwsSsoWorkflow;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // With no parameters provided, the workflow will prompt interactively.
//!     let mut workflow = AwsSsoWorkflow::default();
//!     let credential = workflow.run_workflow().await?;
//!
//!     println!("Account ID: {}", credential.account_id);
//!     println!("Role Name: {}", credential.role_name);
//!     println!("Access Key ID: {}", credential.access_key_id);
//!     println!("Secret Access Key: {}", credential.secret_access_key);
//!     println!("Session Token: {}", credential.session_token);
//!     Ok(())
//! }
//! ```
//!
//! ### Non-interactive Usage (Providing Options)
//!
//! You can also supply the start URL and region directly:
//!
//! ```no_run
//! use awscloud_sso_cred_helper::AwsSsoWorkflow;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Construct the workflow with the start URL and region pre-supplied.
//!     let mut workflow = AwsSsoWorkflow {
//!         start_url: "https://your.awsapps.com/start".into(),
//!         region: "eu-west-1".into(),
//!         ..Default::default()
//!     };
//!
//!     let credential = workflow.run_workflow().await?;
//!
//!     println!("Account ID: {}", credential.account_id);
//!     println!("Role Name: {}", credential.role_name);
//!     println!("Access Key ID: {}", credential.access_key_id);
//!     println!("Secret Access Key: {}", credential.secret_access_key);
//!     println!("Session Token: {}", credential.session_token);
//!     Ok(())
//! }
//! ```
//!
//! ## License
//!
//! Apache License, Version 2.0 or http://www.apache.org/licenses/LICENSE-2.0

use aws_config::BehaviorVersion;
use aws_sdk_sso::config::Region;
use aws_sdk_sso::Client as SsoClient;
use aws_sdk_ssooidc::operation::create_token::CreateTokenOutput;
use aws_sdk_ssooidc::Client as SsoOidcClient;
use configparser::ini::Ini;
use skim::prelude::*;
use std::error::Error;
use std::fs;
use std::io::{Cursor, Write};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio::task;

#[derive(Default, Clone)]
pub struct AwsSsoWorkflow {
    pub start_url: String,
    pub region: String,
}

pub struct Credential {
    pub account_id: String,
    pub role_name: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
}

impl AwsSsoWorkflow {
    fn write_default_aws_credentials(
        access_key_id: &str,
        secret_access_key: &str,
        session_token: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let credentials_path: PathBuf = dirs_next::home_dir()
            .ok_or("Could not locate home directory")?
            .join(".aws")
            .join("credentials");

        if let Some(parent) = credentials_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut config = Ini::new();
        if credentials_path.exists() {
            let path_str = credentials_path
                .to_str()
                .ok_or("Invalid credentials file path")?;
            match config.load(path_str) {
                Ok(_) => (),
                Err(e) => {
                    eprintln!("Warning: Unable to parse existing credentials file ({}). Overwriting with a new file.", e);
                    config = Ini::new();
                }
            }
        }

        config.remove_section("default");
        config.remove_section("defaultx");

        // Use a temporary section name ("defaultx") so that we can later replace it.
        config.set(
            "defaultx",
            "aws_access_key_id",
            Some(access_key_id.to_string()),
        );
        config.set(
            "defaultx",
            "aws_secret_access_key",
            Some(secret_access_key.to_string()),
        );
        config.set(
            "defaultx",
            "aws_session_token",
            Some(session_token.to_string()),
        );

        let path_str = credentials_path
            .to_str()
            .ok_or("Invalid credentials file path")?;
        config.write(path_str)?;

        let mut contents = fs::read_to_string(&credentials_path)?;
        contents = contents.replace("[defaultx]", "[default]");
        fs::write(&credentials_path, contents)?;

        println!("Updated default credentials in {:?}", credentials_path);
        Ok(())
    }

    async fn register_client(
        sso_oidc_client: &SsoOidcClient,
        client_name: &str,
        client_type: &str,
    ) -> Result<(String, String), Box<dyn Error>> {
        sso_oidc_client
            .register_client()
            .client_name(client_name)
            .client_type(client_type)
            .send()
            .await
            .map_err(|e| Box::new(e) as Box<dyn Error>)
            .and_then(|response| {
                let client_id = response.client_id().ok_or("Missing client_id")?;
                let client_secret = response.client_secret().ok_or("Missing client_secret")?;
                Ok((client_id.to_string(), client_secret.to_string()))
            })
    }

    async fn start_device_authorization(
        sso_oidc_client: &SsoOidcClient,
        client_id: &str,
        client_secret: &str,
        start_url: &str,
    ) -> Result<(String, String, String, String, i32), Box<dyn Error>> {
        sso_oidc_client
            .start_device_authorization()
            .client_id(client_id)
            .client_secret(client_secret)
            .start_url(start_url)
            .send()
            .await
            .map_err(|e| Box::new(e) as Box<dyn Error>)
            .and_then(|sda| {
                Ok((
                    sda.device_code().ok_or("Missing device_code")?.to_string(),
                    sda.user_code().ok_or("Missing user_code")?.to_string(),
                    sda.verification_uri()
                        .ok_or("Missing verification_uri")?
                        .to_string(),
                    sda.verification_uri_complete()
                        .ok_or("Missing verification_uri_complete")?
                        .to_string(),
                    sda.interval(),
                ))
            })
    }

    async fn poll_for_token(
        sso_oidc_client: &SsoOidcClient,
        client_id: &str,
        client_secret: &str,
        device_code: &str,
    ) -> Result<CreateTokenOutput, Box<dyn Error>> {
        loop {
            let response = sso_oidc_client
                .create_token()
                .client_id(client_id.to_string())
                .client_secret(client_secret.to_string())
                .grant_type("urn:ietf:params:oauth:grant-type:device_code")
                .device_code(device_code)
                .send()
                .await;

            if let Ok(token) = response {
                return Ok(token);
            }
        }
    }

    fn select_region() -> Result<String, Box<dyn Error>> {
        let regions = vec![
            "us-east-1",
            "us-east-2",
            "us-west-1",
            "us-west-2",
            "af-south-1",
            "ap-east-1",
            "ap-south-1",
            "ap-southeast-1",
            "ap-southeast-2",
            "ap-northeast-1",
            "ap-northeast-2",
            "ap-northeast-3",
            "ca-central-1",
            "eu-central-1",
            "eu-west-1",
            "eu-west-2",
            "eu-west-3",
            "eu-north-1",
            "eu-south-1",
            "me-south-1",
            "sa-east-1",
        ];

        let options = SkimOptionsBuilder::default()
            .height("10".to_string())
            .prompt("Select region: ".to_string())
            .multi(false)
            .build()
            .unwrap();

        let item_reader = SkimItemReader::default();
        let items = item_reader.of_bufread(Cursor::new(regions.join("\n")));

        let selected_items = Skim::run_with(&options, Some(items))
            .map(|out| out.selected_items)
            .unwrap_or_default();
        if let Some(selected) = selected_items.first() {
            println!(); // Ensure output appears on a new line
            Ok(selected.output().to_string())
        } else {
            Err("No region selected".into())
        }
    }

    async fn process_selected_accounts_and_roles(
        sso_client: &SsoClient,
        access_token: &str,
        selected_items: Vec<String>,
    ) -> Result<Credential, Box<dyn std::error::Error>> {
        for selected_output in selected_items {
            let parts: Vec<&str> = selected_output.split(" - ").collect();
            if parts.len() != 3 {
                eprintln!("Invalid selection format: {}", selected_output);
                continue;
            }

            let account_id = parts[0];
            let role_name = parts[2];

            let credentials_resp = sso_client
                .get_role_credentials()
                .account_id(account_id)
                .role_name(role_name)
                .access_token(access_token)
                .send()
                .await?;

            if let Some(credentials) = credentials_resp.role_credentials() {
                let access_key_id = credentials.access_key_id().unwrap_or("").to_string();
                let secret_access_key = credentials.secret_access_key().unwrap_or("").to_string();
                let session_token = credentials.session_token().unwrap_or("").to_string();

                let creds = Credential {
                    account_id: account_id.to_string(),
                    role_name: role_name.to_string(),
                    access_key_id: access_key_id.clone(),
                    secret_access_key: secret_access_key.clone(),
                    session_token: session_token.clone(),
                };

                println!();
                println!(
                    "Credentials fetched for Account ID: {}, Role: {}",
                    account_id, role_name
                );

                AwsSsoWorkflow::write_default_aws_credentials(
                    &access_key_id,
                    &secret_access_key,
                    &session_token,
                )?;

                return Ok(creds);
            } else {
                eprintln!(
                    "Failed to fetch credentials for Account ID: {}, Role: {}",
                    account_id, role_name
                );
            }
        }
        Err("No valid credentials found".into())
    }

    fn perform_fuzzy_search(
        account_role_strings: &[String],
    ) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        Skim::run_with(
            &SkimOptionsBuilder::default()
                .height("20".to_string())
                .multi(true)
                .prompt("Select accounts and roles: ".to_string())
                .build()
                .unwrap(),
            Some(
                SkimItemReader::default().of_bufread(Cursor::new(account_role_strings.join("\n"))),
            ),
        )
        .map(|out| {
            out.selected_items
                .iter()
                .map(|item| item.output().to_string())
                .collect()
        })
        .ok_or_else(|| "No selection made.".into())
    }

    fn extract_access_token(
        token_response: &CreateTokenOutput,
    ) -> Result<&str, Box<dyn std::error::Error>> {
        token_response
            .access_token()
            .ok_or_else(|| "Missing access_token".into())
    }

    async fn fetch_accounts_and_roles(
        sso_client: &SsoClient,
        access_token: &str,
    ) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let mut account_role_strings = Vec::new();
        let mut next_token = None;

        let mut account_ids = Vec::new();
        let mut account_names = Vec::new();

        loop {
            let mut request = sso_client.list_accounts().access_token(access_token);

            if let Some(token) = &next_token {
                request = request.next_token(token);
            }

            let accounts_resp = request.send().await?;
            let accounts = accounts_resp.account_list();

            if accounts.is_empty() {
                break;
            }

            for account in accounts {
                if let Some(account_id) = account.account_id() {
                    let account_name = account.account_name().unwrap_or("Unknown");
                    account_ids.push(account_id.to_string());
                    account_names.push(account_name.to_string());
                }
            }

            next_token = accounts_resp.next_token().map(|s| s.to_string());

            if next_token.is_none() {
                break;
            }
        }

        let semaphore = Arc::new(Semaphore::new(1));
        let mut tasks = vec![];

        for (account_id, account_name) in account_ids.into_iter().zip(account_names.into_iter()) {
            let sso_client = sso_client.clone();
            let access_token = access_token.to_string();
            let semaphore = semaphore.clone();

            let task = task::spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();

                let mut roles = Vec::new();
                let mut next_role_token = None;

                loop {
                    let mut roles_request = sso_client
                        .list_account_roles()
                        .account_id(&account_id)
                        .access_token(&access_token);

                    if let Some(token) = &next_role_token {
                        roles_request = roles_request.next_token(token);
                    }

                    match roles_request.send().await {
                        Ok(roles_resp) => {
                            for role in roles_resp.role_list() {
                                if let Some(role_name) = role.role_name() {
                                    roles.push(format!(
                                        "{} - {} - {}",
                                        account_id, account_name, role_name
                                    ));
                                }
                            }
                            next_role_token = roles_resp.next_token().map(|s| s.to_string());
                            if next_role_token.is_none() {
                                break;
                            }
                        }
                        Err(e) => {
                            eprintln!("Failed to fetch roles for {}: {}", account_id, e);
                            break;
                        }
                    }
                }
                roles
            });

            tasks.push(task);
        }

        for task in tasks {
            match task.await {
                Ok(roles) => account_role_strings.extend(roles),
                Err(e) => eprintln!("A role fetch task failed: {:?}", e),
            }
        }

        Ok(account_role_strings)
    }

    pub async fn run_workflow(&mut self) -> Result<Credential, Box<dyn Error>> {
        if self.start_url.trim().is_empty() {
            self.start_url = Self::prompt_input("Enter the AWS start URL")?;
        }
        if self.region.trim().is_empty() {
            self.region = Self::select_region()?;
        }

        println!(
            "Running AWS workflow with URL: {} and region: {}",
            self.start_url, self.region
        );

        let config: aws_config::SdkConfig = aws_config::defaults(BehaviorVersion::v2024_03_28())
            .region(Region::new(self.region.clone()))
            .load()
            .await;
        let sso_oidc_client = SsoOidcClient::new(&config);
        let (client_id, client_secret) =
            Self::register_client(&sso_oidc_client, "my-rust-sso-client", "public").await?;
        let (device_code, user_code, verification_uri, verification_uri_complete, _interval) =
            Self::start_device_authorization(
                &sso_oidc_client,
                &client_id,
                &client_secret,
                &self.start_url,
            )
            .await?;

        println!("Opening the verification page in your browser...");
        if webbrowser::open(&verification_uri_complete).is_ok() {
            println!("Please authenticate to continue.");
        } else {
            println!(
                "Could not open the browser. Please go to: {}",
                verification_uri
            );
            println!("Enter the user code: {}", user_code);
        }

        let token_response =
            Self::poll_for_token(&sso_oidc_client, &client_id, &client_secret, &device_code)
                .await?;
        let sso_client = SsoClient::new(&config);
        let access_token = Self::extract_access_token(&token_response)?;

        let account_role_strings =
            Self::fetch_accounts_and_roles(&sso_client, access_token).await?;
        if account_role_strings.is_empty() {
            return Err("No accounts or roles found".into());
        }

        let selected_items = Self::perform_fuzzy_search(&account_role_strings)?;
        if selected_items.is_empty() {
            return Err("No accounts selected".into());
        }

        let credentials =
            Self::process_selected_accounts_and_roles(&sso_client, access_token, selected_items)
                .await?;
        Ok(credentials)
    }

    fn prompt_input(prompt: &str) -> Result<String, Box<dyn Error>> {
        print!("{}: ", prompt);
        std::io::stdout().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        Ok(input.trim().to_string())
    }
}
