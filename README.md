# aws_sso

[![Crates.io](https://img.shields.io/crates/v/aws_sso.svg)](https://crates.io/crates/aws_sso)
[![Docs.rs](https://docs.rs/aws_sso/badge.svg)](https://docs.rs/aws_sso)
[![Build Status](https://img.shields.io/github/actions/workflow/status/davidwebstar34/aws_sso/rust.yml?branch=main)](https://github.com/davidwebstar34/aws_sso/actions?query=branch%3Amain)

A crate for managing AWS Single Sign-On (SSO) workflows.

This library provides utilities to interact with AWS SSO using asynchronous operations. It handles client registration, device authorization, token polling, and writing AWS credentials directly to your `~/.aws/credentials` file.

## Getting Started

Add the following to your `Cargo.toml`:

## Getting started

Add the following dependency to your `Cargo.toml`:

```
[dependencies]
aws_sso = "1.0.0"

```

## Usage

### Interactive Mode

If you do not supply a start URL or region, the library will prompt you interactively.

```
use aws_sso::AwsSsoWorkflow;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // With no parameters provided, the workflow prompts interactively.
    let mut workflow = AwsSsoWorkflow::default();
    let credential = workflow.run_workflow().await?;

    println!("Account ID: {}", credential.account_id);
    println!("Role Name: {}", credential.role_name);
    println!("Access Key ID: {}", credential.access_key_id);
    println!("Secret Access Key: {}", credential.secret_access_key);
    println!("Session Token: {}", credential.session_token);
    Ok(())
}
```

### Non-interactive Mode

If you do not supply a start URL or region, the library will prompt you interactively.

```
use aws_sso::AwsSsoWorkflow;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut workflow = AwsSsoWorkflow {
        start_url: "https://your.awsapps.com/start".to_string(),
        region: "eu-west-1".to_string(),
        ..Default::default()
    };

    let credential = workflow.run_workflow().await?;
    println!("Account ID: {}", credential.account_id);
    println!("Role Name: {}", credential.role_name);
    println!("Access Key ID: {}", credential.access_key_id);
    println!("Secret Access Key: {}", credential.secret_access_key);
    println!("Session Token: {}", credential.session_token);
    Ok(())
}
```

## License

- Apache License, Version 2.0 or http://www.apache.org/licenses/LICENSE-2.0

### Final Thoughts

- **Library vs. Binary:**  
  Your library now handles the core AWS SSO workflow and allows optional parameters. You can write a separate binary that uses your library and handles CLI arguments (using `clap` or similar) as needed.
