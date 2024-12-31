# aws_sso

[![Crates.io](https://img.shields.io/crates/v/aws_sso.svg)](https://crates.io/crates/aws_sso)
[![Docs.rs](https://docs.rs/aws_sso/badge.svg)](https://docs.rs/aws_sso)
[![Build Status](https://img.shields.io/github/workflow/status/davidwebstar34/aws_sso/build/main)](https://github.com/davidwebstar34/aws_sso/actions?query=workflow%3Abuild)

A simple crate for working with AWS SSO credentials and saving them directly to your ~/.aws/credentials without needing to copy the credentials to your cli.

## Getting started

Add the following dependency to your `Cargo.toml`:

```
[dependencies]
aws_sso = "1.0.0"

```

## Usage

This library provides utilities to interact with AWS SSO using async operations. Below is an example usage.

## Example: Registering an AWS SSO Client

You can register a new AWS SSO client like this:

```

use aws_sso::AwsSsoWorkflow;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut workflow = AwsSsoWorkflow::default();
    let credential = workflow.run_workflow().await?;

    println!("Account ID: {}", credential.account_id);
    println!("Role Name: {}", credential.role_name);
    println!("Access Key ID: {}", credential.access_key_id);
    println!("Secret Access Key: {}", credential.secret_access_key);
    println!("Session Token: {}", credential.session_token);
    println!("---------------------------------");

    Ok(())
}

```

## License

- Apache License, Version 2.0 or http://www.apache.org/licenses/LICENSE-2.0
