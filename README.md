# aws_sso

[![Crates.io](https://img.shields.io/crates/v/aws_sso.svg)](https://crates.io/crates/aws_sso)
[![Docs.rs](https://docs.rs/aws_sso/badge.svg)](https://docs.rs/aws_sso)
[![Build Status](https://github.com/your_username/aws_sso/actions/workflows/ci.yml/badge.svg)](https://github.com/your_username/aws_sso/actions)

A simple crate for working with AWS SSO operations.

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

use aws_sso::aws::AwsSsoWorkflow;

fn main() -> Result<(), Box<dyn std::error::Error>> {
let mut workflow = AwsSsoWorkflow::default();
let runtime = tokio::runtime::Runtime::new()?;

    let credentials = runtime.block_on(workflow.run_workflow())?;

    if credentials.is_empty() {
        println!("No credentials retrieved.");
    } else {
        for (account_id, role_name, access_key_id, secret_access_key, session_token) in credentials
        {
            println!("Account ID: {}", account_id);
            println!("Role Name: {}", role_name);
            println!("Access Key ID: {}", access_key_id);
            println!("Secret Access Key: {}", secret_access_key);
            println!("Session Token: {}", session_token);
            println!("---------------------------------");
        }
    }

    Ok(())

}

```

## License

- Apache License, Version 2.0 or http://www.apache.org/licenses/LICENSE-2.0
