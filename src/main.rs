use aws_sso::AwsSsoWorkflow;

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
