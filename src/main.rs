use aws_sso::AwsSsoWorkflow;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut workflow = AwsSsoWorkflow::default();
    let _ = workflow.run_workflow().await?;

    // println!("Account ID: {}", credential.account_id);
    // println!("Role Name: {}", credential.role_name);
    // println!("Access Key ID: {}", credential.access_key_id);
    // println!("Secret Access Key: {}", credential.secret_access_key);
    // println!("Session Token: {}", credential.session_token);
    // println!("---------------------------------");

    Ok(())
}
