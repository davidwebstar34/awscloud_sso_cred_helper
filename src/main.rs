use aws_sso::AwsSsoWorkflow;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut workflow = AwsSsoWorkflow {
        start_url: "https://webstar34.awsapps.com/start".into(),
        region: "eu-west-1".into(),
        ..Default::default()
    };

    let _ = workflow.run_workflow().await?;

    Ok(())
}
