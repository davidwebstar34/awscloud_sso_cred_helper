pub mod aws;
use crate::aws::AwsSsoWorkflow;
use std::error::Error;
use std::future::Future;

pub fn create_workflow() -> Result<AwsSsoWorkflow, Box<dyn Error>> {
    Ok(AwsSsoWorkflow::default())
}

pub trait Workflow<'a> {
    type Fut: Future<Output = Result<(), Box<dyn std::error::Error>>>;

    fn run(&'a mut self) -> Self::Fut;
}
