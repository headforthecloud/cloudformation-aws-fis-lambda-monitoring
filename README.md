# terraform-aws-fis-lambda-monitoring
This repository contains an example configuration which can be used to demonstrate how to use Amazon's Fault Injection Service (FIS) to test monitoring in a serverless environment.

It deploys the following configuration via a CloudFormation SAM template:

![](infra.png)

* an example lambda, configured to use the FIS lambda layer,
* an API Gateway to access the lambda,
* an example CloudWatch dashboard,
* a FIS experiment template which you can run to test the lambda.

## Deploying the Configuration
The template is written using the AWS Serverless Application Model (SAM) which has the advantage that it handles the deployment of lambda code without the need for a separate packing pipeline.

You'll need to have the SAM CLI tools installed - this is well documented in the [SAM installation documents](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html).

With the CLI tool installed, and a set of AWS Credentials configured for use, follow these steps:

```
$ git clone git@github.com:headforthecloud/cloudformation-aws-fis-lambda-monitoring.git

$ cd cloudformation-aws-fis-lambda-monitoring.git

$ sam build

$ sam deploy --guided.   # follow the prompts
```


## Python Development Setup
If you're just wanting to deploy the code in this repository, this section doesn't matter but in case you're interested ...

This project uses [uv](https://docs.astral.sh/uv/) for Python package management and virtual environment handling.


### Prerequisites

Install uv if you haven't already:

```bash
# macOS with Homebrew
brew install uv

# macOS/Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# Or with pip
pip install uv
```

### Setting up the Development Environment

1. Create and activate a virtual environment with the project dependencies:

```bash
uv sync
```

This will:
- Create a virtual environment in `.venv/`
- Install all project dependencies and dev dependencies
- Lock the dependencies in `uv.lock`

2. Activate the virtual environment:

```bash
source .venv/bin/activate
```

Or use uv to run commands directly in the virtual environment without activation:

```bash
uv run <command>
```

### Running Tests

Run the test suite using pytest:

```bash
# With activated virtual environment
pytest

# Or directly with uv
uv run pytest

# Run with coverage
uv run pytest --cov=src

# Run with verbose output
uv run pytest -v
```

### Other Useful Commands

```bash
# Install new dependencies
uv add <package-name>

# Install dev dependencies
uv add --dev <package-name>

# Update dependencies
uv sync --upgrade

# Run the lambda function locally (if applicable)
uv run python src/lambda_function.py
```