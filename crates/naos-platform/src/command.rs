use std::{io, process::Stdio};

use async_trait::async_trait;
use thiserror::Error;
use tokio::{io::AsyncWriteExt, process::Command};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandSpec {
    pub program: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
}

impl CommandSpec {
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            env: Vec::new(),
        }
    }

    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args = args.into_iter().map(Into::into).collect();
        self
    }

    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

impl CommandOutput {
    pub const fn success(&self) -> bool {
        self.status == 0
    }
}

#[derive(Debug, Error)]
pub enum CommandError {
    #[error("failed to spawn {program}")]
    Spawn {
        program: String,
        #[source]
        source: io::Error,
    },
    #[error("failed to write stdin for {program}")]
    Stdin {
        program: String,
        #[source]
        source: io::Error,
    },
    #[error("stdin is not supported by command runner for {program}")]
    StdinUnsupported { program: String },
    #[error("failed waiting for {program}")]
    Wait {
        program: String,
        #[source]
        source: io::Error,
    },
}

#[async_trait]
pub trait CommandRunner: Send + Sync {
    async fn run(&self, spec: CommandSpec) -> Result<CommandOutput, CommandError>;

    async fn run_with_stdin(
        &self,
        spec: CommandSpec,
        mut stdin: Vec<u8>,
    ) -> Result<CommandOutput, CommandError> {
        stdin.fill(0);
        Err(CommandError::StdinUnsupported {
            program: spec.program,
        })
    }
}

#[derive(Debug, Default)]
pub struct SystemCommandRunner;

#[async_trait]
impl CommandRunner for SystemCommandRunner {
    async fn run(&self, spec: CommandSpec) -> Result<CommandOutput, CommandError> {
        let output = Command::new(&spec.program)
            .args(&spec.args)
            .envs(spec.env.iter().map(|(key, value)| (key, value)))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|source| CommandError::Spawn {
                program: spec.program.clone(),
                source,
            })?;

        Ok(command_output(output))
    }

    async fn run_with_stdin(
        &self,
        spec: CommandSpec,
        mut stdin: Vec<u8>,
    ) -> Result<CommandOutput, CommandError> {
        let program = spec.program.clone();
        let mut child = Command::new(&spec.program)
            .args(&spec.args)
            .envs(spec.env.iter().map(|(key, value)| (key, value)))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|source| CommandError::Spawn {
                program: program.clone(),
                source,
            })?;

        let write_result = async {
            let mut pipe = child
                .stdin
                .take()
                .ok_or_else(|| CommandError::StdinUnsupported {
                    program: program.clone(),
                })?;
            pipe.write_all(&stdin)
                .await
                .map_err(|source| CommandError::Stdin {
                    program: program.clone(),
                    source,
                })?;
            pipe.shutdown()
                .await
                .map_err(|source| CommandError::Stdin {
                    program: program.clone(),
                    source,
                })
        }
        .await;

        stdin.fill(0);
        write_result?;

        let output = child
            .wait_with_output()
            .await
            .map_err(|source| CommandError::Wait { program, source })?;
        Ok(command_output(output))
    }
}

fn command_output(output: std::process::Output) -> CommandOutput {
    CommandOutput {
        status: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}
