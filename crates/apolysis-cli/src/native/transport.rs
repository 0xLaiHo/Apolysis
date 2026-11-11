// SPDX-License-Identifier: Apache-2.0

//! Content stays in memory. The privileged command line contains only a private
//! socket path, and application stdio is never used for controller messages.

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::{Command, ExitStatus};
use std::time::Duration;

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::signal::unix::{signal, SignalKind};

pub(super) const FRAME_LIMIT: usize = 1024 * 1024;

pub(super) async fn send<T: Serialize, W: AsyncWrite + Unpin>(
    stream: &mut W,
    value: &T,
) -> Result<(), String> {
    let data = serde_json::to_vec(value).map_err(|_| "cannot encode native control message")?;
    if data.len() > FRAME_LIMIT {
        return Err("native control message is too large".into());
    }
    stream
        .write_u32(data.len() as u32)
        .await
        .map_err(|_| "native control channel closed")?;
    stream
        .write_all(&data)
        .await
        .map_err(|_| "native control channel closed".into())
}

pub(super) async fn receive<T: DeserializeOwned, R: AsyncRead + Unpin>(
    stream: &mut R,
) -> Result<T, String> {
    let length = stream
        .read_u32()
        .await
        .map_err(|_| "native control channel closed")? as usize;
    if length == 0 || length > FRAME_LIMIT {
        return Err("invalid native control frame length".into());
    }
    let mut bytes = vec![0; length];
    stream
        .read_exact(&mut bytes)
        .await
        .map_err(|_| "native control channel closed")?;
    serde_json::from_slice(&bytes).map_err(|_| "invalid native control message".into())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Launch {
    pub executable: String,
    pub args: Vec<String>,
}

/// This child runs as the original user. fd 3 is a private, inherited pipe;
/// prompts and arguments are never serialized into a file or sudo argv.
pub(super) fn exec_gated() -> Result<i32, String> {
    // A direct invocation must not take ownership of Tokio's unrelated fd 3.
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: fstat initializes metadata; fcntl only queries the descriptor.
    let valid = unsafe {
        libc::geteuid() != 0
            && libc::fstat(3, metadata.as_mut_ptr()) == 0
            && metadata.assume_init().st_mode & libc::S_IFMT == libc::S_IFIFO
            && libc::fcntl(3, libc::F_GETFL) & libc::O_ACCMODE == libc::O_RDONLY
    };
    if !valid {
        return Err("native launch gate is unavailable".into());
    }
    // SAFETY: the private launcher establishes fd 3 exclusively for this child.
    let mut pipe = unsafe { File::from_raw_fd(3) };
    let mut length = [0_u8; 4];
    pipe.read_exact(&mut length)
        .map_err(|_| "native launch gate closed")?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > FRAME_LIMIT {
        return Err("invalid native launch frame".into());
    }
    let mut bytes = vec![0; length];
    pipe.read_exact(&mut bytes)
        .map_err(|_| "native launch gate closed")?;
    let launch: Launch =
        serde_json::from_slice(&bytes).map_err(|_| "invalid native launch description")?;
    let mut go = [0_u8; 1];
    pipe.read_exact(&mut go)
        .map_err(|_| "capture did not release native launch")?;
    if go != [1] {
        return Err("capture rejected native launch".into());
    }
    drop(pipe);
    let _error = Command::new(launch.executable).args(launch.args).exec();
    Err("could not execute the selected native application".into())
}

pub(super) struct NativeChild {
    pub pid: u32,
    gate: Option<tokio::fs::File>,
    reaped: bool,
    group_owned: bool,
}

impl NativeChild {
    pub async fn spawn(
        binary: &Path,
        launch: &Launch,
        directory: &Path,
        environment: &[(String, String)],
    ) -> Result<Self, String> {
        let mut fds = [0; 2];
        // SAFETY: pipe2 writes exactly two valid descriptors into fds.
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            return Err("cannot create native launch gate".into());
        }
        // SAFETY: successful pipe2 transfers ownership of two distinct fds.
        let read = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let write = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        let read_fd = read.as_raw_fd();
        // SAFETY: getpid has no memory arguments.
        let parent_pid = unsafe { libc::getpid() };
        let mut command = Command::new(binary);
        command
            .arg("_native-exec")
            .current_dir(directory)
            .envs(environment.iter().cloned())
            .env("PWD", directory);
        // SAFETY: only async-signal-safe syscalls in the post-fork closure.
        // No setsid: the native application keeps the real controlling TTY.
        unsafe {
            command.pre_exec(move || {
                if libc::setpgid(0, 0) != 0
                    || libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) != 0
                    || libc::getppid() != parent_pid
                    || libc::dup2(read_fd, 3) < 0
                    || libc::fcntl(3, libc::F_SETFD, 0) < 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = command
            .spawn()
            .map_err(|_| "cannot start unprivileged native launch gate")?;
        drop(read);
        let mut child = Self {
            pid: child.id(),
            gate: Some(tokio::fs::File::from_std(File::from(write))),
            reaped: false,
            group_owned: true,
        };
        let writer = child.gate.as_mut().ok_or("missing native launch gate")?;
        tokio::time::timeout(Duration::from_secs(10), send(writer, launch))
            .await
            .map_err(|_| "native launch gate timed out")??;
        Ok(child)
    }

    pub async fn release(&mut self) -> Result<(), String> {
        let mut gate = self
            .gate
            .take()
            .ok_or("native launch gate already closed")?;
        gate.write_all(&[1])
            .await
            .map_err(|_| "native launch gate closed")?;
        gate.flush()
            .await
            .map_err(|_| "native launch gate closed".into())
    }

    pub fn signal_group(&self, signal: i32) {
        if !self.group_owned {
            return;
        }
        // SAFETY: this process group was created exclusively for the application.
        unsafe { libc::kill(-(self.pid as i32), signal) };
    }

    pub async fn wait(&mut self, terminal: &mut Terminal) -> Result<ExitStatus, String> {
        let mut interrupt = signal(SignalKind::interrupt())
            .map_err(|_| "cannot install native interrupt handler")?;
        let mut terminate = signal(SignalKind::terminate())
            .map_err(|_| "cannot install native termination handler")?;
        let mut deadline = None;
        let mut kill_deadline = None;
        loop {
            // Keep an exited leader as a zombie until its group is cleaned up:
            // its PID/PGID cannot then be recycled underneath a delayed signal.
            let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
            // SAFETY: waitid initializes siginfo for this owned child only.
            let result = unsafe {
                libc::waitid(
                    libc::P_PID,
                    self.pid,
                    info.as_mut_ptr(),
                    libc::WEXITED
                        | libc::WSTOPPED
                        | libc::WCONTINUED
                        | libc::WNOHANG
                        | libc::WNOWAIT,
                )
            };
            // SAFETY: zero initialization covers the no-event case; waitid fills the rest.
            let info = unsafe { info.assume_init() };
            if result == 0 && unsafe { info.si_pid() } == self.pid as i32 {
                let exiting = matches!(
                    info.si_code,
                    libc::CLD_EXITED | libc::CLD_KILLED | libc::CLD_DUMPED
                );
                if exiting {
                    self.signal_group(libc::SIGTERM);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    self.signal_group(libc::SIGKILL);
                    self.group_owned = false;
                }
                let mut status = 0;
                // SAFETY: consume the previously inspected status, including stop/continue.
                if unsafe {
                    libc::waitpid(
                        self.pid as i32,
                        &mut status,
                        libc::WNOHANG | libc::WUNTRACED | libc::WCONTINUED,
                    )
                } != self.pid as i32
                {
                    return Err("native process status changed unexpectedly".into());
                }
                if exiting {
                    self.reaped = true;
                    return Ok(ExitStatus::from_raw(status));
                }
                if libc::WIFSTOPPED(status) {
                    terminal.suspend();
                    // Let the invoking shell manage suspend/resume of this job.
                    // SAFETY: SIGSTOP suspends this supervisor until the shell resumes it.
                    unsafe { libc::kill(libc::getpid(), libc::SIGSTOP) };
                    terminal.foreground(self.pid)?;
                    self.signal_group(libc::SIGCONT);
                }
            } else if result < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() != std::io::ErrorKind::Interrupted {
                    return Err("cannot reap native application".into());
                }
            }
            if deadline.is_some_and(|value| std::time::Instant::now() >= value) {
                self.signal_group(libc::SIGKILL);
                deadline = None;
                kill_deadline = Some(std::time::Instant::now() + Duration::from_secs(2));
            }
            if kill_deadline.is_some_and(|value| std::time::Instant::now() >= value) {
                return Err("native application did not exit after forced cleanup".into());
            }
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(25)) => {},
                _ = interrupt.recv() => self.signal_group(libc::SIGINT),
                _ = terminate.recv() => {
                    self.signal_group(libc::SIGTERM);
                    deadline = Some(std::time::Instant::now() + Duration::from_secs(5));
                },
            }
        }
    }
}

impl Drop for NativeChild {
    fn drop(&mut self) {
        self.gate.take();
        self.signal_group(libc::SIGKILL);
        if !self.reaped {
            // Never block indefinitely on an uninterruptible kernel task.
            for _ in 0..10 {
                // SAFETY: nonblocking reap of this owned child only.
                if unsafe { libc::waitpid(self.pid as i32, std::ptr::null_mut(), libc::WNOHANG) }
                    != 0
                {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

pub(super) struct Terminal {
    original_group: Option<i32>,
    modes: Option<libc::termios>,
    active: bool,
    native_modes: Option<libc::termios>,
}

impl Terminal {
    pub fn new() -> Self {
        // SAFETY: these calls inspect stdin's terminal metadata only.
        let original_group = unsafe { libc::tcgetpgrp(0) };
        let mut modes = std::mem::MaybeUninit::<libc::termios>::uninit();
        let modes = if original_group > 0 && unsafe { libc::tcgetattr(0, modes.as_mut_ptr()) } == 0
        {
            // SAFETY: successful tcgetattr initialized modes.
            Some(unsafe { modes.assume_init() })
        } else {
            None
        };
        Self {
            original_group: (original_group > 0).then_some(original_group),
            modes,
            active: false,
            native_modes: None,
        }
    }

    pub fn foreground(&mut self, pid: u32) -> Result<(), String> {
        if self.original_group.is_some() {
            if terminal_update(pid as i32, self.native_modes.as_ref()) != 0 {
                return Err("cannot give the native application its terminal".into());
            }
            self.active = true;
            self.native_modes = None;
        }
        Ok(())
    }

    pub fn restore(&mut self) {
        if self.active {
            if let Some(group) = self.original_group {
                terminal_update(group, self.modes.as_ref());
            }
            self.active = false;
        }
    }

    fn suspend(&mut self) {
        let mut modes = std::mem::MaybeUninit::<libc::termios>::uninit();
        // SAFETY: capture the native program's current terminal mode before returning the TTY.
        if self.active && unsafe { libc::tcgetattr(0, modes.as_mut_ptr()) } == 0 {
            self.native_modes = Some(unsafe { modes.assume_init() });
        }
        self.restore();
    }
}

impl Drop for Terminal {
    fn drop(&mut self) {
        self.restore();
    }
}

fn terminal_update(group: i32, modes: Option<&libc::termios>) -> i32 {
    // SAFETY: block SIGTTOU on this thread while restoring a background parent's
    // terminal ownership. Restore the previous mask, never change global handlers.
    unsafe {
        let mut set = std::mem::zeroed();
        let mut previous = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGTTOU);
        libc::pthread_sigmask(libc::SIG_BLOCK, &set, &mut previous);
        let result = libc::tcsetpgrp(0, group);
        if let Some(modes) = modes {
            libc::tcsetattr(0, libc::TCSANOW, modes);
        }
        libc::pthread_sigmask(libc::SIG_SETMASK, &previous, std::ptr::null_mut());
        result
    }
}

pub(super) fn exit_code(status: ExitStatus) -> i32 {
    status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(1))
}

pub(super) fn atomic_write(path: &Path, data: &[u8]) -> Result<(), String> {
    let parent = path.parent().ok_or("native output has no parent")?;
    let mut file = tempfile::NamedTempFile::new_in(parent)
        .map_err(|_| "cannot prepare native evidence output")?;
    file.write_all(data)
        .map_err(|_| "cannot write native evidence output")?;
    file.persist(path)
        .map_err(|_| "cannot publish native evidence output")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn control_frames_keep_argument_boundaries_and_reject_oversized_input() {
        let (mut left, mut right) = tokio::io::duplex(4096);
        let launch = Launch {
            executable: "/bin/echo".into(),
            args: vec!["two words".into(), "--agent".into(), "a\nb".into()],
        };
        send(&mut left, &launch).await.unwrap();
        let parsed: Launch = receive(&mut right).await.unwrap();
        assert_eq!(parsed.args, launch.args);
        left.write_u32((FRAME_LIMIT + 1) as u32).await.unwrap();
        assert!(receive::<Launch, _>(&mut right).await.is_err());
    }

    #[test]
    fn atomic_publication_replaces_symlink_without_touching_target() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        std::fs::write(&target, "private").unwrap();
        let output = dir.path().join("output");
        std::os::unix::fs::symlink(&target, &output).unwrap();
        atomic_write(&output, b"report").unwrap();
        assert_eq!(std::fs::read_to_string(target).unwrap(), "private");
        assert_eq!(std::fs::read_to_string(output).unwrap(), "report");
    }

    #[test]
    fn signal_status_preserves_shell_exit_convention() {
        assert_eq!(exit_code(ExitStatus::from_raw(7 << 8)), 7);
        assert_eq!(exit_code(ExitStatus::from_raw(libc::SIGTERM)), 143);
    }
}
