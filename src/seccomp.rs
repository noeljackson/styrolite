/// A seccomp-bpf filter program.
///
/// The caller builds the BPF program as a list of (code, jt, jf, k)
/// instructions. Styrolite installs it via `prctl(PR_SET_SECCOMP)` after
/// capabilities are set but before `execvpe()`.
///
/// Requires `no_new_privs = true` on the `ExecutableSpec`.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SeccompFilter {
    /// BPF instructions as (code, jt, jf, k) tuples.
    pub instructions: Vec<(u16, u8, u8, u32)>,
}

impl SeccompFilter {
    /// Install the seccomp filter via `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER)`.
    ///
    /// # Safety
    ///
    /// Must be called after `prctl(PR_SET_NO_NEW_PRIVS, 1)` and before `execvpe()`.
    /// The caller must ensure the BPF program is valid.
    pub unsafe fn install(&self) -> std::io::Result<()> {
        let filters: Vec<libc::sock_filter> = self
            .instructions
            .iter()
            .map(|&(code, jt, jf, k)| libc::sock_filter { code, jt, jf, k })
            .collect();
        let prog = libc::sock_fprog {
            len: filters.len() as u16,
            filter: filters.as_ptr() as *mut _,
        };
        if libc::prctl(
            libc::PR_SET_SECCOMP,
            2, // SECCOMP_MODE_FILTER
            &prog as *const _ as libc::c_ulong,
        ) != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}
