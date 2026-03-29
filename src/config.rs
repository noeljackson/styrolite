use crate::caps::CapabilityBit;
use crate::namespace::Namespace;
use crate::seccomp::SeccompFilter;
use anyhow::{Result, bail};
use libc::{c_int, gid_t, pid_t, uid_t};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::str::FromStr;

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct AttachRequest {
    /// The PID to join in the namespace.
    pub pid: pid_t,

    /// When true, `pid` is already the exact target process whose namespaces
    /// should be joined. When false, attach resolves the first child of `pid`
    /// (or falls back to `pid` if no visible child exists).
    #[serde(default)]
    pub pid_is_target: bool,

    /// The executable specification for the new process created in this
    /// container.
    pub exec: ExecutableSpec,

    /// An opaque string which is used to designate workload identity.
    /// In the case of attaching to a pre-existing container, it should be
    /// the UUID of the target container.
    /// If this is unset, then we will not correlate resource usage from
    /// the attached process with the rest of the resource usage of the
    /// container.
    pub workload_id: Option<String>,

    /// An optional path to a cgroup2 filesystem to attach to. See
    /// CreateRequest::cgroupfs for a more detailed explanation.
    pub cgroupfs: Option<String>,

    /// A set of namespaces to join.
    pub namespaces: Option<Vec<Namespace>>,
    /// Capabilities for this attachment.
    pub capabilities: Option<Capabilities>,
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct IdMapping {
    /// The base UID/GID inside the user namespace.
    pub base_nsid: u32,

    /// The base UID/GID outside the user namespace.
    pub base_hostid: u32,

    /// The number of UID/GIDs to remap.
    pub remap_count: u32,
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct ExecutableSpec {
    /// Executable path (not resolved by PATH)
    pub executable: Option<String>,

    /// All arguments to the executable.
    pub arguments: Option<Vec<String>>,

    /// A working directory, assuming that the rootfs is /.
    pub working_directory: Option<String>,

    /// Environment variables, order kept by insertion.
    pub environment: Option<BTreeMap<String, String>>,

    /// An optional UID to assume.
    /// These UIDs are relative to the user namespace that is optionally set up.
    pub uid: Option<uid_t>,

    /// An optional GID to assume.
    /// These GIDs are relative to the user namespace that is optionally set up.
    pub gid: Option<gid_t>,

    /// An optional set of process-specific resource limits.
    /// If this set is not provided, setrlimit(2) will not be called.
    pub process_limits: Option<ProcessResourceLimits>,

    /// If `true`, sets `PR_SET_NO_NEW_PRIVS` before
    /// spawning the target executable.
    pub no_new_privs: bool,

    /// An optional seccomp-bpf filter program. Applied after capabilities
    /// are set and `PR_SET_NO_NEW_PRIVS` is enabled, but before `execvpe()`.
    /// Requires `no_new_privs = true`.
    #[serde(default)]
    pub seccomp: Option<SeccompFilter>,
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct CreateRequest {
    /// An opaque string which is used to designate workload identity.
    /// Should typically be a UUID, however, if not set, the supervisor
    /// process ID will be used as a limited fallback.
    pub workload_id: Option<String>,

    /// A bare rootfs. It should be assumed the rootfs is writable via a read-only layer and a writeable backing layer.
    /// It should be assumed the rootfs might already have mounts.
    /// It should be assumed that the rootfs might already have proc, sys, and dev mounts. (This might need to change?)
    pub rootfs: Option<String>,

    /// Whether the rootfs should be mounted readonly.
    pub rootfs_readonly: Option<bool>,

    /// The executable specification for the initial process created in this
    /// container.
    pub exec: ExecutableSpec,

    /// A set of UID mapping rules, used to set up the user namespace.
    /// If empty, a user namespace will not be created.
    pub uid_mappings: Option<Vec<IdMapping>>,

    /// A set of GID mapping rules, used to set up the user namespace.
    /// If empty, a user namespace will not be created.
    pub gid_mappings: Option<Vec<IdMapping>>,

    /// An optional set of mount specifications.
    /// `/proc` will be mounted regardless of whether a mount specification is configured.
    pub mounts: Option<Vec<MountSpec>>,

    /// An optional set of resource limits.
    /// If this set is not provided, no cgroups will be configured.
    pub limits: Option<ResourceLimits>,

    /// An optional path to a cgroup2 filesystem for setting resource limits.
    /// If this is not provided, we will attempt to set limits using the root
    /// hierarchy, but unprivileged users will require their own cgroup
    /// delegation. Ideally, this should be a path to that delegation.
    pub cgroupfs: Option<String>,

    /// An optional hostname to be used for the container.
    /// If this is not provided, the workload identity will be used.
    pub hostname: Option<String>,

    /// An optional list of mutations to apply to the container FS.
    pub mutations: Option<Vec<Mutation>>,

    /// A set of namespaces to join.
    pub namespaces: Option<Vec<Namespace>>,

    /// Whether setgroups(2) should be denied in this container.
    pub setgroups_deny: Option<bool>,

    /// Capabilities for this container.
    pub capabilities: Option<Capabilities>,

    /// Whether the two-stage userns setup should be skipped.
    pub skip_two_stage_userns: Option<bool>,

    /// Optional file descriptor in the supervisor process where the PID of the
    /// initial workload child should be reported as a native-endian `i32`.
    ///
    /// This lets callers persist the real attach target PID without guessing
    /// later via `/proc` topology.
    pub workload_pid_report_fd: Option<c_int>,
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct Capabilities {
    /// Capabilities to raise on the container.
    pub raise: Option<Vec<String>>,
    /// Ambient capabilities to raise on the container.
    pub raise_ambient: Option<Vec<String>>,
    /// Capabilities to drop on the container.
    pub drop: Option<Vec<String>>,
}

impl Capabilities {
    pub fn names_as_bits(names: &[String]) -> Result<Vec<CapabilityBit>> {
        let mut caps = HashSet::new();
        for name in names {
            let bit = CapabilityBit::from_str(name).ok();
            if let Some(bit) = bit {
                caps.insert(bit);
            } else if name.to_uppercase() == "ALL" {
                caps.extend(CapabilityBit::ALL.iter().cloned());
            } else {
                bail!("unknown capability: {}", name);
            }
        }
        Ok(caps.into_iter().collect())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum Config {
    Create(CreateRequest),
    Attach(AttachRequest),
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct CreateDirMutation {
    /// The directory inside the container FS to create.
    pub target: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum Mutation {
    CreateDir(CreateDirMutation),
}

pub trait Wrappable {
    /// Process a configuration request.
    fn wrap(&self) -> Result<()>;
}

pub trait Validatable {
    /// Validate the configuration and error if the configuration is invalid.
    fn validate(&self) -> Result<()>;
}

impl Validatable for CreateRequest {
    fn validate(&self) -> Result<()> {
        Ok(())
    }
}

impl Validatable for AttachRequest {
    fn validate(&self) -> Result<()> {
        Ok(())
    }
}

pub trait Configurable: Serialize + Validatable {
    fn encapsulate(self) -> Result<Config>;
}

impl Configurable for CreateRequest {
    fn encapsulate(self) -> Result<Config> {
        Ok(Config::Create(self))
    }
}

impl Configurable for AttachRequest {
    fn encapsulate(self) -> Result<Config> {
        Ok(Config::Attach(self))
    }
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct MountSpec {
    /// The source location or device node for a mount point.
    pub source: Option<String>,

    /// The target location of the mount point.
    pub target: String,

    /// The filesystem of the mount point.
    pub fstype: Option<String>,

    /// Whether the mount point is a bind mount.
    pub bind: bool,

    /// Whether the mount point should recurse.
    pub recurse: bool,

    /// Whether the mount point should be unshared, e.g. MS_PRIVATE flag.
    pub unshare: bool,

    /// Whether the mount point should be mounted with safety options, e.g. MS_NOSUID.
    pub safe: bool,

    /// Whether the target mount point should be created as a directory if it
    /// does not exist.
    pub create_mountpoint: bool,

    /// Whether the mount point should be mounted readonly.
    pub read_only: bool,

    /// Optional mount data (e.g., "size=64m" for tmpfs).
    pub data: Option<String>,
}

pub trait Mountable {
    /// Perform the mount operation.
    fn mount(&self) -> Result<()>;

    /// Pivot, making this mount point the new rootfs.
    /// The old rootfs is unmounted as a side effect.
    fn pivot(&self) -> Result<()>;

    /// Makes a mountpoint read-only after the fact.
    fn seal(&self) -> Result<()>;
}

pub type ResourceLimits = BTreeMap<String, String>;

pub trait Mutatable {
    fn mutate(&self, rootfs: &str) -> Result<()>;
}

/// Resource limits for processes inside the container itself.
/// Each limit can be left unchanged, set to a concrete value, or set to
/// unlimited explicitly.
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct ProcessResourceLimits {
    /// The maximum size in bytes for container processes to use as virtual address
    /// space.  See RLIMIT_AS in setrlimit(2) for more detail.
    #[serde(default, skip_serializing_if = "ProcessResourceLimitValue::is_keep")]
    pub address_space_size: ProcessResourceLimitValue,

    /// The maximum size in bytes for any core file created when a container process
    /// terminates from crashing.  See RLIMIT_CORE in setrlimit(2) for more detail.
    #[serde(default, skip_serializing_if = "ProcessResourceLimitValue::is_keep")]
    pub core_size: ProcessResourceLimitValue,

    /// The maximum amount of CPU seconds a process can consume before a process is
    /// terminated.  See RLIMIT_CPU in setrlimit(2) for more detail.
    #[serde(default, skip_serializing_if = "ProcessResourceLimitValue::is_keep")]
    pub cpu_time: ProcessResourceLimitValue,

    /// The maximum amount of heap memory that a process can consume before further
    /// heap allocations fail.  See RLIMIT_DATA in setrlimit(2) for more detail.
    #[serde(default, skip_serializing_if = "ProcessResourceLimitValue::is_keep")]
    pub data_space_size: ProcessResourceLimitValue,

    /// The maximum amount of written bytes to disk that a process can write before
    /// further writes fail.  See RLIMIT_FSIZE in setrlimit(2) for more detail.
    #[serde(default, skip_serializing_if = "ProcessResourceLimitValue::is_keep")]
    pub file_size: ProcessResourceLimitValue,

    /// The maximum amount, in bytes, of memory pages which can be locked by a process.
    /// This value is rounded down to the nearest page size boundary.
    /// See RLIMIT_MEMLOCK in setrlimit(2) for more detail.
    #[serde(default, skip_serializing_if = "ProcessResourceLimitValue::is_keep")]
    pub locked_space_size: ProcessResourceLimitValue,

    /// The maximum amount, in bytes, of memory pages which can be allocated for POSIX
    /// message queues.  The value is rounded down to the nearest page size boundary.
    /// See RLIMIT_MSGQUEUE in setrlimit(2) for more detail.
    #[serde(default, skip_serializing_if = "ProcessResourceLimitValue::is_keep")]
    pub msgqueue_size: ProcessResourceLimitValue,

    /// The maximum niceness level ceiling for a given process.  The calculated value
    /// inside the kernel starts at 20 and is subtracted by the supplied ceiling value.
    /// See RLIMIT_NICE in setrlimit(2) for more detail.
    #[serde(default, skip_serializing_if = "ProcessResourceLimitValue::is_keep")]
    pub nice_ceiling: ProcessResourceLimitValue,

    /// The maximum number of open file descriptors for processes inside the container.
    /// See RLIMIT_NOFILE in setrlimit(2) for more detail.
    #[serde(default, skip_serializing_if = "ProcessResourceLimitValue::is_keep")]
    pub open_files: ProcessResourceLimitValue,

    /// The maximum number of threads/LWPs which can be a child of a given process.
    /// See RLIMIT_NPROC in setrlimit(2) for more detail.
    #[serde(default, skip_serializing_if = "ProcessResourceLimitValue::is_keep")]
    pub thread_limit: ProcessResourceLimitValue,

    /// The maximum amount of resident memory allowed for a given process.
    /// See RLIMIT_RSS in setrlimit(2) for more detail.
    #[serde(default, skip_serializing_if = "ProcessResourceLimitValue::is_keep")]
    pub resident_space_size: ProcessResourceLimitValue,

    /// The maximum realtime niceness level ceiling for a given process.
    /// See RLIMIT_RTPRIO in setrlimit(2) for more detail.
    #[serde(default, skip_serializing_if = "ProcessResourceLimitValue::is_keep")]
    pub real_time_priority: ProcessResourceLimitValue,

    /// The maximum amount of CPU microseconds a process may spend before making
    /// a blocking syscall or otherwise being preempted by the kernel scheduler.
    /// See RLIMIT_RTTIME in setrlimit(2) for more detail.
    #[serde(default, skip_serializing_if = "ProcessResourceLimitValue::is_keep")]
    pub real_time_limit: ProcessResourceLimitValue,

    /// The maximum number of pending signals that can be delivered to a process
    /// at any time.  See RLIMIT_SIGPENDING in setrlimit(2) for more detail.
    #[serde(default, skip_serializing_if = "ProcessResourceLimitValue::is_keep")]
    pub pending_signal_limit: ProcessResourceLimitValue,

    /// The stack size that should be used for the main thread's stack when creating
    /// new processes.  On Linux, this normally defaults to 8MB, although the stack
    /// size of other threads is dependent on the system's C library: GLIBC defaults
    /// to an 8MB limit for secondary threads, while musl defaults to 80KB unless a
    /// different stack size annotation is present on the binary being run.
    /// See RLIMIT_STACK in setrlimit(2) for more detail.
    #[serde(default, skip_serializing_if = "ProcessResourceLimitValue::is_keep")]
    pub main_thread_stack_size: ProcessResourceLimitValue,
}

#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub enum ProcessResourceLimitValue {
    #[default]
    Keep,
    Value(u64),
    Unlimited,
}

impl ProcessResourceLimitValue {
    pub const fn keep() -> Self {
        Self::Keep
    }

    pub const fn value(value: u64) -> Self {
        Self::Value(value)
    }

    pub const fn unlimited() -> Self {
        Self::Unlimited
    }

    pub const fn is_keep(&self) -> bool {
        matches!(self, Self::Keep)
    }
}

impl Serialize for ProcessResourceLimitValue {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Keep => serializer.serialize_none(),
            Self::Value(value) => serializer.serialize_u64(*value),
            Self::Unlimited => serializer.serialize_str("unlimited"),
        }
    }
}

impl<'de> Deserialize<'de> for ProcessResourceLimitValue {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = ProcessResourceLimitValue;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a u64, \"unlimited\", or null")
            }

            fn visit_none<E>(self) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(ProcessResourceLimitValue::Keep)
            }

            fn visit_unit<E>(self) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(ProcessResourceLimitValue::Keep)
            }

            fn visit_some<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                Deserialize::deserialize(deserializer)
            }

            fn visit_u64<E>(self, value: u64) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(ProcessResourceLimitValue::Value(value))
            }

            fn visit_i64<E>(self, value: i64) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if value < 0 {
                    return Err(E::custom("resource limit must be non-negative"));
                }
                Ok(ProcessResourceLimitValue::Value(value as u64))
            }

            fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                ProcessResourceLimitValue::from_str(value).map_err(E::custom)
            }

            fn visit_string<E>(self, value: String) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_str(&value)
            }
        }

        deserializer.deserialize_any(Visitor)
    }
}

impl FromStr for ProcessResourceLimitValue {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value {
            "unlimited" => Ok(Self::Unlimited),
            other => other
                .parse::<u64>()
                .map(Self::Value)
                .map_err(|_| format!("invalid process resource limit value: {other}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ProcessResourceLimitValue, ProcessResourceLimits};

    #[test]
    fn process_resource_limit_value_round_trips() {
        assert_eq!(
            serde_json::from_str::<ProcessResourceLimitValue>("123").unwrap(),
            ProcessResourceLimitValue::value(123)
        );
        assert_eq!(
            serde_json::from_str::<ProcessResourceLimitValue>("\"unlimited\"").unwrap(),
            ProcessResourceLimitValue::unlimited()
        );
        assert_eq!(
            serde_json::from_str::<ProcessResourceLimitValue>("null").unwrap(),
            ProcessResourceLimitValue::keep()
        );
        assert_eq!(
            serde_json::to_string(&ProcessResourceLimitValue::value(99)).unwrap(),
            "99"
        );
        assert_eq!(
            serde_json::to_string(&ProcessResourceLimitValue::unlimited()).unwrap(),
            "\"unlimited\""
        );
    }

    #[test]
    fn process_resource_limits_skip_keep_fields() {
        let limits = ProcessResourceLimits {
            open_files: ProcessResourceLimitValue::value(1024),
            core_size: ProcessResourceLimitValue::value(0),
            ..Default::default()
        };

        let json = serde_json::to_string(&limits).unwrap();
        assert!(json.contains("\"open_files\":1024"));
        assert!(json.contains("\"core_size\":0"));
        assert!(!json.contains("address_space_size"));

        let decoded: ProcessResourceLimits = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.open_files, ProcessResourceLimitValue::value(1024));
        assert_eq!(decoded.core_size, ProcessResourceLimitValue::value(0));
        assert_eq!(decoded.address_space_size, ProcessResourceLimitValue::keep());
    }
}
