use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use notify::{Config, EventKind, RecommendedWatcher, RecursiveMode, Watcher};

// Constants
const ADMIN_LOG_DIR: &str = "/home/robot/edr_server/Logs/";
const ADMIN_IP: &str = "192.168.100.24";
const ADMIN_USERNAME: &str = "robot";
const TEMP_FILE_PREFIX: &str = "/tmp/filtered_";

// Common log paths across distributions
const COMMON_LOG_FILES: &[(&str, &str)] = &[
    // System logs
    ("/var/log/syslog", "syslog"),
    ("/var/log/messages", "messages"),
    ("/var/log/auth.log", "auth.log"),
    ("/var/log/secure", "secure"),
    ("/var/log/kern.log", "kern.log"),
    ("/var/log/cron", "cron"),
    ("/var/log/maillog", "maillog"),
    
    // Security logs
    ("/var/log/btmp", "failed_logins.log"),
    ("/var/log/wtmp", "logins.log"),
    ("/var/log/faillog", "faillog.log"),
    
    // Application logs
    ("/var/log/dmesg", "dmesg.log"),
];

// Arch Linux specific log paths
const ARCH_LOG_FILES: &[(&str, &str)] = &[
    ("/var/log/journal/", "system.journal"),
    ("/var/log/pacman.log", "pacman.log"),
    ("/var/log/audit/audit.log", "audit.log"),
    ("/var/log/lightdm/lightdm.log", "lightdm.log"),
    ("/var/log/Xorg.0.log", "Xorg.log"),
];

// Ubuntu specific log paths
const UBUNTU_LOG_FILES: &[(&str, &str)] = &[
    ("/var/log/ufw.log", "ufw.log"),
    ("/var/log/apt/history.log", "apt_history.log"),
    ("/var/log/apt/term.log", "apt_term.log"),
    ("/var/log/apport.log", "apport.log"),
    ("/var/log/cloud-init.log", "cloud-init.log"),
];

// Fedora specific log paths
const FEDORA_LOG_FILES: &[(&str, &str)] = &[
    ("/var/log/firewalld", "firewalld.log"),
    ("/var/log/dnf.log", "dnf.log"),
    ("/var/log/hawkey.log", "hawkey.log"),
    ("/var/log/samba/log.smbd", "samba.log"),
];

struct LogState {
    last_position: u64,
    file_name: String,
}

#[derive(Debug)]
enum AgentError {
    Io(io::Error),
    Notify(notify::Error),
    Ssh(String),
}

impl From<io::Error> for AgentError {
    fn from(err: io::Error) -> Self {
        AgentError::Io(err)
    }
}

impl From<notify::Error> for AgentError {
    fn from(err: notify::Error) -> Self {
        AgentError::Notify(err)
    }
}

fn detect_distro() -> String {
    if Path::new("/etc/arch-release").exists() {
        return "arch".to_string();
    } else if Path::new("/etc/fedora-release").exists() {
        return "fedora".to_string();
    } else if Path::new("/etc/lsb-release").exists() {
        if let Ok(content) = fs::read_to_string("/etc/lsb-release") {
            if content.contains("Ubuntu") {
                return "ubuntu".to_string();
            }
        }
    }
    "unknown".to_string()
}

fn get_log_files() -> Vec<(&'static str, &'static str)> {
    let distro = detect_distro();
    let mut files = Vec::new();
    
    // Add common files
    files.extend_from_slice(COMMON_LOG_FILES);
    
    // Add distro-specific files
    match distro.as_str() {
        "arch" => files.extend_from_slice(ARCH_LOG_FILES),
        "ubuntu" => files.extend_from_slice(UBUNTU_LOG_FILES),
        "fedora" => files.extend_from_slice(FEDORA_LOG_FILES),
        _ => {}
    }
    
    files
}

fn filter_logs(file_name: &str, lines: Vec<String>) -> Vec<String> {
    match file_name {
        // Common log filters
        "auth.log" | "secure" => lines.into_iter().filter(|l| 
            l.contains("FAILED") || l.contains("sudo") || l.contains("user") || 
            l.contains("authentication") || l.contains("failure") || l.contains("root")
        ).collect(),
        "syslog" | "messages" => lines.into_iter().filter(|l| 
            l.contains("error") || l.contains("warn") || l.contains("kernel") ||
            l.contains("service")
        ).collect(),
        "kern.log" => lines.into_iter().filter(|l| 
            l.contains("error") || l.contains("warn")
        ).collect(),
        "cron" => lines.into_iter().filter(|l| 
            l.contains("FAILED") || l.contains("error") || l.contains("job")
        ).collect(),
        "maillog" => lines.into_iter().filter(|l| 
            l.contains("rejected") || l.contains("error") || l.contains("spam")
        ).collect(),
        "failed_logins.log" | "faillog.log" => lines,
        "logins.log" => lines,
        
        // Arch specific filters
        "audit.log" => lines.into_iter().filter(|l| 
            l.contains("failed") || l.contains("denied") || l.contains("user")
        ).collect(),
        "pacman.log" => lines.into_iter().filter(|l| 
            l.contains("installed") || l.contains("removed") || l.contains("error")
        ).collect(),
        "lightdm.log" => lines.into_iter().filter(|l| 
            l.contains("authentication") || l.contains("session") || l.contains("error")
        ).collect(),
        "Xorg.log" => lines.into_iter().filter(|l| 
            l.contains("error") || l.contains("warning") || l.contains("failed")
        ).collect(),
        "system.journal" => lines.into_iter().filter(|l| 
            l.contains("error") || l.contains("failed") || l.contains("authentication")
        ).collect(),
        
        // Ubuntu specific filters
        "ufw.log" => lines.into_iter().filter(|l| 
            l.contains("blocked") || l.contains("denied") || l.contains("dropped")
        ).collect(),
        "apt_history.log" | "apt_term.log" => lines.into_iter().filter(|l| 
            l.contains("install") || l.contains("remove") || l.contains("upgrade") ||
            l.contains("error")
        ).collect(),
        "apport.log" => lines.into_iter().filter(|l| 
            l.contains("crash") || l.contains("error") || l.contains("failed")
        ).collect(),
        "cloud-init.log" => lines.into_iter().filter(|l| 
            l.contains("error") || l.contains("fail") || l.contains("warning")
        ).collect(),
        
        // Fedora specific filters
        "firewalld.log" => lines.into_iter().filter(|l| 
            l.contains("blocked") || l.contains("denied") || l.contains("dropped")
        ).collect(),
        "dnf.log" | "hawkey.log" => lines.into_iter().filter(|l| 
            l.contains("install") || l.contains("remove") || l.contains("upgrade") ||
            l.contains("error")
        ).collect(),
        "samba.log" => lines.into_iter().filter(|l| 
            l.contains("access") || l.contains("denied") || l.contains("error")
        ).collect(),
        
        // Default case
        _ => lines,
    }
}


fn process_journal_file(file_path: &str, state: &mut LogState) -> Result<Option<String>, AgentError> {
    let output = Command::new("journalctl")
        .arg("--file")
        .arg(file_path)
        .arg("--since")
        .arg("1 minute ago")
        .arg("--no-pager")
        .output()?;

    if !output.status.success() {
        return Err(AgentError::Io(io::Error::new(
            io::ErrorKind::Other,
            "Failed to read journal file"
        )));
    }

    let content = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();
    let filtered_lines = filter_logs(&state.file_name, lines);

    if filtered_lines.is_empty() {
        return Ok(None);
    }

    let temp_file_path = format!("{}{}", TEMP_FILE_PREFIX, state.file_name);
    let mut temp_file = File::create(&temp_file_path)?;
    for line in filtered_lines {
        writeln!(temp_file, "{}", line)?;
    }

    Ok(Some(temp_file_path))
}

fn process_log_file(file_path: &str, state: &mut LogState) -> Result<Option<String>, AgentError> {
    let mut file = OpenOptions::new().read(true).open(file_path)?;
    let current_size = file.metadata()?.len();
    
    if current_size < state.last_position {
        state.last_position = 0;
    }
    if state.last_position >= current_size {
        return Ok(None);
    }

    file.seek(SeekFrom::Start(state.last_position))?;
    let reader = BufReader::new(file);
    let lines: Vec<String> = reader.lines().collect::<Result<_, _>>()?;
    let filtered_lines = filter_logs(&state.file_name, lines);
    state.last_position = current_size;

    if filtered_lines.is_empty() {
        return Ok(None);
    }

    let temp_file_path = format!("{}{}", TEMP_FILE_PREFIX, state.file_name);
    let mut temp_file = File::create(&temp_file_path)?;
    for line in filtered_lines {
        writeln!(temp_file, "{}", line)?;
    }

    Ok(Some(temp_file_path))
}

fn ensure_endpoint_dir_exists(endpoint_ip: &str) -> Result<(), AgentError> {
    let clean_ip = endpoint_ip.replace('/', "_");
    let endpoint_dir = format!("{}/{}", ADMIN_LOG_DIR.trim_end_matches('/'), clean_ip);
    
    let status = Command::new("ssh")
        .arg(format!("{}@{}", ADMIN_USERNAME, ADMIN_IP))
        .arg(format!(
            "mkdir -p \"{}\" && chmod 755 \"{}\"",
            endpoint_dir, endpoint_dir
        ))
        .status()?;

    if !status.success() {
        return Err(AgentError::Ssh(format!(
            "Failed to create remote dir {}",
            endpoint_dir
        )));
    }
    Ok(())
}

fn transfer_to_admin(temp_file_path: &str, endpoint_ip: &str) -> Result<(), AgentError> {
    let clean_ip = endpoint_ip.replace('/', "_");
    ensure_endpoint_dir_exists(endpoint_ip)?;

    let file_name = Path::new(temp_file_path)
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| {
            AgentError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid temp file path",
            ))
        })?;

    let destination = format!(
        "{}@{}:{}/{}/{}",  // Added the missing {} for file_name
        ADMIN_USERNAME,
        ADMIN_IP,
        ADMIN_LOG_DIR.trim_end_matches('/'),
        clean_ip,
        file_name
    );

    let status = Command::new("scp")
        .arg("-o")
        .arg("StrictHostKeyChecking=no")
        .arg(temp_file_path)
        .arg(&destination)
        .status()?;

    if !status.success() {
        return Err(AgentError::Ssh(format!("SCP failed for {}", destination)));
    }

    Ok(())
}


fn get_endpoint_ip() -> Result<String, AgentError> {
    let output = Command::new("hostname")
        .arg("-I")
        .output();

    if let Ok(output) = output {
        if output.status.success() {
            let ip = String::from_utf8_lossy(&output.stdout).trim().split_whitespace().next().unwrap_or("").to_string();
            if !ip.is_empty() {
                return Ok(ip);
            }
        }
    }

    let output = Command::new("ip")
        .arg("addr")
        .arg("show")
        .output()
        .map_err(|e| AgentError::Io(io::Error::new(io::ErrorKind::NotFound, format!("Failed to run ip addr command: {}", e))))?;

    if !output.status.success() {
        return Err(AgentError::Io(io::Error::new(io::ErrorKind::NotFound, "Failed to get IP from ip addr")));
    }

    let ip = String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| {
            if line.contains("inet ") && !line.contains("127.0.0.1") {
                line.split_whitespace().nth(1)
            } else {
                None
            }
        })
        .unwrap_or("")
        .to_string();

    if ip.is_empty() {
        return Err(AgentError::Io(io::Error::new(io::ErrorKind::NotFound, "No IP address found")));
    }

    Ok(ip)
}

fn main() -> Result<(), AgentError> {
    let endpoint_ip = get_endpoint_ip()?;
    println!("Running on endpoint: {}", endpoint_ip);

    let mut agent_state: HashMap<String, LogState> = HashMap::new();
    let (tx, rx) = std::sync::mpsc::channel::<notify::Result<notify::Event>>();

    let mut watcher = RecommendedWatcher::new(
        move |res| tx.send(res).unwrap(),
        Config::default()
            .with_poll_interval(Duration::from_secs(2))
            .with_compare_contents(true),
    )?;

    // Get appropriate log files for current distro
    let log_files = get_log_files();
    
    for &(log_path, log_name) in &log_files {
        if Path::new(log_path).exists() {
            println!("Monitoring found: {}", log_path);
            agent_state.insert(log_path.to_string(), LogState {
                last_position: 0,
                file_name: log_name.to_string(),
            });

            watcher.watch(Path::new(log_path), RecursiveMode::NonRecursive)?;
        }
    }

    for (path, state) in agent_state.iter_mut() {
        let result = if state.file_name == "system.journal" {
            process_journal_file(path, state)
        } else {
            process_log_file(path, state)
        };

        if let Ok(Some(temp_file)) = result {
            if let Err(e) = transfer_to_admin(&temp_file, &endpoint_ip) {
                eprintln!("Transfer failed: {:?}", e);
            }
            let _ = fs::remove_file(&temp_file);
        }
    }

    println!("Monitoring started...");

    for event in rx {
        match event {
            Ok(ev) if matches!(ev.kind, EventKind::Modify(_)) => {
                for path in ev.paths {
                    if let Some(p) = path.to_str() {
                        if let Some(state) = agent_state.get_mut(p) {
                            let result = if state.file_name == "system.journal" {
                                process_journal_file(p, state)
                            } else {
                                process_log_file(p, state)
                            };

                            match result {
                                Ok(Some(temp_file)) => {
                                    println!("Detected update: {}", state.file_name);
                                    if let Err(e) = transfer_to_admin(&temp_file, &endpoint_ip) {
                                        eprintln!("SCP failed: {:?}", e);
                                    }
                                    let _ = fs::remove_file(temp_file);
                                }
                                Err(e) => eprintln!("Processing failed: {:?}", e),
                                _ => {}
                            }
                        }
                    }
                }
            }
            Err(e) => eprintln!("Watch error: {:?}", e),
            _ => {}
        }
    }

    Ok(())
}

