use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::os::unix::fs::PermissionsExt;

// Admin system directory
const ADMIN_LOG_DIR: &str = "/home/robot/edr_server/Logs/";

// Essential log files to monitor
const LOG_FILES: &[&str] = &["/var/log/syslog", "/var/log/auth.log", "/var/log/kern.log"];

// Filtering functions for different log files
fn filter_auth_log(lines: Vec<String>) -> Vec<String> {
    lines
        .into_iter()
        .filter(|line| {
            line.contains("FAILED") || line.contains("sudo") || line.contains("user")
        })
        .collect()
}

fn filter_syslog(lines: Vec<String>) -> Vec<String> {
    lines
        .into_iter()
        .filter(|line| line.contains("error") || line.contains("warn") || line.contains("kernel"))
        .collect()
}

fn filter_kern_log(lines: Vec<String>) -> Vec<String> {
    lines
        .into_iter()
        .filter(|line| line.contains("error") || line.contains("warn"))
        .collect()
}

// Filter logs based on the file name
fn filter_logs(file_name: &str, lines: Vec<String>) -> Vec<String> {
    match file_name {
        "auth.log" => filter_auth_log(lines),
        "syslog" => filter_syslog(lines),
        "kern.log" => filter_kern_log(lines),
        _ => lines,
    }
}

// Process a single log file: read, filter, and write to a temporary file
fn process_log_file(file_path: &str) -> io::Result<Option<String>> {
    let file_name = Path::new(file_path)
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Invalid file path"))?
        .to_str()
        .unwrap();

    let file = File::open(file_path)?;
    let reader = BufReader::new(file);

    let lines: Vec<String> = reader.lines().filter_map(Result::ok).collect();
    let filtered_lines = filter_logs(file_name, lines);

    if !filtered_lines.is_empty() {
        let temp_file_path = format!("/tmp/filtered_{}", file_name);
        let mut temp_file = File::create(&temp_file_path)?;
        for line in filtered_lines {
            writeln!(temp_file, "{}", line)?;
        }
        Ok(Some(temp_file_path))
    } else {
        Ok(None)
    }
}

// Ensure the directory for the endpoint's logs exists and has appropriate permissions
fn ensure_endpoint_dir_exists(endpoint_ip: &str, admin_ip: &str) -> io::Result<()> {
    let endpoint_dir = format!("{}/{}", ADMIN_LOG_DIR, endpoint_ip);

    // SSH into the admin system and check/create the directory there
    let command = format!(
        "ssh robot@{} 'mkdir -p {} && chmod 755 {}'",
        admin_ip, endpoint_dir, endpoint_dir
    );
    
    let status = Command::new("bash")
        .arg("-c")
        .arg(command)
        .status()?;

    if !status.success() {
        return Err(io::Error::new(io::ErrorKind::Other, "Failed to create directory on admin system"));
    }

    Ok(())
}

// Transfer the filtered file to the admin system inside the endpoint directory
fn transfer_to_admin(temp_file_path: &str, endpoint_ip: &str, admin_ip: &str) -> io::Result<()> {
    // Ensure the directory for the endpoint exists on the admin system
    ensure_endpoint_dir_exists(endpoint_ip, admin_ip)?;

    let file_name = Path::new(temp_file_path)
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Invalid temp file path"))?
        .to_str()
        .unwrap();

    // Ensure the log file is transferred into the correct endpoint directory
    let destination = format!("robot@{}:{}/{}/{}", admin_ip, ADMIN_LOG_DIR, endpoint_ip, file_name);
    
    // Execute the SCP command with the correct destination
    Command::new("scp")
        .arg(temp_file_path)
        .arg(destination)
        .status()
        .expect("Failed to execute SCP command");

    Ok(())
}

// Function to get the endpoint's own IP address
fn get_endpoint_ip() -> io::Result<String> {
    let output = Command::new("hostname")
        .arg("-I")
        .output()?
        .stdout;
    let ip = String::from_utf8_lossy(&output).trim().to_string();
    if ip.is_empty() {
        Err(io::Error::new(io::ErrorKind::NotFound, "Unable to find IP address"))
    } else {
        Ok(ip)
    }
}

// Main function
fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <ADMIN_IP>", args[0]);
        return Ok(());
    }

    let admin_ip = &args[1];

    // Get the endpoint's own IP address
    let endpoint_ip = get_endpoint_ip()?;
    println!("Endpoint IP: {}", endpoint_ip);

    for log_file in LOG_FILES {
        println!("Processing log file: {}", log_file);
        match process_log_file(log_file) {
            Ok(Some(temp_file_path)) => {
                println!("Filtered logs saved to: {}", temp_file_path);
                match transfer_to_admin(&temp_file_path, &endpoint_ip, admin_ip) {
                    Ok(_) => {
                        println!("Transferred {} to admin system at {}/{}/", log_file, ADMIN_LOG_DIR, endpoint_ip);
                        fs::remove_file(temp_file_path)?;
                    }
                    Err(e) => eprintln!("Failed to transfer file: {}", e),
                }
            }
            Ok(None) => {
                println!("No relevant logs found in {}", log_file);
            }
            Err(e) => eprintln!("Error processing {}: {}", log_file, e),
        }
    }

    Ok(())
}
