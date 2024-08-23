use std::fs;
use std::io;
use std::path::Path;
use std::fs::create_dir_all;
use std::fs::copy;

fn main() -> io::Result<()> {
    // Source directory where logs are stored
    let log_dir = "/var/log";
    
    // Base directory where logs will be copied to
    let base_destination_dir = "/home/robot/Desktop/Rust/log";

    // Directories to store categorized logs
    let auth_dir = format!("{}/auth", base_destination_dir);
    let system_dir = format!("{}/system", base_destination_dir);
    let network_dir = format!("{}/network", base_destination_dir);
    let boot_dir = format!("{}/boot", base_destination_dir);
    let misc_dir = format!("{}/misc", base_destination_dir);

    // Create directories if they don't exist
    create_dir_all(&auth_dir)?;
    create_dir_all(&system_dir)?;
    create_dir_all(&network_dir)?;
    create_dir_all(&boot_dir)?;
    create_dir_all(&misc_dir)?;

    // Iterate over log files in the log directory
    for entry in fs::read_dir(log_dir)? {
        let entry = entry?;
        let path = entry.path();

        // Ensure we are only working with files
        if path.is_file() {
            let filename = path.file_name().unwrap().to_str().unwrap();

            // Categorize and move files based on filename patterns
            if filename.contains("auth") {
                let destination = Path::new(&auth_dir).join(filename);
                copy(&path, &destination)?;
            } else if filename.contains("syslog") || filename.contains("kern") || filename.contains("dmesg") {
                let destination = Path::new(&system_dir).join(filename);
                copy(&path, &destination)?;
            } else if filename.contains("ufw") || filename.contains("iptables") || filename.contains("netfilter") {
                let destination = Path::new(&network_dir).join(filename);
                copy(&path, &destination)?;
            } else if filename.contains("boot") {
                let destination = Path::new(&boot_dir).join(filename);
                copy(&path, &destination)?;
            } else {
                let destination = Path::new(&misc_dir).join(filename);
                copy(&path, &destination)?;
            }
        }
    }

    println!("Log files have been categorized and copied successfully.");
    Ok(())
}
