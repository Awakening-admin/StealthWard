1. Update IPS in inventory.ini of endpoints and admin.
2. Add passwords of endpoints in inventory.ini
3. update username of system in all files where path of directory is initialized.
4. update username in both agent files. agent.c and main.rs
5. compile agent.c with cmd " gcc agent.c -o agent -Wall -Wextra -lpthread -ljansson -lpcap "
6. compile agent main.rs with command cargo build --release
7. Run Ansible using command
8. ansible-playbook -i inventory.ini setup_edr.yml
9. Go to DB folder
10. and run enviornment with cmd " source sw/bin/activate " followed by " python3 app.py"
11. In IDS folder update username and ip where required in files with .py extension
12. after updating use cmd " python3 stealthward_main.py"
