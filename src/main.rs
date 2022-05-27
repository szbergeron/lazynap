use std::env;
use std::fs::{self, OpenOptions};
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::str::FromStr;
use std::sync::{Mutex, Arc};

fn main() {
    let args: Vec<_> = env::args().collect();

    for a in args {
        match a.as_str() {
            "suspend" => suspend(),
            "resume" => resume(),
            _ => {},
        }
    }
}

fn to_suspend_kws() -> Vec<&'static str> {
    vec![
        "/usr/lib/upowerd",
        "evolution",
        "fwupd",
        "boltd",
        "NetworkManager",
        "akonadi",
        "polkit",

        "i915",
        "pci_pme_list_scan",
        "intel_display_power",
        "sidewinderd",
    ]
}

fn to_not_suspend_kws() -> Vec<&'static str> {
    vec![
        "lid",
        "idle",
        "sot",
        "htop",
        "powertop",
        "power-usage-report",
        /*"gnome",
        "init",
        "systemd",
        //"pipewire",
        //"wireplumber",
        "acpid",
        "polkit",
        "NetworkManager",
        "gsd",
        "ibus",
        //"xdg",
        "fuser",
        "gjs",
        //"akonadi",
        //"fish",
        "watchman",
        //"mysql",
        //"zeitgeist",
        //"Xwayland",
        "registry",
        //"evolution",
        "shell",
        "gvfsd",
        "fuse",
        "gdm",
        "rtkit",
        "bluetooth",
        "dbus",      */
        //"kitty",
        //"nano",
        /*"bolt",
        "nvidia",
        "iio",
        "kitty",
        "nano",
        "cargo",
        "kworker",
        "fwupd",
        "upowerd",
        "colord",
        "udisk",
        "irq",
        "cryptd",
        "nv_queue",
        "card",
        "gvt",
        "nvme",
        "charger",
        "kstrp",
        "ip",
        "acpi",
        "kthrotld",
        "kswap",
        "watchdog",
        "ata",
        "devfreq",
        "edac",
        "blk",
        "kblock",
        "kintegrity",
        "khugepaged",
        "ksmd",
        "kcompact",
        "writeback",
        "oom_reaper",
        "khung",
        "kaudit",
        "inet",
        "kdev",
        "migration",
        "idle",
        "cpu",
        "dconf",
        "accounts",
        "USB",
        "usb",
        "UVM",
        "uvm",
        "ext4",
        "kmpath",
        "cfg",
        "tpm",
        "zswap",
        "mld",
        "rcu",
        "netns",
        "kthread",
        "sudo",*/
    ]
}

#[derive(Debug, Clone)]
struct Process {
    pid: u32,
    cmdline: String,
    command: String,
    //children: Mutex<Vec<Arc<Process>>>,
}

/*struct ProcessTree {
    roots: Vec<Arc<Process>>
}

impl ProcessTree {
    fn push(&mut self, p: Process) {
    }
}*/

fn filter(procs: Vec<Process>, wl: Vec<&'static str>, include_list: bool) -> Vec<Process> {
    let mut res = vec![];

    'outer: for proc in procs {
        for w in wl.iter() {
            if proc.command.contains(w) {
                if include_list {
                    println!("Adding {} {}", proc.command, proc.cmdline);
                    res.push(proc);
                    continue 'outer;
                } else {
                    println!("Rejecting {} because {w}", proc.command);
                    continue 'outer;
                }
            }

            if proc.cmdline.contains(w) {
                if include_list {
                    println!("Adding {} {}", proc.command, proc.cmdline);
                    res.push(proc);
                    continue 'outer;
                } else {
                    println!("Rejecting {} because {w}", proc.command);
                    continue 'outer;
                }
            }
        }
        println!("Adding {} {}", proc.command, proc.cmdline);
        if !include_list {
            res.push(proc);
        }
    }

    res
}

fn all_user_pids() -> Vec<u32> {
    let psout = Command::new("ps").args(["-u", "sawyer"]).output().unwrap();

    let mut pids_for_user = vec![];

    for line in String::from_utf8(psout.stdout).unwrap().lines().skip(1) {
        let pid: u32 = line.split_whitespace().nth(0).unwrap().parse().unwrap();
        pids_for_user.push(pid);
    }

    pids_for_user
}

fn all_system_pids() -> Vec<u32> {
    let psout = Command::new("ps").args(["-aux"]).output().unwrap();

    let mut pids = vec![];

    for line in String::from_utf8(psout.stdout).unwrap().lines().skip(1) {
        let pid: u32 = line.split_whitespace().nth(1).unwrap().parse().unwrap();
        pids.push(pid);
    }

    pids
}

fn read_all_procs(pids: Vec<u32>) -> Vec<Process> {
    let mut res = Vec::new();
    //let paths = fs::read_dir("/proc/").unwrap();

    //let pids_for_user = all_user_pids();


    for pid in pids {
        let p = PathBuf::from_str(format!("/proc/{pid}/").as_str()).unwrap();
        if p.exists() {
            let path = p;

            if (path.file_name().unwrap().to_str().unwrap().chars().nth(0).unwrap()).is_numeric() {
                let pid: u32 = path.file_name().unwrap().to_str().unwrap().parse().unwrap();
                
                let children = match path.read_dir() {
                    Ok(children) => { children },
                    Err(_) => { continue },
                };

                let mut cmdline = None;
                let mut command = None;

                for child in children {
                    match child {
                        Ok(child) => {
                            let f = child.file_name();
                            let fname = f.to_str().unwrap_or("");

                            let contents = match fname {
                                "comm" | "cmdline" => {
                                    match fs::read_to_string(child.path()) {
                                        Ok(contents) => { contents },
                                        Err(_) => { continue },
                                    }
                                }
                                _ => {continue},
                            };

                            match fname {
                                "comm" => command = Some(contents),
                                "cmdline" => cmdline = Some(contents),
                                _ => {},
                            }
                        },
                        Err(_) => {},
                    }
                }

                if let (Some(cmdline), Some(command)) = (cmdline, command) {
                    res.push(Process { pid, cmdline, command });
                }
            }
        }
    }

    res
}

fn recover_proc_list() -> Vec<Process> {
    let pf = fs::read_to_string("/tmp/suspend_proc_list").unwrap();

    let mut procs = Vec::new();

    for l in pf.lines() {
        let pid: u32 = match l.parse() {
            Ok(p) => {p},
            Err(_) => {continue},
        };

        procs.push(Process { pid, cmdline: String::new(), command: String::new()})
    }

    return procs;
}

fn write_proc_list(procs: &Vec<Process>) {
    let mut to_write = String::new();

    use std::fmt::Write;
    for proc in procs {
        to_write.write_str(format!("{}\n", proc.pid).as_str());
        //writeln!(to_write, "{}", proc.pid);
        //to_write.wr
    }

    //let mut file = OpenOptions::new().write(true).open("/tmp/suspend_proc_list").unwrap();
    let mut file = File::create("/tmp/suspend_proc_list").unwrap();

    file.write_all(to_write.as_bytes()).unwrap();

    //
}

fn signal(proc: Process, signal: &str) {
    println!("Sending {signal} to process: {proc:?}");
    use std::process::Command;

    //return;
    let res = Command::new("kill").args(["-s", signal, proc.pid.to_string().as_str()]).output();
    match res {
        Ok(_) => {},
        Err(v) => {
        },
    }
}

fn suspend() {
    let mut to_suspend = filter(read_all_procs(all_user_pids()), to_not_suspend_kws(), false);
    to_suspend.append(&mut filter(read_all_procs(all_system_pids()), to_suspend_kws(), true));
    write_proc_list(&to_suspend);

    for proc in to_suspend {
        signal(proc, "STOP");
    }

}

fn resume() {
    let to_resume = recover_proc_list();

    for proc in to_resume.into_iter().rev() {
        signal(proc, "CONT");
    }
}
