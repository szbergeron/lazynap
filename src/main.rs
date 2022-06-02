use std::env;
use std::fs::File;
use std::fs::{self};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::Command;
use std::str::FromStr;


use std::time::{Duration, Instant};

use drm::control::Device;
use ipipe::Pipe;
use nix::sys::signal::Signal;
use nix::unistd::Pid;
//use rayon::prelude::*;
//use serde::{Deserialize, Serialize};
//use unix_ipc::{Bootstrapper, Receiver, Sender};
//use drm

fn main() {
    let args: Vec<_> = env::args().collect();

    for a in args {
        match a.as_str() {
            "suspend" => as_client(Message::Suspend()),
            "resume" => as_client(Message::Resume()),
            "server" => as_server(),
            "dpms_check" => {
                println!("DPMS status: {:?}", Monitors::get_dpms_status());
            }
            "test" => {
                testing()
            }
            //"test" => testing(),
            _ => {}
        }
    }
}

//#[derive(Serialize, Deserialize, Debug)]
enum Message {
    Suspend(),
    Resume(),
    Exit(),
}

impl Message {
    fn as_u8(&self) -> u8 {
        match self {
            Self::Suspend() => 1,
            Self::Resume() => 2,
            Self::Exit() => 3,
        }
    }

    fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Suspend(),
            2 => Self::Resume(),
            3 => Self::Exit(),
            _ => panic!("bad message"),
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct Statistics {
    /// current battery percentage
    battery_pct: f64,

    /// watt hours remaining
    battery_energy: f64,

    /// positive if charging, negative if
    /// discharging, measured in watts
    energy_rate: f64,

    time: Instant,
}

impl Statistics {
    #[allow(dead_code)]
    fn new() -> Statistics {
        Statistics {
            battery_pct: 0.0,
            battery_energy: 0.0,
            energy_rate: 0.0,
            time: Instant::now(),
        }
    }
}

#[allow(dead_code)]
struct Event {
    //time: Instant,
    stats: Statistics,

    event: Message,
}

#[allow(dead_code)]
struct Context {
    events: Vec<Event>,

    frozen_processes: Vec<Process>,
}

#[derive(Debug)]
/// A simple wrapper for a device node.
pub struct Card(std::fs::File);

/// Implementing `AsRawFd` is a prerequisite to implementing the traits found
/// in this crate. Here, we are just calling `as_raw_fd()` on the inner File.
impl std::os::unix::io::AsRawFd for Card {
    fn as_raw_fd(&self) -> std::os::unix::io::RawFd {
        self.0.as_raw_fd()
    }
}

/// With `AsRawFd` implemented, we can now implement `drm::Device`.
impl drm::Device for Card {}
impl drm::control::Device for Card {}

impl Card {
    pub fn open(path: &str) -> Self {
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        options.write(true);
        Card(options.open(path).unwrap())
    }

    pub fn open_global() -> Self {
        Self::open("/dev/dri/card0")
    }
}

#[allow(dead_code)]
fn change_vt(target: &str) {
    std::process::Command::new("chvt")
        .arg(&target[3..])
        .output()
        .unwrap();
}

fn testing() {
    suspend_flow();

    std::thread::sleep(Duration::from_secs(3));

    resume_flow();
    /********suspend_userspace();

    std::thread::sleep(Duration::from_secs(5));

    change_vt("tty6");

    //Monitors::set_dpms_sus(DPMS::Suspend);

    std::thread::sleep(Duration::from_secs_f64(20.0));

    //Monitors::set_dpms_sus(DPMS::On);

    std::thread::sleep(Duration::from_secs(5));

    change_vt("tty2");

    //std::process::Command::new("chvt").arg("2").output().unwrap();

    //std::thread::sleep(Duration::from_secs(5));

    resume_userspace();*/
}

#[derive(Debug)]
enum DPMS {
    On = 0,
    Off = 3,
    Suspend = 2,
    Standby = 1,
}

struct Monitors {}

impl Monitors {
    fn get_dpms_status() -> Option<DPMS> {
        //let card = Card
        let card = Card::open_global();
        let resources = card.resource_handles().ok()?;

        for conn_handle in resources.connectors() {
            let props = card.get_properties(*conn_handle).ok()?;
            let (ids, vals) = props.as_props_and_values();

            for (&id, &val) in ids.iter().zip(vals.iter()) {
                //println!("Property: {:?}", id);
                let info = card.get_property(id).ok()?;
                //println!("Val: {}", val);

                if info.name().to_str().unwrap() == "DPMS" {
                    //println!("{:?}", info.name());
                    //println!("{:#?}", info.value_type());
                    //println!("Mutable: {}", info.mutable());
                    //println!("Atomic: {}", info.atomic());
                    //println!("Value: {:?}", info.value_type().convert_value(val));
                    //println!();

                    return Some(match val {
                        0 => DPMS::On,
                        1 => DPMS::Standby,
                        2 => DPMS::Suspend,
                        3 => DPMS::Off,
                        _ => unreachable!(),
                    });

                    //info.value_type().convert_value(val)
                    //card.set_property(*conn_handle, id, num).unwrap();
                    //std::thread::sleep_ms(1000);
                    //card.set_property(*conn_handle, id, 0).unwrap();
                    //break 'outer;
                }
            }
        }

        None
    }
}

impl Context {
    #[allow(dead_code)]
    pub fn default() -> Context {
        Context {
            events: vec![Event {
                stats: Statistics::new(),
                event: Message::Resume(),
            }],
            frozen_processes: Vec::new(),
        }
    }

    #[allow(dead_code)]
    pub fn is_sleeping(&self) -> bool {
        match self
            .events
            .iter()
            .rev()
            .filter(|p| match p.event {
                Message::Resume() | Message::Suspend() => true,
                _ => false,
            })
            .next()
        {
            Some(e) => match e.event {
                Message::Resume() => false,
                Message::Suspend() => true,
                _ => unreachable!(),
            },
            None => false,
        }
    }
}

fn pipe() -> Pipe {
    let pipe = Pipe::with_name("idlefd3").unwrap();
    pipe
}

/********fn sock() -> Bootstrapper<Message> {
    let bootstrapper = Bootstrapper::bind("/tmp/idlefd2").unwrap();
    bootstrapper
}*/

fn as_client(msg: Message) {
    //Sender::try_into
    //pipe().send(msg).unwrap();
    pipe().write(&[msg.as_u8()]).unwrap();
}

fn as_server() {
    //let b = sock();
    /*let b = sock();
    let rcv = Receiver::connect("/tmp/idlefd2").unwrap();*/

    let mut pipe = pipe();

    loop {
        println!("Waiting for messages...");
        //let msg: Message = rcv.recv().unwrap();
        let mut msgb = [0u8];
        pipe.read_exact(&mut msgb).unwrap();
        let msg = Message::from_u8(msgb[0]);
        println!("Got a message!");

        match msg {
            Message::Exit() => break,
            Message::Resume() => {
                println!("Resuming...");

                resume_flow();
            }
            Message::Suspend() => {
                println!("Suspending...");

                suspend_flow();
            }
        }
    }
}

fn lock_blank_screen_gnome() {
    let o = execute::shell("su sawyer -c \"DBUS_SESSION_BUS_ADDRESS='unix:path=/run/user/1000/bus' dbus-send --session --dest=org.gnome.ScreenSaver --type=method_call /org/gnome/ScreenSaver org.gnome.ScreenSaver.SetActive boolean:true\"").output().unwrap();

    println!("Status: {}", o.status);
    println!("Blank output: {}", String::from_utf8(o.stderr).unwrap());
}

fn lock_blank_screen() {
    for _i in 0..10 {
        lock_blank_screen_gnome();

        std::thread::sleep(Duration::from_secs_f64(2.0));

        match Monitors::get_dpms_status() {
            Some(DPMS::On) => {
                println!("Monitor not yet asleep...");
                continue; // we have confirmation that the monitor is *on*
            }
            Some(_) => {
                println!("Monitor suspended nicely");
                break; // monitor is sleeping some way
            }
            None => {
                println!("Error reading monitor state!!");
                break;
            }
        }
    }
}

fn modprobe(module: &str, load: bool) -> Option<()> {
    match load {
        true => Command::new("modprobe").arg(module).output(),
        false => Command::new("modprobe").arg("-r").arg(module).output(),
    }
    .ok()?;

    Some(())
}

fn suspend_flow() {
    let start = Instant::now();

    lock_blank_screen();

    let post_lock = Instant::now();

    wifi(false);
    bluetooth(false);

    suspend_userspace();

    unload_us_modules();

    let end = Instant::now();

    println!(
        "Suspend took {} seconds, {} seconds since screen was locked",
        (end - start).as_secs_f64(),
        (end - post_lock).as_secs_f64()
    );
}

fn resume_flow() {
    resume_userspace();

    load_us_modules();

    wifi(true);
    bluetooth(true);
}

fn load_us_modules() {
    modprobe_on_list(modprobe_list(), true);
}

fn unload_us_modules() {
    modprobe_on_list(modprobe_list(), false);
}

fn modprobe_on_list(list: &[&str], load: bool) {
    for elem in list {
        modprobe(elem, load);
    }
}

fn wifi(enable: bool) -> Option<()> {
    match enable {
        true => execute::shell("nmcli radio wifi on").output().ok()?,
        false => execute::shell("nmcli radio wifi off").output().ok()?,
    };

    Some(())
}

fn bluetooth(enable: bool) -> Option<()> {
    match enable {
        true => execute::shell("rfkill unblock bluetooth").output().ok()?,
        false => execute::shell("rfkill block bluetooth").output().ok()?,
    };

    Some(())
}

fn modprobe_list() -> &'static [&'static str] {
    &[
        "i2c_hid",
        "i2c_hid_acpi",
        "i2c_smbus",
        "psmouse",
        "v4l2loopback",
        "dell_laptop",
        "dell_wmi",
    ]
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
        /*"pipewire",
        "wireplumber",
        "gnome-shell",*/
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
                    //println!("Adding {} {}", proc.command, proc.cmdline);
                    res.push(proc);
                    continue 'outer;
                } else {
                    //println!("Rejecting {} because {w}", proc.command);
                    continue 'outer;
                }
            }

            if proc.cmdline.contains(w) {
                if include_list {
                    //println!("Adding {} {}", proc.command, proc.cmdline);
                    res.push(proc);
                    continue 'outer;
                } else {
                    //println!("Rejecting {} because {w}", proc.command);
                    continue 'outer;
                }
            }
        }
        //println!("Adding {} {}", proc.command, proc.cmdline);
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

            if (path
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .chars()
                .nth(0)
                .unwrap())
            .is_numeric()
            {
                let pid: u32 = path.file_name().unwrap().to_str().unwrap().parse().unwrap();

                let children = match path.read_dir() {
                    Ok(children) => children,
                    Err(_) => continue,
                };

                let mut cmdline = None;
                let mut command = None;

                for child in children {
                    match child {
                        Ok(child) => {
                            let f = child.file_name();
                            let fname = f.to_str().unwrap_or("");

                            let contents = match fname {
                                "comm" | "cmdline" => match fs::read_to_string(child.path()) {
                                    Ok(contents) => contents,
                                    Err(_) => continue,
                                },
                                _ => continue,
                            };

                            match fname {
                                "comm" => command = Some(contents),
                                "cmdline" => cmdline = Some(contents),
                                _ => {}
                            }
                        }
                        Err(_) => {}
                    }
                }

                if let (Some(cmdline), Some(command)) = (cmdline, command) {
                    res.push(Process {
                        pid,
                        cmdline,
                        command,
                    });
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
            Ok(p) => p,
            Err(_) => continue,
        };

        procs.push(Process {
            pid,
            cmdline: String::new(),
            command: String::new(),
        })
    }

    return procs;
}

fn write_proc_list(procs: &Vec<Process>) {
    let mut to_write = String::new();

    use std::fmt::Write;
    for proc in procs {
        to_write
            .write_str(format!("{}\n", proc.pid).as_str())
            .unwrap();
        //writeln!(to_write, "{}", proc.pid);
        //to_write.wr
    }

    //let mut file = OpenOptions::new().write(true).open("/tmp/suspend_proc_list").unwrap();
    let mut file = File::create("/tmp/suspend_proc_list").unwrap();

    file.write_all(to_write.as_bytes()).unwrap();

    //
}

/*#[derive(Clone, Copy)]
enum Signal {
    STOP,
    CONT,
}

impl Signal {
    fn as_str(&self) -> &'static str {
        match self {
            Self::STOP => "STOP",
            Self::CONT => "CONT",
        }
    }
}*/

fn signal(proc: Process, signal: Signal) {
    //println!("Sending {} to process: {proc:?}", signal.as_str());
    //use std::process::Command;
    //String signal = signal.to_string();
    let pid = proc.pid;
    //return;

    //return;
    /*let res = Command::new("kill")
        .args(["-s", signal.as_str(), pid.to_string().as_str()])
        .output();
    match res {
        Ok(_) => {}
        Err(v) => {}
    }*/

    // Don't unwrap! This operation should continue even if lossy, otherwise too easy to just
    // not wake back up from sleep
    let _res = nix::sys::signal::kill(Pid::from_raw(pid as i32), signal);
}

fn suspend_userspace() {
    let mut to_suspend = filter(read_all_procs(all_user_pids()), to_not_suspend_kws(), false);
    to_suspend.append(&mut filter(
        read_all_procs(all_system_pids()),
        to_suspend_kws(),
        true,
    ));
    write_proc_list(&to_suspend);

    let before = Instant::now();
    let count = to_suspend.len();

    //let mut joins = Vec::new();
    for proc in to_suspend {
        signal(proc, Signal::SIGSTOP);
    }

    let after = Instant::now();

    let delta = (after - before).as_secs_f64();

    println!("Freezing {count} processes took {delta} seconds");

    //joins.into_iter().for_each(|o| o.join().unwrap());
}

fn resume_userspace() {
    let a = Instant::now();
    let to_resume = recover_proc_list();

    let b = Instant::now();

    println!("Unfreezing {} processes", to_resume.len());

    for proc in to_resume.into_iter().rev() {
        signal(proc, Signal::SIGCONT);
    }

    let c = Instant::now();

    println!("Load took: {}", (b - a).as_secs_f64());
    println!("Unfreeze took: {}", (c - b).as_secs_f64());
}
