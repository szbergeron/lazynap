#![feature(iter_intersperse)]
#![feature(box_syntax)]

use bus::BusReader;
use drm::control::Device;

use battery::*;
use crossbeam::channel::{Receiver, Sender};
use image::imageops;
use panic_monitor::PanicMonitor;
use parallel::{Trigger, recver};
use procfs::process::{Stat, Status};
use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::fs::{self};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::Command;
use std::str::FromStr;
//use image::load_from_memory_with_format

use std::sync::atomic::AtomicBool;
//use std::sync::mpsc::Sender;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

//use lazy_static::lazy_static;

#[macro_use]
extern crate lazy_static;

use ipipe::Pipe;
use nix::sys::signal::Signal;
use nix::unistd::Pid;

use crate::parallel::{send_commit, wait_all, wait_commit, send};
//use rayon::prelude::*;
//use serde::{Deserialize, Serialize};
//use unix_ipc::{Bootstrapper, Receiver, Sender};
//use drm

fn main() {
    let args: Vec<_> = env::args().collect();

    for a in args {
        match a.as_str() {
            "lid_close" => as_client(EventReason::LidClose),
            "lid_open" => as_client(EventReason::LidOpen),
            "power_connect" => as_client(EventReason::PowerConnect),
            "power_disconnect" => as_client(EventReason::PowerDisconnect),
            "power_button" => as_client(EventReason::PowerButton),
            "server" => as_server(),
            "dpms_check" => {
                println!("DPMS status: {:?}", Monitors::get_dpms_status());
            }
            "check" => as_client(EventReason::Check),

            "suspend" => as_client(EventReason::Suspend),
            "resume" => as_client(EventReason::Resume),
            //"test" => testing(),
            _ => {}
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

fn as_client(msg: EventReason) {
    //let v: u8 = msg.into();
    //Sender::try_into
    //pipe().send(msg).unwrap();
    let mut p = pipe();
    p.write(&[msg.into()]).unwrap();
    let _ = p.close();
}

lazy_static! {
    static ref PANIC_MONITOR: PanicMonitor = PanicMonitor::new();
}

fn as_server() {
    PANIC_MONITOR.init();
    //let b = sock();
    /*let b = sock();
    let rcv = Receiver::connect("/tmp/idlefd2").unwrap();*/

    //Platform::start();

    let mut handles = Vec::new();

    for runner in [
        || Platform::new().run(),
        || Wifi::new().run(),
        || Bluetooth::new().run(),
        || Cpus::new().run(),
        || VT::new().run(),
        || Processes::new().run(),
        || server_loop(),
    ] {
        let handle = std::thread::spawn(runner);
        //handles.push(handle.thread().id());
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    //PANIC_MONITOR.wait(handles.as_slice());

    //system.on_startup();
}

fn server_loop() {
    let mut pipe = pipe();

    loop {
        println!("Waiting for messages...");
        //let msg: Message = rcv.recv().unwrap();
        let mut msgb = [0u8];
        //pipe.read_exact(&mut msgb).unwrap();
        //let msg = Message::from_u8(msgb[0]);
        //let msg = EventReason::from(msgb[0]);
        //let msg: EventReason = msgb[0].try_into().unwrap();
        if let Ok(_) = pipe.read_exact(&mut msgb) {
            if let Ok(msg) = msgb[0].try_into() {
                println!("Got a message! Message: {msg:?}");

                match msg {
                    EventReason::Exit => break,
                    EventReason::Check => {
                        //system.print_report();
                    }
                    //other => system.handle_acpi(other),
                    other => handle_acpi(other),
                }
            }
        }
    }
}

fn handle_acpi(reason: EventReason) {
    use parallel::Action;
    use parallel::Device;
    use parallel::Progress;

    //let (send, recv) = register();

    match reason {
        EventReason::Resume | EventReason::LidOpen => send(Trigger {
            for_dev: Device::Platform(),
            from_dev: Device::Anonymous(),
            announce: Action::Resume(),
        }),

        EventReason::Suspend | EventReason::LidClose => send(Trigger {
            for_dev: Device::Platform(),
            from_dev: Device::Anonymous(),
            announce: Action::Suspend(),
        }),
        _ => (),
    };
}

mod parallel {
    use std::sync::Mutex;

    use bus::{Bus, BusReader};
    use crossbeam::channel::{Receiver, Sender};
    use multiqueue::{BroadcastSender, BroadcastReceiver};
    use once_cell::sync::OnceCell;

    #[derive(PartialEq, Eq, Clone, Copy, Debug)]
    pub enum Progress {
        PreStart(),

        Resuming(),
        Resumed(),

        Suspending(),
        Suspended(),

        Disabling(),
        Disabled(),

        Enabling(),
        Enabled(),
    }

    #[derive(PartialEq, Eq, Clone, Debug)]
    pub enum Action {
        //Suspending(Progress),
        //Resuming(Progress),
        Resume(),

        Suspend(),

        Disable(),

        Enable(),

        PowerToggle(),

        /// any action should wait for Commit
        /// to be sent before stepping forward
        Commit(),

        Reply(Progress),
    }

    #[derive(PartialEq, Eq, Clone, Copy, Debug)]
    pub enum Device {
        CPUs(),
        Processes(),
        Display(),
        VT(),

        Bluetooth(),
        Wifi(),

        Platform(),

        Anonymous(),
    }

    #[derive(PartialEq, Eq, Clone, Debug)]
    pub struct Trigger {
        pub for_dev: Device,
        pub from_dev: Device,
        pub announce: Action,
    }

    impl Trigger {
        pub fn new(announce: Action, from_dev: Device, for_dev: Device) -> Self {
            Self {
                announce,
                from_dev,
                for_dev,
            }
        }

        pub fn send(self) {
            //let _ = register().0.send(self);
            send(self)
        }
    }

    lazy_static! {
        static ref PAIR: (Sender<Trigger>, Receiver<Trigger>) = crossbeam::channel::unbounded();
        //static ref MQ: (BroadcastSender<Trigger>, BroadcastReceiver<Trigger>) = multiqueue::broadcast_queue(256);

        static ref BUS: Mutex<Bus<Trigger>> = Mutex::new(bus::Bus::new(100));
    }

    pub fn recver() -> bus::BusReader<Trigger> {
        BUS.lock().unwrap().add_rx()
    }

    pub fn send(t: Trigger) {
        BUS.lock().unwrap().broadcast(t);
    }

    /*pub fn register() -> (Sender<Trigger>, Receiver<Trigger>) {
        //static o: OnceCell<crossbeam::channel::Sender<Announcement>>

        PAIR.clone()
    }*/

    pub fn wait_commit(r: &mut Receiver<Trigger>, from: Device) {
        while let Ok(v) = r.recv() {
            if from == v.from_dev {
                if let Action::Commit() = v.announce {
                    break;
                }
            }
        }
    }

    pub fn send_commit(from_dev: Device) {
        Trigger {
            from_dev,
            for_dev: Device::Anonymous(),
            announce: Action::Commit(),
        }.send();
    }

    /// returns only once all of the required announcement events
    /// have fired
    pub fn wait_all(r: &mut BusReader<Trigger>, mut set: Vec<Trigger>) {
        while !set.is_empty() {
            if let Ok(v) = r.recv() {
                println!("Got a message: {v:?}");
                set = set.into_iter().filter(|e| *e != v).collect();
            }
        }
    }

    pub fn wait_any(r: &mut Receiver<Trigger>, set: Vec<Trigger>) {
        while let Ok(v) = r.recv() {
            if set.contains(&v) {
                break;
            }
        }
    }
}

struct Platform {
    recv: BusReader<Trigger>,
    //send: Sender<Trigger>,

    cstate_stats: Vec<u64>,
}

impl Platform {
    /*pub fn start() -> JoinHandle<()> {
        std::thread::spawn(|| {
            Platform::new().run();
        })
    }*/

    fn new() -> Self {
        //let (send, recv) = parallel::register();
        Self {
            recv: recver(),
            cstate_stats: vec![],
        }
    }

    fn run(&mut self) {
        use parallel::Action;
        use parallel::Device;
        use parallel::Progress;

        while let Ok(trigger) = self.recv.recv() {
            println!("platform got trigger: {trigger:?}");

            match trigger.for_dev {
                parallel::Device::Platform() => match trigger.announce {
                    Action::Resume() => {
                        println!("platform starting resume");

                        println!("sent update");

                        let trigger = Trigger::new(
                            Action::Reply(Progress::Resuming()),
                            Device::Platform(),
                            Device::Anonymous(),
                        );

                        trigger.send();
                        //self.send.send(trigger).unwrap();

                        let mut wait_for = Vec::new();

                        for dev in [
                            Device::CPUs(),
                            Device::Display(),
                            Device::Bluetooth(),
                            Device::Wifi(),
                            Device::Processes(),
                            Device::VT(),
                        ] {
                            /*let _ = self.send.send(Trigger {
                                for_dev: dev.clone(),
                                announce: Action::Resume(),
                            });*/

                            println!("sending trigger to resume");

                            //trigger.send();
                            Trigger {
                                from_dev: Device::Platform(),
                                for_dev: dev,
                                announce: Action::Resume(),
                            }.send();

                            wait_for.push(Trigger {
                                for_dev: dev,
                                from_dev: Device::Platform(),
                                announce: Action::Reply(Progress::Resumed()),
                            })
                        }

                        send_commit(Device::Platform());

                        println!("sent commit, waiting...");

                        wait_all(&mut self.recv, wait_for);

                        println!("done wait");

                        /*self.send.send(Trigger {
                            for_dev: Device::VT(), announce: Action::Resume()
                        });*/

                        let trigger = Trigger::new(
                            Action::Reply(Progress::Resumed()),
                            Device::Platform(),
                            Device::Anonymous(),
                        );

                        trigger.send();

                        //self.send.send(trigger).unwrap();

                        println!("platform finished resume");

                        //
                    }
                    Action::Suspend() => {
                        println!("platform started suspend");
                        Trigger {
                            from_dev: Device::Platform(),
                            for_dev: trigger.from_dev,
                            announce: Action::Reply(Progress::Suspending()),
                        }.send();

                        let mut wait_for = Vec::new();

                        for dev in [
                            Device::CPUs(),
                            Device::Display(),
                            Device::Bluetooth(),
                            Device::Wifi(),
                            Device::Processes(),
                            Device::VT(),
                        ] {
                            Trigger {
                                from_dev: Device::Platform(),
                                for_dev: dev,
                                announce: Action::Suspend(),
                            }.send();

                            wait_for.push(Trigger {
                                for_dev: dev,
                                from_dev: Device::Platform(),
                                announce: Action::Reply(Progress::Suspended()),
                            })
                        }

                        send_commit(Device::Platform());

                        std::thread::spawn(move || {
                            wait_all(&mut recver(), wait_for);

                            Trigger {
                                from_dev: Device::Platform(),
                                for_dev: trigger.from_dev,
                                announce: Action::Reply(Progress::Suspended()),
                            }.send();

                            println!("platform finished suspend");
                        });
                    }

                    _ => (),
                },
                _ => (),
            }
        }
    }

    fn debug_low_power(&mut self) {
        println!("Checking stats");
        let sample_1 = self.get_cstate_stats();

        std::thread::sleep(Duration::from_secs(2));

        let sample_2 = self.get_cstate_stats();

        let counts: Vec<u64> = sample_1
            .into_iter()
            .zip(sample_2.into_iter())
            .map(|(a, b)| b - a)
            .rev()
            .collect();

        println!("Stats in rev order: {counts:?}");

        let mut counts = counts.into_iter();

        let c10 = counts.next().unwrap_or(1);
        let c9 = counts.next().unwrap_or(1);
        let c8 = counts.next().unwrap_or(1);
        let c7 = counts.next().unwrap_or(1);
        let c6 = counts.next().unwrap_or(1);
        let c3 = counts.next().unwrap_or(1);
        let c2 = counts.next().unwrap_or(1);

        if c10 > 0 {
            // sleeping peacefully :)
        } else if c9 > 0 {
            println!("Got to C9 but not C10, taking corrective actions");
            // could be that TCSS is in a bad state, try reset USB-C/USB subsystem
            // this is likely pipewire being naughty though, so instead of trying
            // to fully reset the usb subsystem lets just..."restart" that
            //let _ = execute::shell("killall pipewire pipewire-pulse").output();
            println!("Restarting pipewire because an app probably left something open (fuck you, discord)");
            let r = execute::shell("sudo -u sawyer XDG_RUNTIME_DIR=\"/run/user/$(id -u sawyer)\" systemctl --user restart pipewire pipewire-pulse").output();
            if let Ok(o) = r {
                println!("Ran restart of pw, stdout:");
                println!(
                    "{}",
                    String::from_utf8(o.stdout).unwrap_or("not utf8".to_owned())
                );
                println!(
                    "{}",
                    String::from_utf8(o.stderr).unwrap_or("not utf8".to_owned())
                );
            } else {
                println!("Failed to restart, unknown reason");
            }
            //println!("Res: {}", .stdout());

            /*
             * requirements for C10:
             *  All VRs at PS4 or LPM.
             *  Crystal clock off.
             *  TCSS may enter lowest power state (TC cold) 2
             */
        } else if c8 > 0 {
            println!("Got to C8 but not C9, will measure again, this is...strange");
            /*
             * requirements for C9:
             *  All IA cores in C9 or deeper
             *  display in PSR or off
             *  VCCIO stays on
             */
        } else if c7 > 0 {
            println!("Got to C7 but not C8, taking corrective actions");
            /* requirements for C8:
             *  C8 transient, involves LLC being flushed
             */
        } else if c6 > 0 {
            println!("Got to C6 but not C7, taking corrective actions");
            /* requirements for C7:
             *  all IA cores requested C7
             *  graphics cores in RC6 or deeper
             *  platform allow proper LTR
             */
        } else if c3 > 0 {
            println!("Got to C3 but not C6, taking corrective actions");
            /* requirements for C6:
             *  IA cores in C6 or deeper, GPU cores in RC6
             *  BCLK is off
             *  IMVP VRs voltage reduction, PSx state possible
             *
             *  try to wrest anything using GPU away from it?
             *  Likely GDM is in a weird state here unless something
             *  was between transactions. Try just retrying sleep cycle?
             */
            //self.async_resume_suspend_cycle(10);

            // for some reason adb sometimes gets us stuck in this state
            //let r = execute::shell("sudo adb kill-server").output();
        } else if c2 > 0 {
            println!("Got to C2 but not C3, taking corrective actions");
            // if we aren't getting deeper than this during *sleep* then realistically all hope is
            // lost, just...don't
            //self.async_resume_suspend_cycle(10);
        } else {
            println!("Never left C0!");
            // something is just eating our cpu whole and we're stuck in c0, abort??
        }

        if c10 < 1 {
            println!("Doing uniform tasks to try to recover things");

            println!("Restarting pipewire because an app probably left something open (fuck you, discord)");
            let _r = execute::shell("sudo -u sawyer XDG_RUNTIME_DIR=\"/run/user/$(id -u sawyer)\" systemctl --user restart pipewire pipewire-pulse").output();

            let _r = execute::shell("killall adb");
        }

        // schedule another checkup
        //schedule_power_check();
    }

    fn get_cstate_stats(&self) -> Vec<u64> {
        let empty = vec![0u64; 7];

        let cf = File::open("/sys/kernel/debug/pmc_core/package_cstate_show");

        if let Ok(mut cf) = cf {
            let mut build = Vec::new();
            let mut buf = String::new();

            let _ = cf.read_to_string(&mut buf);

            for line in buf.lines() {
                let num = line
                    .split_whitespace()
                    .last()
                    .unwrap_or("0")
                    .parse()
                    .unwrap_or(0);

                build.push(num);
            }
            //cf.
            //cf.close();

            build
        } else {
            empty
        }
    }

    fn print_cstate_stats(&self, old: Vec<u64>, new: Vec<u64>) {
        println!("Cstate stats:");
        let combined: Vec<u64> = old.iter().zip(new.iter()).map(|(a, b)| b - a).collect();

        let labels = vec!["C2", "C3", "C6", "C7", "C8", "C9", "C10"];

        let total: u64 = combined.iter().sum();

        let combined: Vec<(u64, &str)> = combined.into_iter().zip(labels.into_iter()).collect();

        for (state, label) in combined.iter() {
            let percent = 100.0 * (*state as f64 / total as f64);
            println!("Package {label} : {percent:.03}% of total",)
        }
    }

    fn load_us_modules(&mut self) {
        self.modprobe_on_list(self.modprobe_list(), true);
    }

    fn unload_us_modules(&mut self) {
        self.modprobe_on_list(
            self.modprobe_list()
                .iter()
                .rev()
                .map(|e| *e)
                .collect::<Vec<&str>>()
                .as_slice(),
            false,
        );
    }

    fn modprobe(&self, module: &str, load: bool) -> Option<()> {
        match load {
            true => Command::new("modprobe").arg(module).output(),
            false => Command::new("modprobe").arg("-r").arg(module).output(),
        }
        .ok()?;

        Some(())
    }

    fn modprobe_on_list(&self, list: &[&str], load: bool) {
        for elem in list {
            self.modprobe(elem, load);
        }
    }

    fn modprobe_list(&self) -> &'static [&'static str] {
        &[
            "i2c_hid",
            "i2c_hid_acpi",
            "i2c_smbus",
            "psmouse",
            //"btusb",
            //"btintel",
            //"v4l2loopback",
            //"dell_laptop",
            //"dell_wmi",
            //"bluetooth",
        ]
    }

    /// a minimum of 1 core is enabled regardless of requested count
    fn set_enabled_core_count(&mut self, count: usize) {
        println!("We have {} cpus available", num_cpus::get());
        let bounded = count.max(1usize);

        let bounded = bounded.min(num_cpus::get());

        for idx in 0..bounded {}
    }
}

struct VT {
    recv: BusReader<Trigger>,
    //send: Sender<Trigger>,
    suspended: bool,
    active_tty: String,
}

impl VT {
    pub fn start() -> JoinHandle<()> {
        std::thread::spawn(|| {
            VT::new().run();
        })
    }

    fn new() -> Self {
        //let (send, recv) = parallel::register();
        Self {
            recv: recver(),
            suspended: false,
            active_tty: String::new(),
        }
    }

    fn run(&mut self) {
        use parallel::Action;
        use parallel::Device;
        use parallel::Progress;

        while let Ok(trigger) = self.recv.recv() {
            match (trigger.for_dev, trigger.announce) {
                (Device::Platform(), Action::Resume()) => {
                    if self.suspended {
                        wait_all(
                            &mut self.recv,
                            vec![
                                Trigger {
                                    from_dev: Device::Processes(),
                                    for_dev: Device::Anonymous(),
                                    announce: Action::Reply(Progress::Resumed()),
                                },
                                Trigger {
                                    from_dev: Device::Display(),
                                    for_dev: Device::Anonymous(),
                                    announce: Action::Reply(Progress::Resumed()),
                                },
                            ],
                        );

                        self.suspended = true;

                        self.change_vt(&self.active_tty);
                    }

                    Trigger {
                        from_dev: Device::VT(),
                        for_dev: Device::Anonymous(),
                        announce: Action::Reply(Progress::Resumed()),
                    }.send();
                }
                (Device::Platform(), Action::Suspend()) => {
                    if !self.suspended {
                        self.active_tty = self.get_active_tty();

                        let _ = execute::shell("echo 0 > /sys/class/graphics/fbcon/cursor_blink")
                            .output();
                        let _ = execute::shell("openvt --switch bash").output();
                    }

                    Trigger {
                        from_dev: Device::VT(),
                        for_dev: Device::Anonymous(),
                        announce: Action::Reply(Progress::Suspended()),
                    }.send();
                }

                _ => (),
            }
        }
    }

    fn change_vt(&self, target: &str) {
        std::process::Command::new("chvt")
            .arg(&target[3..])
            .output()
            .unwrap();
    }

    fn get_active_tty(&mut self) -> String {
        /*let num = String::from_utf8(execute::shell("tty").output().unwrap().stdout).unwrap();
        let num = num.split("/").collect::<Vec<&str>>().into_iter().rev().next().unwrap();

        let ret = format!("tty{num}");*/

        let output = execute::shell("cat /sys/devices/virtual/tty/tty0/active").output();

        String::from_utf8(output.map(|o| o.stdout).unwrap_or(vec![])).unwrap_or("tty2".into())
    }
}

struct Processes {
    frozen_processes: Vec<FreezableProcess>,
    processes: Vec<procfs::process::Process>,

    suspended: bool,

    //send: Sender<Trigger>,
    recv: BusReader<Trigger>,
}

impl Processes {
    pub fn new() -> Self {
        //let (send, recv) = register();
        Self {
            suspended: false,
            frozen_processes: vec![],
            processes: vec![],
            recv: recver(),
        }
    }

    fn gather_procs(&mut self) -> Vec<FreezableProcess> {
        let mut r: Vec<FreezableProcess> = procfs::process::all_processes()
            .unwrap()
            .into_iter()
            .map(|proc| FreezableProcess::new(proc))
            .collect();

        r.sort_by_key(|p| p.pid()); // first sort by pid to disambiguate parent-child within same jiffy

        r.sort_by_key(|p| p.backing_process.stat().unwrap().starttime); // sort by start time, since pids could wrap

        r
    }

    fn suspend_userspace(&mut self) {
        self.frozen_processes = self.gather_procs();

        for proc in self.frozen_processes.iter_mut() {
            proc.suspend();
        }
    }

    fn resume_userspace(&mut self) {
        println!("Unfreezing {} processes", self.frozen_processes.len());

        let mut pstats = Vec::new();

        for proc in self.frozen_processes.iter_mut().rev() {
            let pstat = proc.resume();

            if let Some(pstat) = pstat {
                pstats.push(pstat);
            }
        }

        self.print_proc_stats(pstats);
    }

    fn print_proc_stats(&self, mut stats: Vec<ProcessStats>) {
        println!("Process statistics:");

        fn print_proc(s: &ProcessStats) {
            println!(
                "Process {} ({}) took {} utime, {} stime and had suspend state {}",
                s.pid, s.command, s.utime, s.stime, s.was_suspended
            );
        }

        stats.sort_by_key(|p| p.stime);

        println!("By stime:");
        stats.iter().rev().take(30).for_each(|s| {
            if s.stime > 0 {
                print_proc(s);
            }
        });

        stats.sort_by_key(|p| p.utime);

        println!("By utime:");
        stats.iter().rev().take(30).for_each(|s| {
            if s.utime > 0 {
                print_proc(s);
            }
        });
    }

    pub fn run(&mut self) {
        use parallel::Action;
        use parallel::Device;
        use parallel::Progress;

        while let Ok(trigger) = self.recv.recv() {
            match (trigger.for_dev, trigger.announce) {
                (Device::Platform(), Action::Resume()) => {
                    if self.suspended {
                        //self.resume_userspace();
                    }

                    Trigger {
                        announce: Action::Reply(Progress::Resumed()),
                        from_dev: Device::Processes(),
                        for_dev: Device::Anonymous(),
                    }.send();
                }

                (Device::Platform(), Action::Suspend()) => {
                    if !self.suspended {
                        //self.suspend_userspace();
                    }

                    Trigger {
                        announce: Action::Reply(Progress::Suspended()),
                        from_dev: Device::Processes(),
                        for_dev: Device::Anonymous(),
                    }.send();
                }

                _ => (),
            }
        }
    }
}

struct ProcessStats {
    utime: u64,
    stime: u64,
    command: String,
    pid: i32,
    was_suspended: bool,
}

struct FreezableProcess {
    backing_process: procfs::process::Process,

    stats_on_freeze: (
        Option<procfs::process::Stat>,
        Option<procfs::process::Status>,
    ),

    suspended: bool,
}

impl FreezableProcess {
    pub fn new(on: procfs::process::Process) -> Self {
        Self {
            suspended: false,
            stats_on_freeze: (None, None),
            backing_process: on,
        }
    }

    pub fn pid(&self) -> i32 {
        self.backing_process.pid()
    }

    pub fn powernap_list() -> &'static [&'static str] {
        &[
            "upowerd",
            "systemd-journal",
            "khugepaged",
            "systemd-logind",
            "sot",
        ]
    }

    pub fn should_powernap(&mut self) -> bool {
        let comm = self.backing_process.stat.comm.as_str();
        let owner = self.backing_process.owner;
        let cmdline = self.backing_process.cmdline().unwrap_or(Vec::new());
        let cmdline = cmdline.as_slice();
        let pid = self.pid();

        Self::powernap_list()
            .iter()
            .find(|kw| comm.contains(*kw))
            .is_some()
            && !self.suspended
    }

    pub fn suspend_anyway_kws() -> &'static [&'static str] {
        &[
            "evolution",
            "fwupd",
            "akonadi",
            "sidewinderd",
            "mozillavpn",
            "upowerd",
            /*"NetworkManager",
            "upowerd",
            "systemd-timesyn",
            "systemd-journal",*/

            /*
            "boltd",
            "cpuhp",
            "polkitd",
            "rcu",
            "systemd-udevd",
            "systemd",
            "migration",
            "dbus",
            "iio-sensor",
            "rtkit",
            "idle_inject",
            "khugepaged",
            */
            //"khugepaged",
            //"netns",

            //"dbus-daemon",
            //"dconf-service",
            //"iio_sensor_prox",
            //"wpa_supplicant",
        ]
    }

    pub fn continue_anyway_kws() -> &'static [&'static str] {
        &[
            "pipewire",
            "pipewire-pulse",
            "dbus-daemon",
            "wireplumber",
            "systemd",
            "sd-pam",
            "bash",
            "tmux",
            "asciinema",
            "cargo",
            "lid",
            "idle",
            "sot",
            "htop",
            "powertop",
            "power-usage-report",
            "turbostat",
            "sleep",
        ]
    }

    pub fn should_suspend(&mut self) -> bool {
        let comm = self.backing_process.stat.comm.as_str();
        let owner = self.backing_process.owner;
        let cmdline = self.backing_process.cmdline().unwrap_or(Vec::new());
        let cmdline = cmdline.as_slice();
        let pid = self.pid();

        let should = if owner < 1000 {
            // this is a root or system owned process

            Self::suspend_anyway_kws()
                .iter()
                .find(|kw| comm.contains(*kw))
                .is_some()
        } else {
            // this is user owned

            Self::continue_anyway_kws()
                .iter()
                .find(|kw| comm.contains(*kw))
                .is_none()
        };

        println!("Declares {pid} {comm}: {cmdline:?} should be in suspend state {should}, it is owned by {owner}");

        should
    }

    pub fn suspend(&mut self) {
        if self.should_suspend() {
            self.suspended = true;

            //println!("Sending {} a sigstop", self.backing_process.stat.comm);
            self.signal(Signal::SIGSTOP);
        }

        self.stats_on_freeze = self.stats();
    }

    pub fn stats(&mut self) -> (Option<Stat>, Option<Status>) {
        (
            self.backing_process.stat().ok(),
            self.backing_process.status().ok(),
        )
    }

    pub fn resume(&mut self) -> Option<ProcessStats> {
        let new_stats = self.stats();

        let r = match (self.stats_on_freeze.clone(), new_stats) {
            ((Some(old_stat), Some(old_status)), (Some(new_stat), Some(new_status))) => {
                Some(ProcessStats {
                    pid: self.pid(),
                    command: new_stat.comm,
                    utime: new_stat.utime - old_stat.utime,
                    stime: new_stat.stime - old_stat.stime,
                    was_suspended: self.suspended,
                })
            }
            _ => None, // oh well
        };

        if self.suspended {
            //println!("Sending {} a sigcont", self.backing_process.stat.comm);
            self.signal(Signal::SIGCONT);

            self.suspended = false;
        }

        r
    }

    fn signal(&mut self, sig: Signal) {
        let pid = self.pid();
        let res = nix::sys::signal::kill(Pid::from_raw(pid), sig);

        match res {
            Err(v) => {
                println!("Couldn't send {sig} to pid {pid}, error: {v}");
            }
            _ => (),
        }
    }
}

struct Cpus {
    // vec of cpu ids
    //available: Vec<u64>,

    //enabled: Vec<u64>,
    //send: Sender<Trigger>,
    recv: BusReader<Trigger>,

    suspended: bool,
}

impl Cpus {
    pub fn run(&mut self) {
        use parallel::Action;
        use parallel::Device;
        use parallel::Progress;

        while let Ok(trigger) = self.recv.recv() {
            match (trigger.for_dev, trigger.announce) {
                (Device::Platform(), Action::Resume()) => {
                    println!("cpus told to resume");
                    if self.suspended {
                        self.powersave();
                    }

                    Trigger {
                        announce: Action::Reply(Progress::Resumed()),
                        from_dev: Device::CPUs(),
                        for_dev: Device::Anonymous(),
                    }.send();
                }

                (Device::Platform(), Action::Suspend()) => {
                    println!("cpus told to suspend");
                    if !self.suspended {
                        //self.superpowersave();
                    }

                    Trigger {
                        announce: Action::Reply(Progress::Suspended()),
                        from_dev: Device::CPUs(),
                        for_dev: Device::Anonymous(),
                    }.send();
                }

                _ => (),
            }
        }
    }

    fn parse_range(line: &str) -> Vec<usize> {
        let mut builder = Vec::new();

        let ranges = line.split(",");

        for range in ranges {
            let mut elements = range.split("-");

            let start: usize = elements.next().unwrap_or("0").parse().unwrap_or(0);
            let end: usize = elements.next().unwrap_or("0").parse().unwrap_or(0);

            for id in start..=end {
                builder.push(id);
            }
        }

        builder.sort();
        builder.dedup();

        builder
    }

    fn get_cpu_range(file: &str) -> Vec<usize> {
        if let Ok(contents) = std::fs::read_to_string(file) {
            for line in contents.lines() {
                return Self::parse_range(line);
            }
        }

        Vec::new()
    }

    fn detect_available(&mut self) -> Vec<usize> {
        Self::get_cpu_range("/sys/devices/system/cpu/possible")
    }

    fn detect_enabled(&mut self) -> Vec<usize> {
        Self::get_cpu_range("/sys/devices/system/cpu/online")
    }

    fn set_cpu_state(&mut self, cpus: Vec<(usize, bool)>) {
        for (cpid, enabled) in cpus {
            let enabled = if enabled { "1" } else { "0" };
            println!("Setting state of core {cpid} to {enabled}");
            let _ = execute::shell(format!(
                "echo {enabled} > /sys/devices/system/cpu/cpu{cpid}/online"
            ))
            .output();

            let _ = execute::shell(format!(
                "echo 15 > /sys/devices/system/cpu/cpu{cpid}/power/energy_perf_bias"
            ))
            .output();
        }
    }

    fn disabled_set(&mut self) -> Vec<(usize, bool)> {
        let mut cpus: Vec<(usize, bool)> = self
            .detect_available()
            .into_iter()
            .map(|cpid| (cpid, false))
            .collect();

        cpus
    }

    fn enable_count(&mut self, count: usize) {
        // failsafe so we never disable all cores
        let count = count.max(1);

        let mut cpus = self.disabled_set();

        for i in 0..(count.min(cpus.len())) {
            cpus[i].1 = true;
        }

        self.set_cpu_state(cpus);
    }

    fn superpowersave(&mut self) {
        // we will enable a single core

        self.enable_count(1);
    }

    fn powersave(&mut self) {
        self.enable_count(12); // just leave it, it's fine
    }

    fn performance(&mut self) {
        self.enable_count(128); // just...don't use this script with a dual socket amd epyc :)
    }

    fn new() -> Self {
        //let (send, recv) = parallel::register();
        Self {
            recv: recver(),
            suspended: false,
        }
    }
}

struct Wifi {
    suspended: bool,
    disabled: bool,

    //send: Sender<Trigger>,
    recv: BusReader<Trigger>,
}

impl Wifi {
    fn new() -> Self {
        //let (send, recv) = parallel::register();
        Self {
            recv: recver(),
            suspended: false,
            disabled: false,
        }
    }

    fn resume(&mut self) {
        let _ = execute::shell("nmcli radio wifi on").output();
    }

    fn suspend(&mut self) {
        let _ = execute::shell("nmcli radio wifi off").output();
    }

    fn detect(&mut self) {
        let cmdout = execute::shell("nmcli radio wifi").output().unwrap().stdout;
        let as_str = String::from_utf8(cmdout).unwrap();

        if as_str.contains("enabled") {
            self.disabled = false;
        } else {
            self.disabled = true;
        }
    }

    fn run(&mut self) {
        use parallel::Action;
        use parallel::Device;
        use parallel::Progress;

        while let Ok(trigger) = self.recv.recv() {
            match (trigger.for_dev, trigger.announce) {
                (Device::Platform(), Action::Resume()) => {
                    if self.suspended && !self.disabled {
                        self.resume();
                    }

                    Trigger {
                        announce: Action::Reply(Progress::Resumed()),
                        from_dev: Device::Wifi(),
                        for_dev: Device::Anonymous(),
                    }.send();
                }
                (Device::Platform(), Action::Suspend()) => {
                    if !self.suspended {
                        self.detect();

                        if !self.disabled {
                            self.suspend();
                        }
                    }

                    Trigger {
                        announce: Action::Reply(Progress::Suspended()),
                        from_dev: Device::Wifi(),
                        for_dev: Device::Anonymous(),
                    }.send();
                }
                _ => (),
            }
        }
    }
}

struct Bluetooth {
    suspended: bool,
    disabled: bool,

    //send: Sender<Trigger>,
    recv: BusReader<Trigger>,
}

impl Bluetooth {
    fn new() -> Self {
        //let (send, recv) = parallel::register();
        Self {
            recv: recver(),
            suspended: false,
            disabled: false,
        }
    }

    fn resume(&mut self) {
        println!("Enabling bluetooth bluetooth");
        let _ = execute::shell("rfkill unblock bluetooth").output();
        std::thread::sleep(Duration::from_millis(200)); // otherwise doesn't have long enough
    }

    fn suspend(&mut self) {
        println!("Disabling bluetooth");
        let _ = execute::shell("rfkill block bluetooth").output();
        std::thread::sleep(Duration::from_millis(200)); // otherwise doesn't have long enough
    }

    fn detect(&mut self) {
        let cmdout = execute::shell("rfkill list bluetooth")
            .output()
            .unwrap()
            .stdout;
        let as_str = String::from_utf8(cmdout).unwrap();

        if as_str.contains("yes") {
            self.disabled = false;
        } else {
            self.disabled = true;
        }
    }

    fn run(&mut self) {
        use parallel::Action;
        use parallel::Device;
        use parallel::Progress;

        while let Ok(trigger) = self.recv.recv() {
            println!("bluetooth got trigger: {trigger:?}");
            match (trigger.for_dev, trigger.announce) {
                (Device::Platform(), Action::Resume()) => {
                    println!("bluetooth resuming");

                    if self.suspended && !self.disabled {
                        self.resume();
                    }

                    Trigger {
                        announce: Action::Reply(Progress::Resumed()),
                        from_dev: Device::Bluetooth(),
                        for_dev: Device::Anonymous(),
                    }.send();

                    println!("bluetooth done resume");
                }
                (Device::Platform(), Action::Suspend()) => {
                    if !self.suspended {
                        self.detect();

                        if !self.disabled {
                            self.suspend();
                        }
                    }

                    Trigger {
                        announce: Action::Reply(Progress::Suspended()),
                        from_dev: Device::Bluetooth(),
                        for_dev: Device::Anonymous(),
                    }.send();
                }
                _ => (),
            }
        }
    }
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

#[derive(Debug, Clone, Copy)]
enum DPMSState {
    On = 0,
    Standby = 1,
    Suspend = 2,
    Off = 3,
    Unknown,
}

struct Monitors {
    //dpms_handle: Option<drm::control::property::Info>,
    dpms_handle: Option<drm::control::property::Handle>,
    conn_handle: Option<drm::control::connector::Handle>,
    card: Card,
}

impl Monitors {
    fn new() -> Self {
        let card = Card::open_global();

        let mut m = Monitors {
            card,
            dpms_handle: None,
            conn_handle: None,
        };

        m.refresh_dpms_info();

        m
    }

    fn refresh_dpms_info(&mut self) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let resources = self.card.resource_handles()?;

        for conn_handle in resources.connectors() {
            let props = self.card.get_properties(*conn_handle)?;
            let (ids, vals) = props.as_props_and_values();

            for (&id, &val) in ids.iter().zip(vals.iter()) {
                //println!("Property: {:?}", id);
                let info = self.card.get_property(id)?;
                //println!("Val: {}", val);

                if info.name().to_str().unwrap() == "DPMS" {
                    println!("{:?}", info.name());
                    println!("{:#?}", info.value_type());
                    println!("Mutable: {}", info.mutable());
                    println!("Atomic: {}", info.atomic());
                    println!("Value: {:?}", info.value_type().convert_value(val));
                    println!();

                    self.dpms_handle = Some(id);
                    self.conn_handle = Some(*conn_handle);

                    //info.value_type().convert_value(val)
                    //card.set_property(*conn_handle, id, num).unwrap();
                    //std::thread::sleep_ms(1000);
                    //card.set_property(*conn_handle, id, 0).unwrap();
                    //break 'outer;
                }
            }
        }
        println!("Dpms could not be detected");

        Ok(())
    }

    fn get_dpms(&self) -> DPMSState {
        match self.conn_handle {
            Some(v) => {
                self.card.get_properties(v).unwrap();
            }
            None => {}
        }

        match self.dpms_handle {
            Some(handle) => match self.card.get_property(handle) {
                Ok(v) => {}
                _ => {}
            },
            None => {}
        }

        DPMSState::Unknown
    }

    /*fn set_dpms_state(&mut self) {
        match self.dpms_handle {
            Some(handle) => {
                //self.card.set_property(handle, , value)
                self.card.set_property(handle, prop, value)

            }
            None => (),
        }
    }*/

    pub fn load_image(path: &str) -> image::RgbaImage {
        //let path = format!("examples/images/{}", name);

        image::open(path).unwrap().to_rgba8()
    }

    fn hold_resume_display() {
        std::thread::spawn(|| {
            let cond = AtomicBool::new(false);
            let _ = Self::set_resume_display(&cond);
        });
    }

    fn set_resume_display(
        freed: &AtomicBool,
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        use drm::buffer::DrmFourcc;
        use drm::control::{connector, crtc};

        let card = Card::open_global();

        // Load the information.
        let res = card.resource_handles()?;
        //.expect("Could not load normal resource ids.");
        let coninfo: Vec<connector::Info> = res
            .connectors()
            .iter()
            .flat_map(|con| card.get_connector(*con))
            .collect();
        let crtcinfo: Vec<crtc::Info> = res
            .crtcs()
            .iter()
            .flat_map(|crtc| card.get_crtc(*crtc))
            .collect();

        // Filter each connector until we find one that's connected.
        let con = coninfo
            .iter()
            .find(|&i| i.state() == connector::State::Connected)
            .ok_or::<Box<dyn std::error::Error>>("no connected connectors".into())?;
        //.expect("No connected connectors");

        // Get the first (usually best) mode
        let &mode = con
            .modes()
            .get(0)
            .ok_or::<Box<dyn std::error::Error>>("No modes found on connector".into())?; //.expect("No modes found on connector");

        let (disp_width, disp_height) = mode.size();

        // Find a crtc and FB
        let crtc = crtcinfo
            .get(0) //.expect("No crtcs found");
            .ok_or::<Box<dyn std::error::Error>>("No crtcs found".into())?; //.expect("No modes found on connector");

        // Select the pixel format
        let fmt = DrmFourcc::Xrgb8888;

        // Create a DB
        // If buffer resolution is larger than display resolution, an ENOSPC (not enough video memory)
        // error may occur
        let mut db = card.create_dumb_buffer((disp_width.into(), disp_height.into()), fmt, 32)?;
        //.expect("Could not create dumb buffer");

        // Map it and grey it out.
        {
            let mut map = card.map_dumb_buffer(&mut db)?;
            //.expect("Could not map dumbbuffer");

            let img = Self::load_image("/home/sawyer/default.png");
            let img = imageops::resize(
                &img,
                disp_width as u32,
                disp_height as u32,
                imageops::FilterType::Triangle,
            );

            let pixels = img.pixels();

            let buffer = map.as_mut();

            println!("disp dims: {disp_width}, {disp_height}");
            println!("Image dims: {}, {}", img.width(), img.height());

            for (img_px, map_px) in img.pixels().zip(buffer.chunks_exact_mut(4)) {
                // Assuming little endian, it's BGRA
                map_px[0] = img_px[2]; // Blue
                map_px[1] = img_px[1]; // Green
                map_px[2] = img_px[0]; // Red
                map_px[3] = img_px[3]; // Alpha
            }

            /*for b in map.as_mut().iter_mut().enumerate() {
            }*/
            /*for b in map.as_mut() {
                *b = 128;
            }*/
        }

        // Create an FB:
        let fb = card.add_framebuffer(&db, 24, 32)?;
        //.expect("Could not create FB");

        println!("{:#?}", mode);
        println!("{:#?}", fb);
        println!("{:#?}", db);

        // Set the crtc
        // On many setups, this requires root access.
        card.set_crtc(crtc.handle(), Some(fb), (0, 0), &[con.handle()], Some(mode))?;
        //.expect("Could not set CRTC");

        //let five_seconds = ::std::time::Duration::from_millis(5000);
        //::std::thread::sleep(five_seconds);
        //std::thread::sleep_ms(700);

        loop {
            if freed.load(std::sync::atomic::Ordering::Relaxed) {
                std::thread::sleep_ms(100);
                break;
            } else {
                std::thread::sleep_ms(1000);
            }
        }

        //card.destroy_framebuffer(fb).unwrap();
        //card.destroy_dumb_buffer(db).unwrap();

        Ok(())
    }

    fn set_dpms(state: DPMSState) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let card = Card::open_global();
        let resources = card.resource_handles()?;

        for conn_handle in resources.connectors() {
            let props = card.get_properties(*conn_handle)?;
            let (ids, vals) = props.as_props_and_values();

            for (&id, &val) in ids.iter().zip(vals.iter()) {
                //println!("Property: {:?}", id);
                let info = card.get_property(id)?;
                //println!("Val: {}", val);

                if info.name().to_str().unwrap() == "DPMS" {
                    let num = match state {
                        DPMSState::On => 0,
                        DPMSState::Standby => 1,
                        DPMSState::Suspend => 2,
                        DPMSState::Off => 3,
                        DPMSState::Unknown => return Err("had unknown dpms state!".into()),
                    };

                    card.set_property(*conn_handle, id, num);
                }
            }
        }

        Ok(())
    }

    fn get_dpms_status() -> std::result::Result<DPMSState, Box<dyn std::error::Error>> {
        //let card = Card
        let card = Card::open_global();
        let resources = card.resource_handles()?;

        for conn_handle in resources.connectors() {
            let props = card.get_properties(*conn_handle)?;
            let (ids, vals) = props.as_props_and_values();

            for (&id, &val) in ids.iter().zip(vals.iter()) {
                //println!("Property: {:?}", id);
                let info = card.get_property(id)?;
                //println!("Val: {}", val);

                if info.name().to_str().unwrap() == "DPMS" {
                    println!("{:?}", info.name());
                    println!("{:#?}", info.value_type());
                    println!("Mutable: {}", info.mutable());
                    println!("Atomic: {}", info.atomic());
                    println!("Value: {:?}", info.value_type().convert_value(val));
                    println!();

                    return Ok(match val {
                        0 => DPMSState::On,
                        1 => DPMSState::Standby,
                        2 => DPMSState::Suspend,
                        3 => DPMSState::Off,
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
        println!("Dpms could not be detected");

        Err("nothing detected".into())
    }
}

use num_enum::{FromPrimitive, IntoPrimitive};

#[derive(IntoPrimitive, FromPrimitive)]
#[repr(u8)]
#[derive(Clone, Copy, Debug)]
enum EventReason {
    #[default]
    PowerButton,

    LidOpen,
    LidClose,

    Suspend,
    Resume,

    PowerConnect,
    PowerDisconnect,

    DebugLowPowerStates,

    Check,

    Exit,
}
