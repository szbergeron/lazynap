use battery::*;
use procfs::process::{Stat, Status};
use std::collections::HashMap;
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
            "test" => testing(),
            //"test" => testing(),
            _ => {}
        }
    }
}

struct System {
    context: Context,
    devices: Vec<Box<dyn PoweredDevice>>,
    battery_manager: battery::Manager,

    info: HashMap<String, Data>,

    flags: SystemFlags,
}

#[derive(Default, Debug, Clone)]
struct SystemFlags {
    power_connected: bool,
    lid_closed: bool,
    sleeping: bool,
}

enum Data {
    Bool(bool),
    Integer(i64),
    String(String),
    Map(HashMap<String, Data>),
}

impl System {
    fn new() -> Self {
        System {
            context: Context::default(),
            //devices: vec![Wifi::create(), Bluetooth::create(), Platform::create()],
            devices: vec![
                Display::create(),
                Wifi::create(),
                Bluetooth::create(),
                Platform::create(),
            ],
            //devices: vec![Platform::create()],
            //devices: vec![Display::create()],
            battery_manager: battery::Manager::new().unwrap(),
            info: HashMap::new(),
            flags: Default::default(),
        }
    }

    fn power_button(&mut self) {
        self.flags.sleeping = !self.flags.sleeping;

        if self.flags.sleeping {
            self.suspend();
        } else {
            self.resume();
        }
    }

    fn lid_open(&mut self) {
        self.flags.lid_closed = false;

        if self.flags.sleeping {
            self.flags.sleeping = false;
            self.resume()
        }
    }

    fn lid_close(&mut self) {
        self.flags.lid_closed = true;

        if !self.flags.power_connected {
            if !self.flags.sleeping {
                self.flags.sleeping = true;
                self.suspend();
            }
        } else {
            println!("Inhibiting sleep since power is connected")
        }
    }

    fn power_connect(&mut self) {
        self.flags.power_connected = true;
    }

    fn power_disconnect(&mut self) {
        self.flags.power_connected = false;

        // If we're disconnecting power and the lid is shut,
        // we want system to go into suspend
        if !self.flags.sleeping && self.flags.lid_closed {
            self.flags.sleeping = true;
            self.suspend();
        }
    }

    fn handle_acpi(&mut self, event: EventReason) {
        use EventReason::*;

        match event {
            PowerButton => self.power_button(),
            LidOpen => self.lid_open(),
            LidClose => self.lid_close(),
            PowerConnect => self.power_connect(),
            PowerDisconnect => self.power_disconnect(),
            _ => (),
        }
    }

    fn suspend(&mut self) {
        let start = Instant::now();

        for d in self.devices.iter_mut() {
            d.detect();

            if d.should_block_sleep() {
                d.suspend();
            }
        }

        let end = Instant::now();

        println!(
            "Suspend took {} seconds, unknown seconds since screen was locked",
            (end - start).as_secs_f64(),
            //(end - post_lock).as_secs_f64()
        );

        println!("Running a sleep study");
        //return;

        //let mut o = execute::shell("turbostat --show Pkg%pc2,Pkg%pc3,Pkg%pc6,Pkg%pc7,Pkg%pc8,Pkg%pc9,Pk%pc10,SYS%LPI sleep 300");
        //let mut o = execute::shell("power-usage-report");
        let mut o = execute::shell("/home/sawyer/oss/idle/while_sleeping.sh");
        let o = o.output();
        if let Ok(o) = o {
            let os = String::from_utf8(o.stdout).unwrap_or(String::new());
            let oe = String::from_utf8(o.stderr).unwrap_or(String::new());

            //use std::fmt::Write;
            let f = std::fs::File::create("/home/sawyer/oss/idle/while_sleeping_output.txt");
            if let Ok(mut f) = f {
                let _ = writeln!(f, "Stdout:");
                let _ = writeln!(f, "{os}");
                let _ = writeln!(f, "Stderr:");
                let _ = writeln!(f, "{oe}");
            }
        }
    }

    fn resume(&mut self) {
        // unpowermanage devices in reverse suspend order, starting with platform
        for d in self.devices.iter_mut().rev() {
            d.resume(); // noop if wasn't suspended or if device couldn't block sleep
        }
    }

    fn print_report(&mut self) {
        println!(
            "Current power status is: {:?}",
            BatteryStatistic::collect(self.battery_manager.batteries().unwrap())
        );
        for dev in self.devices.iter_mut() {
            let rep = dev.report().unwrap();
            let devname = dev.name();

            println!("Report for device {devname}:");
            println!("\t{rep:?}")
        }
    }
}

//#[derive(Serialize, Deserialize, Debug)]
/*enum Message {
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
}*/

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct BatteryStatistic {
    /// current battery percentage
    battery_pct: f32,

    /// watt hours remaining
    battery_energy: f32,

    /// positive if charging, negative if
    /// discharging, measured in watts
    energy_rate: f32,

    display_dpms_state: DPMSState,

    time: Instant,
}

#[derive(Debug, Clone, Copy, Default)]
struct DeviceStatistic {
    time_sleeping: Duration,
    time_active: Duration,
    time_disabled: Duration,
}

impl BatteryStatistic {
    #[allow(dead_code)]
    fn collect(mut batteries: Batteries) -> BatteryStatistic {
        let batt = batteries.next().unwrap().unwrap();
        let rate = batt.energy_rate().get::<battery::units::power::watt>();
        let charge = batt.energy().get::<battery::units::energy::watt_hour>();
        let charge_full = batt
            .energy_full()
            .get::<battery::units::energy::watt_hour>();
        //battery.energy().get::<battery::units::Energy>();

        BatteryStatistic {
            battery_pct: (charge / charge_full),
            battery_energy: charge,
            energy_rate: rate,
            display_dpms_state: DPMSState::Unknown,
            time: Instant::now(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum SleepState {
    Sleeping(),
    Awake(),
    Unknown(),
}

#[derive(Debug, Clone, Copy)]
enum DPMSState {
    On = 0,
    Standby = 1,
    Suspend = 2,
    Off = 3,
    Unknown,
}

#[derive(Debug, Clone, Copy)]
enum LidState {
    Open,
    Closed,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DevicePowerState {
    Enabled,
    Disabled,
    PowerSave,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DeviceState {
    power: DevicePowerState,
    present: DevicePresenceState,
}

impl DeviceState {
    fn present_on() -> Self {
        DeviceState {
            power: DevicePowerState::Enabled,
            present: DevicePresenceState::Present,
        }
    }

    fn unknown() -> Self {
        DeviceState {
            power: DevicePowerState::Unknown,
            present: DevicePresenceState::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DevicePresenceState {
    Present,
    Missing,
    Unknown,
}

#[derive(Debug, Clone, Copy)]
struct DeviceStateTransition {
    old: DeviceState,
    new: DeviceState,
    time: Instant,
}

impl DeviceStateTransition {
    pub fn new(old: DeviceState, new: DeviceState) -> Self {
        Self {
            old,
            new,
            time: Instant::now(),
        }
    }

    pub fn first() -> Self {
        Self::new(DeviceState::unknown(), DeviceState::present_on())
    }

    //pub fn first(old: DeviceState::unknown(), new: DeviceState::present_on())
}

#[derive(Debug, Clone)]
struct Display {
    state: DeviceState,
    log: Vec<DeviceStateTransition>,
}

impl Display {
    fn create() -> Box<Self> {
        Box::new(Self {
            state: DeviceState::present_on(),
            log: vec![DeviceStateTransition::first()],
        })
    }
}

impl PoweredDevice for Display {
    fn events(&self) -> &[DeviceStateTransition] {
        self.log.as_slice()
    }

    fn events_mut(&mut self) -> &mut Vec<DeviceStateTransition> {
        &mut self.log
    }

    fn enable(&mut self) {
        // don't do anything here :)

        self.state.power = DevicePowerState::Enabled;
    }

    fn disable(&mut self) {
        lock_blank_screen();

        std::thread::sleep(Duration::from_secs(2));

        self.state.power = DevicePowerState::Disabled;
    }

    fn state(&self) -> DeviceState {
        self.state
    }

    fn set_power(&mut self, state: DevicePowerState) {
        self.state.power = state;
    }

    fn should_block_sleep(&self) -> bool {
        true
    }

    fn detect(&mut self) {
        println!("Monitor detect called");

        let status = Monitors::get_dpms_status();

        println!("Got status: {status:?}");

        let status = match status {
            Ok(DPMSState::On) => DevicePowerState::Enabled,
            Ok(DPMSState::Off) => DevicePowerState::Disabled,
            Ok(DPMSState::Unknown) => DevicePowerState::Unknown,
            Ok(_) => DevicePowerState::PowerSave,
            Err(e) => {
                println!("Got detection error: {e}");
                DevicePowerState::Unknown
            }
        };

        let presence = DevicePresenceState::Present;

        self.state = DeviceState {
            power: status,
            present: presence,
        };

        self.handle_detect(self.state);
    }

    fn name(&self) -> &'static str {
        "display"
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

    pub fn suspend_anyway_kws() -> &'static [&'static str] {
        &[
            "evolution",
            "fwupd",
            "akonadi",
            "sidewinderd",

            "NetworkManager",
            //"upowerd",
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
            //"systemd",

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

            Self::suspend_anyway_kws().iter().find(|kw| comm.contains(*kw)).is_some()
        } else {
            // this is user owned

            Self::continue_anyway_kws().iter().find(|kw| comm.contains(*kw)).is_none()
        };

        println!("Declares {pid} {comm}: {cmdline:?} should be in suspend state {should}, it is owned by {owner}");

        should
    }

    pub fn suspend(&mut self) {
        self.stats_on_freeze = self.stats();

        if self.should_suspend() {
            self.suspended = true;

            //println!("Sending {} a sigstop", self.backing_process.stat.comm);
            self.signal(Signal::SIGSTOP);
        }
    }

    pub fn stats(&mut self) -> (Option<Stat>, Option<Status>) {
            (
                self.backing_process.stat().ok(),
                self.backing_process.status().ok()
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
            },
            _ => {
                None
            } // oh well
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
}

impl Cpus {
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
                return Self::parse_range(line)
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
            execute::shell(format!("echo {enabled} > /sys/devices/system/cpu/cpu{cpid}/online")).output();
        }
    }

    fn disabled_set(&mut self) -> Vec<(usize, bool)> {
        let mut cpus: Vec<(usize, bool)> = self.detect_available().into_iter().map(|cpid| (cpid, false)).collect();

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
        self.enable_count(4);
    }

    fn performance(&mut self) {
        self.enable_count(128); // just...don't use this script with a dual socket amd epyc :)
    }

    fn create() -> Self {
        Self {}
    }
}

/// Describes the SoC/RAM/Chipset
/// as a power manageable component
///
/// Here, only for tracking when we
/// try entering different power states such as "sleep"
struct Platform {
    frozen_processes: Vec<FreezableProcess>,
    state: DeviceState,
    log: Vec<DeviceStateTransition>,

    cpus: Cpus,

    cstate_stats: Vec<u64>,

    processes: Vec<procfs::process::Process>,
}

impl Platform {
    fn create() -> Box<Self> {
        let s = Self {
            cpus: Cpus::create(),
            cstate_stats: vec![0u64; 7],
            processes: Vec::new(),
            frozen_processes: Vec::new(),
            state: DeviceState::present_on(),
            log: vec![DeviceStateTransition::first()],
        };

        let b = Box::new(s);

        b
    }

    fn gather_procs(&mut self) -> Vec<FreezableProcess> {
        let mut r: Vec<FreezableProcess> = procfs::process::all_processes().unwrap().into_iter().map(|proc| {
            FreezableProcess::new(proc)
        }).collect();

        r.sort_by_key(|p| p.pid());

        r
    }

    fn get_cstate_stats(&self) -> Vec<u64> {
        let empty = vec![0u64; 7];

        let cf = File::open("/sys/kernel/debug/pmc_core/package_cstate_show");

        if let Ok(mut cf) = cf {
            let mut build = Vec::new();
            let mut buf = String::new();

            cf.read_to_string(&mut buf);

            for line in buf.lines() {
                let num = line.split_whitespace().last().unwrap_or("0").parse().unwrap_or(0);

                build.push(num);
            }

            build

        } else {
            empty
        }
    }

    fn print_cstate_stats(&self, old: Vec<u64>, new: Vec<u64>) {
        println!("Cstate stats:");
        let combined: Vec<u64> = old
            .iter()
            .zip(new.iter())
            .map(|(a, b)| b - a)
            .collect();

        let labels = vec!["C2", "C3", "C6", "C7", "C8", "C9", "C10"];

        let total: u64 = combined.iter().sum();

        let combined: Vec<(u64, &str)> = combined.into_iter().zip(labels.into_iter()).collect();


        for (state, label) in combined.iter() {
            let percent = 100.0 * (*state as f64 / total as f64);
            println!("Package {label} : {percent:.03}% of total", )
        }
    }

    fn suspend_userspace(&mut self) {
        self.frozen_processes = self.gather_procs();


        //self.frozen_processes.sort_by_key(|p| p.pid());

        for proc in self.frozen_processes.iter_mut() {
            proc.suspend();
        }

        self.cstate_stats = self.get_cstate_stats();

        self.cpus.superpowersave();
    }

    fn resume_userspace(&mut self) {
        println!("Unfreezing {} processes", self.frozen_processes.len());

        self.cpus.powersave();

        let new_cstate_stats = self.get_cstate_stats();

        let a = Instant::now();

        let mut pstats = Vec::new();

        for proc in self.frozen_processes.iter_mut().rev() {
            let pstat = proc.resume();

            if let Some(pstat) = pstat {
                pstats.push(pstat);
            }
        }
        let b = Instant::now();

        self.print_proc_stats(pstats);

        println!("Unfreeze took {} seconds", (b - a).as_secs_f64());

        self.print_cstate_stats(self.cstate_stats.clone(), new_cstate_stats);


        //self.set_enabled_core_count(100);

    }

    fn print_proc_stats(&self, mut stats: Vec<ProcessStats>) {
        println!("Process statistics:");

        fn print_proc(s: &ProcessStats) {
            println!("Process {} ({}) took {} utime, {} stime and had suspend state {}",
                s.pid, s.command, s.utime, s.stime, s.was_suspended
            );
        }

        stats.sort_by_key(|p| p.stime);

        println!("By stime:");
        stats.iter().rev().take(30).for_each(|s| {
            print_proc(s);
        });

        stats.sort_by_key(|p| p.utime);

        println!("By utime:");
        stats.iter().rev().take(30).for_each(|s| {
            print_proc(s);
        });
    }

    fn load_us_modules(&mut self) {
        modprobe_on_list(modprobe_list(), true);
    }

    fn unload_us_modules(&mut self) {
        modprobe_on_list(modprobe_list(), false);
    }

    /// a minimum of 1 core is enabled regardless of requested count
    fn set_enabled_core_count(&mut self, count: usize) {
        println!("We have {} cpus available", num_cpus::get());
        let bounded = count.max(1usize);

        let bounded = bounded.min(num_cpus::get());

        for idx in 0..bounded {
        }
    }
}

impl PoweredDevice for Platform {
    fn name(&self) -> &'static str {
        "platform"
    }

    fn events(&self) -> &[DeviceStateTransition] {
        self.log.as_slice()
    }

    fn events_mut(&mut self) -> &mut Vec<DeviceStateTransition> {
        &mut self.log
    }

    fn detect(&mut self) {
        // platform can't be managed except through here, so
        // detection is unecessary
        self.handle_detect(self.state());
    }

    fn enable(&mut self) {
        panic!("Not applicable to platform")
    }

    fn disable(&mut self) {
        panic!("Not applicable to platform")
    }

    fn resume(&mut self) {
        // we can unconditionally resume since
        // sending sigcont and doing modprobes is idempotent
        match self.state().power {
            DevicePowerState::PowerSave | DevicePowerState::Disabled => {
                self.resume_userspace();

                self.load_us_modules();

                self.set_power(DevicePowerState::Enabled);
            }
            _ => (),
        }
    }

    fn suspend(&mut self) {
        match self.state().power {
            DevicePowerState::Enabled => {
                self.unload_us_modules();

                self.suspend_userspace();

                self.set_power(DevicePowerState::PowerSave);
            }
            _ => (),
        }
    }

    fn state(&self) -> DeviceState {
        self.state
    }

    fn set_power(&mut self, state: DevicePowerState) {
        self.state.power = state;
    }

    fn should_block_sleep(&self) -> bool {
        true
    }
}

#[derive(Debug, Clone)]
struct Wifi {
    state: DeviceState,
    log: Vec<DeviceStateTransition>,
}

impl Wifi {
    fn create() -> Box<Self> {
        Box::new(Self {
            state: DeviceState::unknown(),
            log: vec![DeviceStateTransition::first()],
        })
    }
}

impl PoweredDevice for Wifi {
    fn events(&self) -> &[DeviceStateTransition] {
        self.log.as_slice()
    }

    fn events_mut(&mut self) -> &mut Vec<DeviceStateTransition> {
        &mut self.log
    }

    fn enable(&mut self) {
        execute::shell("nmcli radio wifi on");

        self.state.power = DevicePowerState::Enabled;
    }

    fn disable(&mut self) {
        execute::shell("nmcli radio wifi off");

        self.state.power = DevicePowerState::Disabled;
    }

    fn state(&self) -> DeviceState {
        self.state
    }

    fn set_power(&mut self, state: DevicePowerState) {
        self.state.power = state;
    }

    fn should_block_sleep(&self) -> bool {
        true
    }

    fn detect(&mut self) {
        let cmdout = execute::shell("nmcli radio wifi").output().unwrap().stdout;
        let as_str = String::from_utf8(cmdout).unwrap();

        self.state.present = DevicePresenceState::Present;
        if as_str.contains("enabled") {
            self.state.power = DevicePowerState::Enabled;
        } else {
            self.state.power = match self.state.power {
                DevicePowerState::Disabled => DevicePowerState::Disabled,
                DevicePowerState::Enabled => DevicePowerState::PowerSave,
                DevicePowerState::PowerSave => DevicePowerState::PowerSave,
                DevicePowerState::Unknown => DevicePowerState::PowerSave,
            }
        }

        self.handle_detect(self.state);
    }

    fn name(&self) -> &'static str {
        "wifi"
    }
}

#[derive(Debug, Clone)]
struct Bluetooth {
    state: DeviceState,
    log: Vec<DeviceStateTransition>,
}

impl Bluetooth {
    fn create() -> Box<Self> {
        Box::new(Self {
            state: DeviceState::unknown(),
            log: vec![DeviceStateTransition::first()],
        })
    }
}

impl PoweredDevice for Bluetooth {
    fn events(&self) -> &[DeviceStateTransition] {
        self.log.as_slice()
    }

    fn events_mut(&mut self) -> &mut Vec<DeviceStateTransition> {
        &mut self.log
    }

    fn enable(&mut self) {
        execute::shell("rfkill unblock bluetooth");
        self.state.power = DevicePowerState::Enabled;
    }

    fn disable(&mut self) {
        execute::shell("rfkill block bluetooth");

        self.state.power = DevicePowerState::Disabled;
    }

    fn state(&self) -> DeviceState {
        self.state
    }

    fn set_power(&mut self, state: DevicePowerState) {
        self.state.power = state;
    }

    fn should_block_sleep(&self) -> bool {
        true
    }

    fn detect(&mut self) {
        let cmdout = execute::shell("rfkill list bluetooth")
            .output()
            .unwrap()
            .stdout;
        let as_str = String::from_utf8(cmdout).unwrap();

        self.state.present = DevicePresenceState::Present;
        if as_str.contains("yes") {
            self.state.power = DevicePowerState::Enabled;
        } else {
            self.state.power = match self.state.power {
                DevicePowerState::Disabled => DevicePowerState::Disabled,
                DevicePowerState::Enabled => DevicePowerState::PowerSave,
                DevicePowerState::PowerSave => DevicePowerState::PowerSave,
                DevicePowerState::Unknown => DevicePowerState::PowerSave,
            }
        }

        self.handle_detect(self.state);
    }

    fn name(&self) -> &'static str {
        "bluetooth"
    }
}

trait PoweredDevice {
    fn name(&self) -> &'static str;

    /// Poll device state and update internal
    /// state to match observed state
    fn detect(&mut self);

    fn handle_detect(&mut self, new_state: DeviceState) {
        let old_state = *self.events().last().unwrap();

        if new_state != old_state.new {
            self.events_mut()
                .push(DeviceStateTransition::new(old_state.new, new_state));
        }
    }

    fn suspend(&mut self) {
        let state_before = self.state().power;

        println!("Disabling device by name {}", self.name());
        self.disable();

        let power = match state_before {
            DevicePowerState::Enabled => DevicePowerState::PowerSave,
            DevicePowerState::PowerSave => DevicePowerState::PowerSave,
            DevicePowerState::Disabled => DevicePowerState::Disabled,
            DevicePowerState::Unknown => DevicePowerState::Unknown,
        };

        self.set_power(power);

        self.handle_detect(self.state());
    }

    fn resume(&mut self) {
        match self.state().power {
            DevicePowerState::PowerSave => {
                println!("Resume calls enable for {}", self.name());
                self.enable();
            }
            _ => (),
        }

        self.handle_detect(self.state());
    }

    fn enable(&mut self);
    fn disable(&mut self);

    fn state(&self) -> DeviceState;
    fn set_power(&mut self, state: DevicePowerState);

    /// If this device should be disabled or power saved
    /// before sleep, this returns true
    fn should_block_sleep(&self) -> bool;

    fn events_mut(&mut self) -> &mut Vec<DeviceStateTransition>;

    fn events(&self) -> &[DeviceStateTransition];

    fn report(&mut self) -> Option<DeviceStatistic> {
        self.detect();

        let mut events = self.events().iter();

        let mut prior = events.next().unwrap();

        let mut ds = DeviceStatistic::default();

        for evt in events {
            println!("Dev {}, Looking at transition: {evt:?}", self.name());

            let old = prior;
            let new = evt;

            let span_state = new.old;

            let dur = new.time - old.time;

            match span_state.power {
                DevicePowerState::PowerSave => ds.time_sleeping += dur,
                DevicePowerState::Enabled => ds.time_active += dur,
                DevicePowerState::Disabled => ds.time_disabled += dur,
                _ => {}
            }
        }

        Some(ds)
    }
}

struct Event {
    time: Instant,

    reason: EventReason,
}

impl Event {
    pub fn new(reason: EventReason) -> Event {
        Event {
            time: Instant::now(),
            reason,
        }
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

    PowerConnect,
    PowerDisconnect,

    Check,

    Exit,
}

#[allow(dead_code)]
struct Context {
    log: Vec<Event>,

    statistics: Vec<BatteryStatistic>,
}

impl Context {
    #[allow(dead_code)]
    pub fn default() -> Context {
        Context {
            log: vec![Event::new(EventReason::LidOpen)],
            statistics: Vec::new(),
        }
    }

    #[allow(dead_code)]
    pub fn is_sleeping(&self) -> bool {
        match self
            .log
            .iter()
            .rev()
            .filter(|p| match p.reason {
                EventReason::LidOpen | EventReason::LidClose => true,
                _ => false,
            })
            .next()
        {
            Some(e) => match e.reason {
                EventReason::LidOpen => false,
                EventReason::LidClose => true,
                _ => unreachable!(),
            },
            None => false,
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

#[allow(dead_code)]
fn change_vt(target: &str) {
    std::process::Command::new("chvt")
        .arg(&target[3..])
        .output()
        .unwrap();
}

fn testing() {
    let s = std::thread::spawn(|| as_server());

    as_client(EventReason::LidClose);

    std::thread::sleep(Duration::from_secs(10));

    as_client(EventReason::LidOpen);

    as_client(EventReason::Exit);

    s.join().unwrap();
    //suspend_flow();

    //std::thread::sleep(Duration::from_secs(3));

    //resume_flow();
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

struct Monitors {}

impl Monitors {
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
    pipe().write(&[msg.into()]).unwrap();
}

fn as_server() {
    //let b = sock();
    /*let b = sock();
    let rcv = Receiver::connect("/tmp/idlefd2").unwrap();*/

    let mut pipe = pipe();

    let mut system = System::new();

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
                        system.print_report();
                    }
                    other => system.handle_acpi(other),
                }
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
            Ok(DPMSState::On) => {
                println!("Monitor not yet asleep...");
                continue; // we have confirmation that the monitor is *on*
            }
            Ok(_) => {
                println!("Monitor suspended nicely");
                break; // monitor is sleeping some way
            }
            Err(_) => {
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
        //"v4l2loopback",
        "dell_laptop",
        "dell_wmi",
    ]
}

fn to_suspend_kws() -> Vec<&'static str> {
    vec![
        "evolution",
        "fwupd",
        "akonadi",
        "sidewinderd",
        /*
        "boltd",
        "pci_pme_list_scan",
        "/usr/lib/upowerd",
        "intel_display_power",
        "polkit",
        "i915",
        "NetworkManager",
        "i915_hpd_poll_init_work",
        "output_poll_execute",*/
        //"systemd-core",
        //"systemd-logind",
        //
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
        "turbostat",
        "sleep",
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
    match _res {
        Ok(_) => {}
        Err(v) => {
            println!("Failed to send {signal} to process {pid}: {}", v);
        }
    }
}
