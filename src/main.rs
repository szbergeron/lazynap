#![feature(iter_intersperse)]

use battery::*;
use image::imageops;
use procfs::process::{Stat, Status};
use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::Command;
use std::str::FromStr;
//use image::load_from_memory_with_format

use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use drm::control::Device;
use ipipe::Pipe;
use nix::sys::signal::Signal;
use nix::unistd::Pid;

use async_trait::async_trait;
//use rayon::prelude::*;
//use serde::{Deserialize, Serialize};
//use unix_ipc::{Bootstrapper, Receiver, Sender};
//use drm

#[tokio::main]
async fn main() {
    let args: Vec<_> = env::args().collect();

    for a in args {
        match a.as_str() {
            "lid_close" => as_client(EventReason::LidClose),
            "lid_open" => as_client(EventReason::LidOpen),
            "power_connect" => as_client(EventReason::PowerConnect),
            "power_disconnect" => as_client(EventReason::PowerDisconnect),
            "power_button" => as_client(EventReason::PowerButton),
            "server" => as_server().await,
            "dpms_check" => {
                println!("DPMS status: {:?}", Monitors::get_dpms_status());
            }
            "check" => as_client(EventReason::Check),

            "suspend" => as_client(EventReason::Suspend),
            "resume" => as_client(EventReason::Resume),
            "test" => testing().await,
            //"test" => testing(),
            _ => {}
        }
    }
}

mod parallel {
    enum Progress {
        NotStarted(),
        Starting(),
        Done(),
    }

    enum 

    pub fn announce()
}

/*mod parallel {
    struct Command {
        primary: String,
    }

    pub fn create<T>(channel_name: &'static str) {
    }

    pub fn send<T>
}*/

fn format_duration(d: std::time::Duration) -> String {
    //let dur = chrono::Duration::from_std(d).unwrap_or(chrono::Duration::min_value());

    //let hours = ()

    //todo!()
    use hhmmss::Hhmmss;

    d.hhmmssxxx()
}

fn schedule_power_check() {
    std::thread::spawn(|| {
        std::thread::sleep(Duration::from_secs(600));
        as_client(EventReason::DebugLowPowerStates);
    });
}

/// i KNOW this is dumb, and probably unsafe,
/// and probably a very bad idea. This is just because battery
/// manager doesn't properly allow send itself for some godforsaken reason.
unsafe impl Send for System {
}

struct System {
    context: Context,
    //devices: Vec<Box<dyn PoweredDevice>>,
    display: Display,
    display_late: DisplayLate,
    wifi: Wifi,
    bluetooth: Bluetooth,
    platform: Platform,

    battery_manager: Arc<battery::Manager>,

    info: HashMap<String, Data>,

    flags: SystemFlags,
}

#[derive(Debug, Clone)]
struct SystemFlags {
    power_connected: bool,
    lid_closed: bool,
    sleeping: bool,
    //deep_sleeping: bool,
    power_button_spinner: bool,

    time_sleeping: Duration,
    time_active: Duration,
    last_sleep_event: Instant,
}

impl Default for SystemFlags {
    fn default() -> Self {
        Self {
            power_connected: Default::default(),
            lid_closed: Default::default(),
            sleeping: Default::default(),
            power_button_spinner: Default::default(),
            time_sleeping: Default::default(),
            time_active: Default::default(),
            last_sleep_event: Instant::now(),
        }
    }
}

enum Data {
    Bool(bool),
    Integer(i64),
    String(String),
    Map(HashMap<String, Data>),
}

impl System {
    fn on_startup(&mut self) {
        //return;
        // check if we need to recover from a failed suspend/resume cycle
        // we only do this once, and delete the file, so that
        // we don't trap ourselves in a loop

        modprobe_on_list(modprobe_list(), true); // so we at least have keyboard and are relatively recoverable

        let suspended_procs =
            std::fs::read_to_string("/tmp/suspended_procs").unwrap_or(String::default());
        execute::shell("rm /tmp/suspended_procs").output().unwrap();

        let mut pids: Vec<i32> = suspended_procs
            .split(",")
            .map(|substr| substr.parse().unwrap_or(-1))
            .collect();

        pids.sort();

        // we want to iterate from highest PIDs to lowest so we don't have the "parent sees a dead
        // child and panics" situation

        for pid in pids.iter().rev() {
            let _ = nix::sys::signal::kill(Pid::from_raw(*pid), Signal::SIGCONT);
        }

        std::thread::spawn(|| {
            // if we're in a backpack let's try not to melt the user
            std::thread::sleep(Duration::from_secs(10));

            let state = std::fs::read_to_string("/proc/acpi/button/lid/LID0/state").unwrap();
            if state.contains("closed") {
                as_client(EventReason::LidClose);
            }
        });
    }

    fn devices(&mut self) -> Vec<&mut dyn PoweredDevice> {
        vec![
            &mut self.wifi,
            &mut self.bluetooth,
            &mut self.display,
            &mut self.platform,
            &mut self.display_late,
        ]
    }

    fn new() -> Self {
        System {
            context: Context::default(),
            //devices: vec![Wifi::create(), Bluetooth::create(), Platform::create()],
            display: *Display::create(),
            display_late: *DisplayLate::create(),
            wifi: *Wifi::create(),
            bluetooth: *Bluetooth::create(),
            platform: *Platform::create(),
            //devices: vec![Platform::create()],
            //devices: vec![Display::create()],
            battery_manager: Arc::new(battery::Manager::new().unwrap()),
            info: HashMap::new(),
            flags: Default::default(),
        }
    }

    async fn power_button(&mut self) {
        self.flags.power_button_spinner = !self.flags.power_button_spinner;

        if self.flags.power_button_spinner {
            self.flags.sleeping = !self.flags.sleeping;

            if self.flags.sleeping {
                self.do_suspend().await;
            } else {
                self.do_resume().await;
            }
        }
    }

    async fn lid_open(&mut self) {
        self.flags.lid_closed = false;

        if self.flags.sleeping {
            //self.flags.sleeping = false;
            self.resume().await
        }
    }

    async fn lid_close(&mut self) {
        self.flags.lid_closed = true;

        if !self.flags.power_connected {
            if !self.flags.sleeping {
                //self.flags.sleeping = true;
                self.suspend().await;
            }
        } else {
            println!("Inhibiting sleep since power is connected")
        }
    }

    async fn power_connect(&mut self) {
        self.flags.power_connected = true;
    }

    async fn power_disconnect(&mut self) {
        self.flags.power_connected = false;

        // really we should only do this if we're "charged"
        if true {
            self.flags.time_active = Duration::ZERO;
            self.flags.time_sleeping = Duration::ZERO;
        }

        // If we're disconnecting power and the lid is shut,
        // we want system to go into suspend
        if !self.flags.sleeping && self.flags.lid_closed {
            self.flags.sleeping = true;
            self.suspend().await;
        }
    }

    async fn suspend(&mut self) {
        self.flags.sleeping = true;
        self.do_suspend().await;
    }

    async fn resume(&mut self) {
        self.flags.sleeping = false;
        self.do_resume().await;
    }

    async fn handle_acpi(&mut self, event: EventReason) {
        use EventReason::*;

        match event {
            PowerButton => self.power_button().await,
            LidOpen => self.lid_open().await,
            Suspend => self.do_suspend().await,
            Resume => self.do_resume().await,
            LidClose => self.lid_close().await,
            PowerConnect => self.power_connect().await,
            PowerDisconnect => self.power_disconnect().await,
            DebugLowPowerStates => {
                if self.flags.sleeping {
                    self.platform.debug_low_power().await;
                }
            }
            /*Suspend => self.do_suspend(),
            Resume => self.do_resume(),*/
            _ => (),
        }
    }

    async fn do_suspend(&mut self) {
        self.flags.sleeping = true;

        let last_event = self.flags.last_sleep_event;
        let now = Instant::now();

        let awake_for = now - last_event;

        self.flags.time_active += awake_for;
        self.flags.last_sleep_event = now;

        let start = Instant::now();

        for d in self.devices().iter_mut() {
            d.detect();

            let should_block = d.should_block_sleep().await;

            if should_block {
                d.suspend().await;
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

        schedule_power_check()
    }

    async fn do_resume(&mut self) {
        self.flags.sleeping = false;

        let last_event = self.flags.last_sleep_event;
        let now = Instant::now();

        let sleeping_for = now - last_event;

        self.flags.last_sleep_event = now;
        self.flags.time_sleeping += sleeping_for;
        // unpowermanage devices in reverse suspend order, starting with platform
        for d in self.devices().iter_mut().rev() {
            d.resume().await; // noop if wasn't suspended or if device couldn't block sleep
        }

        println!(
            "Device was sleeping for {} seconds",
            sleeping_for.as_secs_f64()
        );

        println!(
            "So far device has spent {} seconds 'resumed' and {} seconds 'suspended'",
            format_duration(self.flags.time_active),
            format_duration(self.flags.time_sleeping)
        );
    }

    fn print_report(&mut self) {
        println!(
            "Current power status is: {:?}",
            BatteryStatistic::collect(self.battery_manager.batteries().unwrap())
        );
        for dev in self.devices().iter_mut() {
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
struct DisplayLate {
    log: Vec<DeviceStateTransition>,
}

impl DisplayLate {
    fn create() -> Box<Self> {
        Box::new(Self {
            log: vec![DeviceStateTransition::first()],
        })
    }
}

#[async_trait]
impl PoweredDevice for DisplayLate {
    fn name(&self) -> &'static str {
        "display_late"
    }

    fn detect(&mut self) {
        ()
    }

    async fn enable(&mut self) {
        Monitors::hold_resume_display();
        let _ = Monitors::set_dpms(DPMSState::On);
    }

    async fn disable(&mut self) {
        let _ = Monitors::set_dpms(DPMSState::Suspend);
    }

    fn state(&self) -> DeviceState {
        DeviceState::unknown()
    }

    async fn set_power(&mut self, state: DevicePowerState) {
        ()
    }

    async fn should_block_sleep(&self) -> bool {
        true
    }

    fn events_mut(&mut self) -> &mut Vec<DeviceStateTransition> {
        &mut self.log
    }

    fn events(&self) -> &[DeviceStateTransition] {
        &self.log
    }
}

#[derive(Debug, Clone)]
struct Display {
    state: DeviceState,
    log: Vec<DeviceStateTransition>,

    active_tty: String,
}

impl Display {
    fn create() -> Box<Self> {
        Box::new(Self {
            state: DeviceState::present_on(),
            log: vec![DeviceStateTransition::first()],
            active_tty: Self::active_tty(),
        })
    }

    fn active_tty() -> String {
        /*let num = String::from_utf8(execute::shell("tty").output().unwrap().stdout).unwrap();
        let num = num.split("/").collect::<Vec<&str>>().into_iter().rev().next().unwrap();

        let ret = format!("tty{num}");*/

        let output = execute::shell("cat /sys/devices/virtual/tty/tty0/active").output();

        String::from_utf8(output.map(|o| o.stdout).unwrap_or(vec![])).unwrap_or("tty2".into())
    }

    fn unblank(&mut self) {
        println!("unblanking to: {}", self.active_tty);


        //let _ = Monitors::set_dpms(DPMSState::On);

        //std::thread::sleep_ms(500);
        //std::thread::sleep_ms(30);

        println!("switching back to original tty");
        change_vt(&self.active_tty);
        println!("done switch");
    }

    fn blank(&mut self) {
        println!("switching to new vt");
        //let _ = execute::shell("openvt --switch bash").output();
        //execute::shell("openvt --switch \"echo 0 > /sys/class/graphics/fbcon/cursor_blink && bash\"");
        let _ = execute::shell("echo 0 > /sys/class/graphics/fbcon/cursor_blink").output();
        let _ = execute::shell("openvt --switch bash").output();
        println!("blanking");

        //let _ = Monitors::hold_resume_display();

        //let _ = Monitors::set_dpms(DPMSState::Suspend);
        //let _ = execute::shell("setterm --blank 0 --powerdown 0").output();
    }
}

#[async_trait]
impl PoweredDevice for Display {
    fn events(&self) -> &[DeviceStateTransition] {
        self.log.as_slice()
    }

    fn events_mut(&mut self) -> &mut Vec<DeviceStateTransition> {
        &mut self.log
    }

    async fn enable(&mut self) {
        // don't do anything here :)
        self.unblank();

        self.state.power = DevicePowerState::Enabled;
    }

    async fn disable(&mut self) {
        self.active_tty = Self::active_tty();

        //lock_blank_screen();

        self.blank();

        std::thread::sleep(Duration::from_secs(2));

        self.state.power = DevicePowerState::Disabled;
    }

    fn state(&self) -> DeviceState {
        self.state
    }

    async fn set_power(&mut self, state: DevicePowerState) {
        self.state.power = state;
    }

    async fn should_block_sleep(&self) -> bool {
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
        let cpus: Vec<(usize, bool)> = self
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

        self.enable_count(3);
    }

    fn powersave(&mut self) {
        self.enable_count(12); // just leave it, it's fine
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
        let mut r: Vec<FreezableProcess> = procfs::process::all_processes()
            .unwrap()
            .into_iter()
            .map(|proc| FreezableProcess::new(proc))
            .collect();

        r.sort_by_key(|p| p.pid()); // first sort by pid to disambiguate parent-child within same jiffy

        r.sort_by_key(|p| p.backing_process.stat().unwrap().starttime); // sort by start time, since pids could wrap

        r
    }

    async fn debug_low_power(&mut self) {
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
        schedule_power_check();
    }

    fn async_resume_suspend_cycle(&self, seconds: u64) {
        std::thread::spawn(move || {
            as_client(EventReason::Resume);
            std::thread::sleep(Duration::from_secs(seconds));
            let _ = execute::shell("notify-send 'force gdm to wake for a moment'").output();
            std::thread::sleep(Duration::from_secs(1));
            as_client(EventReason::Suspend);
        });
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

    /// Allows going into an even deeper sleep,
    /// where we suspend things like journald
    /// and upowerd even though other
    /// parts of this script rely on them
    fn powernap_for(&mut self, time: Duration) {
        let to_freeze = self.gather_procs();

        for proc in to_freeze {}
    }

    fn suspend_userspace(&mut self) {
        self.frozen_processes = self.gather_procs();

        //self.frozen_processes.sort_by_key(|p| p.pid());
        self.cpus.superpowersave();

        //let r = self.frozen_processes.iter().map(|p| p.pid().to_string()).intersperse(",".to_owned());

        //let c: String = r.collect();

        //let _ = std::fs::write("/tmp/suspended_procs", c); // don't want this to completely
        // break flow if it fails

        for proc in self.frozen_processes.iter_mut() {
            proc.suspend();
        }

        self.cstate_stats = self.get_cstate_stats();
    }

    fn resume_userspace(&mut self) {
        println!("Unfreezing {} processes", self.frozen_processes.len());

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

        self.cpus.powersave();

        self.print_proc_stats(pstats);

        println!("Unfreeze took {} seconds", (b - a).as_secs_f64());

        self.print_cstate_stats(self.cstate_stats.clone(), new_cstate_stats);

        let _ = execute::shell("rm /tmp/suspended_procs").output(); // best effort

        //self.set_enabled_core_count(100);
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

    fn load_us_modules(&mut self) {
        modprobe_on_list(modprobe_list(), true);
    }

    fn unload_us_modules(&mut self) {
        modprobe_on_list(
            modprobe_list()
                .iter()
                .rev()
                .map(|e| *e)
                .collect::<Vec<&str>>()
                .as_slice(),
            false,
        );
    }

    /// a minimum of 1 core is enabled regardless of requested count
    fn set_enabled_core_count(&mut self, count: usize) {
        println!("We have {} cpus available", num_cpus::get());
        let bounded = count.max(1usize);

        let bounded = bounded.min(num_cpus::get());

        for idx in 0..bounded {}
    }
}

#[async_trait]
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

    async fn enable(&mut self) {
        panic!("Not applicable to platform")
    }

    async fn disable(&mut self) {
        panic!("Not applicable to platform")
    }

    async fn resume(&mut self) {
        // we can unconditionally resume since
        // sending sigcont and doing modprobes is idempotent
        match self.state().power {
            DevicePowerState::PowerSave | DevicePowerState::Disabled => {
                self.resume_userspace();

                self.load_us_modules();

                self.set_power(DevicePowerState::Enabled).await;
            }
            _ => (),
        }
    }

    async fn suspend(&mut self) {
        match self.state().power {
            DevicePowerState::Enabled => {
                self.unload_us_modules();

                self.suspend_userspace();

                self.set_power(DevicePowerState::PowerSave).await;
            }
            _ => (),
        }
    }

    fn state(&self) -> DeviceState {
        self.state
    }

    async fn set_power(&mut self, state: DevicePowerState) {
        self.state.power = state;
    }

    async fn should_block_sleep(&self) -> bool {
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

#[async_trait]
impl PoweredDevice for Wifi {
    fn events(&self) -> &[DeviceStateTransition] {
        self.log.as_slice()
    }

    fn events_mut(&mut self) -> &mut Vec<DeviceStateTransition> {
        &mut self.log
    }

    async fn enable(&mut self) {
        let _ = execute::shell("nmcli radio wifi on").output();

        self.state.power = DevicePowerState::Enabled;
    }

    async fn disable(&mut self) {
        let _ = execute::shell("nmcli radio wifi off").output();

        self.state.power = DevicePowerState::Disabled;
    }

    fn state(&self) -> DeviceState {
        self.state
    }

    async fn set_power(&mut self, state: DevicePowerState) {
        self.state.power = state;
    }

    async fn should_block_sleep(&self) -> bool {
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

    fn status() -> String {
        if let Ok(o) = execute::shell("rfkill list bluetooth").output() {
            if let Ok(s) = String::from_utf8(o.stdout) {
                return s;
            }
        }

        String::from("couldn't get bt status")
    }
}

#[async_trait]
impl PoweredDevice for Bluetooth {
    fn events(&self) -> &[DeviceStateTransition] {
        self.log.as_slice()
    }

    fn events_mut(&mut self) -> &mut Vec<DeviceStateTransition> {
        &mut self.log
    }

    async fn enable(&mut self) {
        println!("Enabling bluetooth bluetooth");
        let _ = execute::shell("rfkill unblock bluetooth").output();
        std::thread::sleep(Duration::from_millis(200)); // otherwise doesn't have long enough
        println!("Status: {}", Self::status());
        self.state.power = DevicePowerState::Enabled;
    }

    async fn disable(&mut self) {
        println!("Disabling bluetooth");
        let _ = execute::shell("rfkill block bluetooth").output();
        std::thread::sleep(Duration::from_millis(200)); // otherwise doesn't have long enough
        println!("Status: {}", Self::status());

        self.state.power = DevicePowerState::Disabled;
    }

    fn state(&self) -> DeviceState {
        self.state
    }

    async fn set_power(&mut self, state: DevicePowerState) {
        self.state.power = state;
    }

    async fn should_block_sleep(&self) -> bool {
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
#[async_trait]
trait PoweredDevice: Send + Sync {
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

    async fn suspend(&mut self) {
        let state_before = self.state().power;

        println!("Disabling device by name {}", self.name());
        self.disable().await;

        let power = match state_before {
            DevicePowerState::Enabled => DevicePowerState::PowerSave,
            DevicePowerState::PowerSave => DevicePowerState::PowerSave,
            DevicePowerState::Disabled => DevicePowerState::Disabled,
            DevicePowerState::Unknown => DevicePowerState::Unknown,
        };

        self.set_power(power).await;

        self.handle_detect(self.state());
    }

    async fn resume(&mut self) {
        match self.state().power {
            DevicePowerState::PowerSave => {
                println!("Resume calls enable for {}", self.name());
                self.enable().await;
            }
            _ => (),
        }

        self.handle_detect(self.state());
    }

    async fn enable(&mut self);
    async fn disable(&mut self);

    fn state(&self) -> DeviceState;
    async fn set_power(&mut self, state: DevicePowerState);

    /// If this device should be disabled or power saved
    /// before sleep, this returns true
    async fn should_block_sleep(&self) -> bool;

    fn events_mut(&mut self) -> &mut Vec<DeviceStateTransition>;

    fn events(&self) -> &[DeviceStateTransition];

    fn report(&mut self) -> Option<DeviceStatistic> {
        self.detect();

        let events: Vec<DeviceStateTransition> = self.events().iter().cloned().collect();

        let prior = events.first().cloned().unwrap();

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

    Suspend,
    Resume,

    PowerConnect,
    PowerDisconnect,

    DebugLowPowerStates,

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

async fn testing() {
    //let s = std::thread::spawn(|| as_server().await);
    //let s = tokio::spawn(async { as_server().await });

    let s = std::thread::spawn(|| {
        let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
        rt.spawn(as_server());
    });

    as_client(EventReason::LidClose);

    std::thread::sleep(Duration::from_secs(60));

    as_client(EventReason::LidOpen);

    as_client(EventReason::Exit);

    //s.await.unwrap();

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

struct Monitors {
    //dpms_handle: Option<drm::control::property::Info>,
    dpms_handle: Option<drm::control::property::Handle>,
    conn_handle: Option<drm::control::connector::Handle>,
    card: Card,
}

impl Monitors {
    async fn new() -> Self {
        let card = Card::open_global();

        let mut m = Monitors {
            card,
            dpms_handle: None,
            conn_handle: None,
        };

        let _ = m.refresh_dpms_info().await;

        m
    }

    async fn refresh_dpms_info(&mut self) -> std::result::Result<(), Box<dyn std::error::Error>> {
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

    fn set_resume_display(freed: &AtomicBool) -> std::result::Result<(), Box<dyn std::error::Error>> {
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
        let crtc = crtcinfo.get(0) //.expect("No crtcs found");
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
                //tokio::time::sleep(Duration::from_millis(100)).await;
                break;
            } else {
                //tokio::time::sleep(Duration::from_millis(1000)).await;
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

                    let _ = card.set_property(*conn_handle, id, num);
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

async fn as_server() {
    //let b = sock();
    /*let b = sock();
    let rcv = Receiver::connect("/tmp/idlefd2").unwrap();*/

    let mut pipe = pipe();

    let mut system = System::new();

    system.on_startup();

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
                    other => system.handle_acpi(other).await,
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

fn lock_blank_screen_2() {}

async fn lock_blank_screen() {
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

fn modprobe_list() -> &'static [&'static str] {
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

mod monitoring {
    use std::time::Duration;

    /// If monitoring should be throttled/lowered,
    /// this will be sent as an event over the info channel
    pub enum Throttling {
        StartThrottle,
        EndThrottle,
    }

    pub enum MonitoringSignal {
        Throttle(Throttling),
    }

    fn monitor(channel: std::sync::mpsc::Receiver<MonitoringSignal>) {
        let poll_rate = Duration::from_secs(3);
        let manager = battery::Manager::new();

        let batt = manager
            .unwrap()
            .batteries()
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
    }
}
