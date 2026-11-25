//! The `auto_route` switch: the default route the TUN device captures, the
//! prefixes the config names, and the prefixes it keeps off the tunnel, all
//! installed through the platform's routing table and removed when the inbound
//! stops.

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use std::sync::{Mutex, OnceLock, RwLock, RwLockReadGuard, RwLockWriteGuard, Weak};

#[cfg(any(target_os = "linux", target_os = "macos"))]
use route_manager::RouteKind;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use route_manager::{Route, RouteManager};

/// The captures in force, one per open TUN inbound, shared with the dial path so an address resolved after the routes landed is pinned before it is dialled. Two inbounds each hold their own table entry, so one closing does not unpin the other's edges.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn capture() -> &'static Mutex<Vec<Weak<Guard>>> {
    static CAPTURE: OnceLock<Mutex<Vec<Weak<Guard>>>> = OnceLock::new();
    CAPTURE.get_or_init(|| Mutex::new(Vec::new()))
}

/// The route each live underlay pin currently installs, shared so the last owner deletes the
/// replacement rather than the record it read. An entry leaves when its final guard closes.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
static CAPTURE_GENERATION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Changes whenever a capture installs or drops, so a learned endpoint pin is not trusted across captures.
pub(crate) fn capture_generation() -> u64 {
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    {
        CAPTURE_GENERATION.load(std::sync::atomic::Ordering::Relaxed)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        0
    }
}

/// Restore every live capture's routes for a process that is exiting. A signal
/// or `TerminateProcess` skips `Drop`, so the CLI's stop file and the signal
/// handler both call this before `exit`.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub(crate) fn release_all() {
    let _operation = route_operation();
    let guards: Vec<Arc<Guard>> = capture()
        .lock()
        .map(|mut slot| {
            slot.retain(|weak| weak.strong_count() > 0);
            slot.iter().filter_map(Weak::upgrade).collect()
        })
        .unwrap_or_default();
    for guard in guards {
        guard.release_now();
    }
    if let Ok(mut manager) = RouteManager::new() {
        retry_pending(&mut manager);
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub(crate) fn release_all() {}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn installed_pins() -> &'static Mutex<HashMap<(IpAddr, u8), Route>> {
    static PINS: OnceLock<Mutex<HashMap<(IpAddr, u8), Route>>> = OnceLock::new();
    PINS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Routes whose delete failed transiently (a full descriptor table cannot open the netlink socket), kept for the next guard to retry.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn pending_deletes() -> &'static Mutex<Vec<Route>> {
    static PENDING: OnceLock<Mutex<Vec<Route>>> = OnceLock::new();
    PENDING.get_or_init(|| Mutex::new(Vec::new()))
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[allow(clippy::type_complexity)]
fn pending_pinned() -> &'static Mutex<Vec<((IpAddr, u8), Route)>> {
    static PENDING: OnceLock<Mutex<Vec<((IpAddr, u8), Route)>>> = OnceLock::new();
    PENDING.get_or_init(|| Mutex::new(Vec::new()))
}

/// Serializes route installs against direct dials: a dial holds the read side from its underlay check through its connect, and an install takes the write side, so a capture cannot land underneath a decision already made.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn route_lock() -> &'static RwLock<()> {
    static ROUTES: OnceLock<RwLock<()>> = OnceLock::new();
    ROUTES.get_or_init(|| RwLock::new(()))
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub(crate) fn route_read() -> RwLockReadGuard<'static, ()> {
    route_lock()
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn route_write() -> RwLockWriteGuard<'static, ()> {
    route_lock()
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Serializes an install against a guard's release, so a route one guard is retiring cannot be adopted by a successor before the old owner's delete decision.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn route_operation_lock() -> &'static Mutex<()> {
    static OPERATION: OnceLock<Mutex<()>> = OnceLock::new();
    OPERATION.get_or_init(|| Mutex::new(()))
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn route_operation() -> std::sync::MutexGuard<'static, ()> {
    route_operation_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// A route lookup reads an IPv4-mapped destination as the IPv4 address the kernel routes.
pub(crate) fn route_address(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map_or(IpAddr::V6(address), IpAddr::V4),
        IpAddr::V4(address) => IpAddr::V4(address),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
thread_local! {
    static DIAL_UNDERLAY: std::cell::RefCell<Option<(IpAddr, String, Option<u32>)>> =
        const { std::cell::RefCell::new(None) };
}

// A local DNS dial resolves its server name inside the socket path, so the underlay is staged once the destination address is known.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
thread_local! {
    static FORCE_UNDERLAY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub(crate) fn force_underlay() {
    FORCE_UNDERLAY.with(|flag| flag.set(true));
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub(crate) fn force_underlay() {}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub(crate) fn take_underlay_force() -> bool {
    FORCE_UNDERLAY.with(std::cell::Cell::take)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub(crate) fn take_underlay_force() -> bool {
    false
}

/// The effective route into a capture and the physical route an underlay bind should use.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
struct DialRoute {
    captured: bool,
    underlay: Option<(String, Option<u32>)>,
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
impl DialRoute {
    fn uncaptured() -> Self {
        Self {
            captured: false,
            underlay: None,
        }
    }
}

/// Classify one destination against every live capture in a single route-table read per guard:
/// the effective route decides whether it enters a device, and the filtered route picks the
/// physical underlay a socket binds to.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn dial_route(address: IpAddr) -> io::Result<DialRoute> {
    let address = route_address(address);
    let guards: Vec<Arc<Guard>> = {
        let mut slot = capture()
            .lock()
            .map_err(|_| io::Error::other("the capture registry is poisoned"))?;
        slot.retain(|weak| weak.strong_count() > 0);
        slot.iter().filter_map(Weak::upgrade).collect()
    };
    let mut captured = false;
    let mut underlay = None;
    let mut failure = None;
    for guard in guards {
        match guard.route_to(address) {
            Ok(route) if route.captured => {
                captured = true;
                if route.underlay.is_some() {
                    underlay = route.underlay;
                    break;
                }
            }
            Ok(_) => {}
            Err(error) => {
                failure.get_or_insert(error);
            }
        }
    }
    if captured && (underlay.is_some() || failure.is_none()) {
        return Ok(DialRoute { captured, underlay });
    }
    if let Some(error) = failure {
        return Err(error);
    }
    Ok(DialRoute::uncaptured())
}

/// Bind the next dial to the underlay that currently carries `address`, so a direct destination
/// does not need a host route that would exempt unrelated traffic from the capture.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub(crate) fn bind_dial(address: IpAddr) {
    let _ = stage_dial(address);
}

/// The classification behind `bind_dial`, so a caller that needs the answer does not scan the
/// table again.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub(crate) fn stage_dial(address: IpAddr) -> io::Result<bool> {
    let address = route_address(address);
    DIAL_UNDERLAY.with(|slot| *slot.borrow_mut() = None);
    let route = dial_route(address)?;
    if route.captured {
        if let Some((interface, index)) = route.underlay {
            DIAL_UNDERLAY.with(|slot| *slot.borrow_mut() = Some((address, interface, index)));
        }
    }
    Ok(route.captured)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub(crate) fn bind_dial(_address: IpAddr) {}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub(crate) fn stage_dial(_address: IpAddr) -> io::Result<bool> {
    Ok(false)
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub(crate) fn dial_underlay() -> Option<(IpAddr, String, Option<u32>)> {
    DIAL_UNDERLAY.with(std::cell::RefCell::take)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub(crate) fn dial_underlay() -> Option<(IpAddr, String, Option<u32>)> {
    None
}

pub(crate) enum PinOutcome {
    Uncaptured,
    Pinned,
    Refused,
}

pub(crate) fn pin_dialled(address: IpAddr) -> bool {
    matches!(pin_dialled_outcome(address), PinOutcome::Pinned)
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub(crate) fn pin_dialled_outcome(address: IpAddr) -> PinOutcome {
    let address = route_address(address);
    if address.is_unspecified() || address.is_loopback() {
        return PinOutcome::Uncaptured;
    }
    let Ok(guards) = capture().lock().map(|mut slot| {
        slot.retain(|weak| weak.strong_count() > 0);
        slot.iter().filter_map(Weak::upgrade).collect::<Vec<_>>()
    }) else {
        return PinOutcome::Refused;
    };
    let mut covered = false;
    let mut pinned = true;
    for guard in guards {
        if let Some(success) = guard.pin(address) {
            covered = true;
            pinned &= success;
        }
    }
    if !covered {
        PinOutcome::Uncaptured
    } else if pinned {
        PinOutcome::Pinned
    } else {
        PinOutcome::Refused
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub(crate) fn pin_dialled_outcome(_address: IpAddr) -> PinOutcome {
    PinOutcome::Uncaptured
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub(crate) fn unpin_dialled(address: IpAddr) -> bool {
    let address = route_address(address);
    let Ok(guards) = capture()
        .lock()
        .map(|slot| slot.iter().filter_map(Weak::upgrade).collect::<Vec<_>>())
    else {
        return false;
    };
    let mut removed = false;
    for guard in guards {
        removed |= guard.unpin(address);
    }
    removed
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub(crate) fn unpin_dialled(_address: IpAddr) -> bool {
    false
}

/// Whether a live capture already sends this address into a TUN device.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub(crate) fn captured(address: IpAddr) -> io::Result<bool> {
    Ok(dial_route(address)?.captured)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub(crate) fn captured(_address: IpAddr) -> io::Result<bool> {
    Ok(false)
}

/// What one open device captures: the half-default of each family it carries,
/// the prefixes the config names, and the prefixes it must not capture.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Plan {
    routes: Vec<(IpAddr, u8)>,
    keep: Vec<(IpAddr, u8)>,
    pins: Vec<(IpAddr, u8)>,
}

impl Plan {
    /// Build the plan. A family is captured only when the device carries an
    /// address of it, so a v4-only tunnel does not blackhole v6. An excluded
    /// prefix keeps whatever route already carried it, pinned before the
    /// half-defaults land so longest-prefix still sends it where it went.
    pub(crate) fn new(v4: bool, v6: bool, routes: &[(IpAddr, u8)], keep: &[(IpAddr, u8)]) -> Self {
        let mut plan = Self {
            routes: Vec::new(),
            keep: Vec::new(),
            pins: Vec::new(),
        };
        let kept = |address: IpAddr, prefix: u8| {
            keep.iter().any(|(outer, outer_prefix)| {
                same_family(*outer, address) && covers(*outer, *outer_prefix, address, prefix)
            })
        };
        if v4 {
            for half in [
                IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                IpAddr::V4(std::net::Ipv4Addr::new(128, 0, 0, 0)),
            ] {
                if !kept(half, 1) {
                    plan.routes.push((half, 1));
                }
            }
        }
        if v6 {
            for half in [
                IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
                IpAddr::V6(std::net::Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0)),
            ] {
                if !kept(half, 1) {
                    plan.routes.push((half, 1));
                }
            }
        }
        for (address, prefix) in routes {
            let address = network(*address, *prefix);
            if (address.is_ipv4() && !v4) || (address.is_ipv6() && !v6) {
                eprintln!("tun inbound: the device carries no route family for {address}/{prefix}");
                continue;
            }
            if *prefix == 0 || plan.routes.contains(&(address, *prefix)) || kept(address, *prefix) {
                continue;
            }
            plan.routes.push((address, *prefix));
        }
        for (address, prefix) in keep {
            let address = network(*address, *prefix);
            if (address.is_ipv4() && !v4) || (address.is_ipv6() && !v6) {
                eprintln!("tun inbound: the device carries no route family for {address}/{prefix}");
                continue;
            }
            plan.keep.push((address, *prefix));
        }
        plan.keep.retain(|(excluded, prefix)| {
            plan.routes.iter().any(|(captured, captured_prefix)| {
                overlaps(*excluded, *prefix, *captured, *captured_prefix)
            })
        });
        plan
    }

    /// Name the server edges that may move when the host changes networks. They are pinned like a
    /// kept prefix before the capture lands, but a later dial may move them to the current underlay.
    pub(crate) fn with_pins(mut self, pins: &[(IpAddr, u8)]) -> Self {
        let mut kept = Vec::with_capacity(pins.len());
        for (address, prefix) in pins {
            let address = network(*address, *prefix);
            if self.routes.iter().any(|(captured, captured_prefix)| {
                covers(*captured, *captured_prefix, address, *prefix)
            }) {
                kept.push((address, *prefix));
            }
        }
        self.pins = kept;
        self
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.routes.is_empty() && self.pins.is_empty()
    }

    /// The prefixes the plan captures, in install order.
    pub(crate) fn routes(&self) -> &[(IpAddr, u8)] {
        &self.routes
    }

    /// The prefixes the plan leaves where they were.
    pub(crate) fn keep(&self) -> &[(IpAddr, u8)] {
        &self.keep
    }

    /// The server edges the plan pins to whatever underlay carries them now.
    pub(crate) fn pins(&self) -> &[(IpAddr, u8)] {
        &self.pins
    }
}

/// The routes one device holds; dropping the guard puts the table back.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub(crate) struct Guard {
    manager: Mutex<RouteManager>,
    added: Mutex<Vec<Route>>,
    pinned: Mutex<HashMap<(IpAddr, u8), Route>>,
    kept: Mutex<Vec<(IpAddr, u8)>>,
    pinning: Mutex<()>,
    plan: Plan,
    interface: String,
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
impl Guard {
    /// Pin every kept prefix where it already resolves, then capture the plan's
    /// prefixes on `interface`. A prefix whose current route cannot be found rolls
    /// the install back and returns an error, so startup fails; an operator should
    /// check for an underlay route for that address family.
    #[allow(clippy::too_many_lines)]
    pub(crate) fn install(interface: &str, plan: &Plan) -> io::Result<Arc<Self>> {
        let _routes = route_write();
        let _operation = route_operation();
        let mut manager = RouteManager::new()?;
        retry_pending(&mut manager);
        let mut added: Vec<Route> =
            Vec::with_capacity(plan.routes.len() + plan.keep.len() + plan.pins.len());
        let mut pinned = HashMap::with_capacity(plan.pins.len());
        let mut kept = Vec::with_capacity(plan.keep.len());
        let mut captures = capture_interfaces();
        if !captures.iter().any(|capture| capture == interface) {
            captures.push(interface.to_owned());
        }
        for (destination, prefix) in plan.keep() {
            if local_covers(&mut manager, *destination, *prefix) {
                continue;
            }
            let pins = match keep_edges(&mut manager, *destination, *prefix, &captures) {
                Ok(pins) if pins.is_empty() => {
                    retire(&mut manager, &mut added, &mut pinned);
                    return Err(io::Error::new(
                        io::ErrorKind::AddrNotAvailable,
                        format!("no route carries the excluded prefix {destination}/{prefix}"),
                    ));
                }
                Ok(pins) => pins,
                Err(error) => {
                    eprintln!(
                        "tun inbound: could not read the route for {destination}/{prefix}: {error}"
                    );
                    retire(&mut manager, &mut added, &mut pinned);
                    return Err(error);
                }
            };
            for pin in pins {
                let (destination, prefix) = (pin.destination(), pin.prefix());
                match manager.add(&pin) {
                    Ok(()) => {
                        added.push(pin);
                        kept.push((destination, prefix));
                    }
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                        if held_by_another(destination, prefix) {
                            added.push(pin);
                            kept.push((destination, prefix));
                        }
                    }
                    Err(error) => {
                        eprintln!(
                            "tun inbound: could not keep {destination}/{prefix} on its own route: {error}"
                        );
                        retire(&mut manager, &mut added, &mut pinned);
                        return Err(error);
                    }
                }
            }
        }
        for (destination, prefix) in plan.pins() {
            if local_destination(&mut manager, *destination) {
                continue;
            }
            let Some(base) = best_underlay(&mut manager, *destination, &captures, &[]) else {
                eprintln!("tun inbound: no route carries the server edge {destination}/{prefix}");
                continue;
            };
            let pin = edge_route(&base, *destination, *prefix);
            match manager.add(&pin) {
                Ok(()) => {
                    added.push(pin.clone());
                    pinned.insert((*destination, *prefix), pin);
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    let live = manager.list().ok().and_then(|routes| {
                        routes.into_iter().find(|held| {
                            is_main_table(held)
                                && held.destination() == *destination
                                && held.prefix() == *prefix
                        })
                    });
                    if let Some(route) = live.filter(another_guard_holds) {
                        added.push(route.clone());
                        pinned.insert((*destination, *prefix), route);
                    }
                }
                Err(_) => {
                    eprintln!("tun inbound: could not pin the server edge {destination}/{prefix}");
                }
            }
        }
        for (destination, prefix) in plan.routes() {
            if local_covers(&mut manager, *destination, *prefix) {
                eprintln!(
                    "tun inbound: {destination}/{prefix} is in the local table; not capturing it"
                );
                continue;
            }
            let route = Route::new(*destination, *prefix).with_if_name(interface.to_owned());
            if let Some(holder) = capture_holder(*destination, *prefix) {
                if holder != interface {
                    retire(&mut manager, &mut added, &mut pinned);
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        format!("{destination}/{prefix} is already captured by {holder}"),
                    ));
                }
            }
            if let Some(holder) = foreign_route(&mut manager, *destination, *prefix, interface) {
                retire(&mut manager, &mut added, &mut pinned);
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("{destination}/{prefix} is already routed via {holder}"),
                ));
            }
            match manager.add(&route) {
                Ok(()) => added.push(route),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    if held_by_another(*destination, *prefix) {
                        added.push(route);
                    } else if pending_targets(*destination, *prefix, interface) {
                        if let Some(holder) =
                            foreign_route(&mut manager, *destination, *prefix, interface)
                        {
                            retire(&mut manager, &mut added, &mut pinned);
                            return Err(io::Error::new(
                                io::ErrorKind::AlreadyExists,
                                format!("{destination}/{prefix} is already routed via {holder}"),
                            ));
                        }
                        added.push(route);
                    }
                }
                Err(error) => {
                    retire(&mut manager, &mut added, &mut pinned);
                    return Err(io::Error::new(
                        error.kind(),
                        format!("could not route {destination}/{prefix} into {interface}: {error}"),
                    ));
                }
            }
        }
        let guard = Arc::new(Self {
            manager: Mutex::new(manager),
            added: Mutex::new(added),
            pinned: Mutex::new(pinned),
            kept: Mutex::new(kept),
            pinning: Mutex::new(()),
            plan: plan.clone(),
            interface: interface.to_owned(),
        });
        // Publish the pins and the live guard under one lock, so a concurrent last-owner drain sees this guard before it can drop its pins.
        if let Ok(mut global) = installed_pins().lock() {
            if let Ok(pinned) = guard.pinned.lock() {
                for (key, route) in pinned.iter() {
                    global.insert(*key, route.clone());
                }
            }
            if let Ok(mut slot) = capture().lock() {
                slot.retain(|weak| weak.strong_count() > 0);
                slot.push(Arc::downgrade(&guard));
                CAPTURE_GENERATION.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
        // A duplicated pin skipped the kernel add; its holder may have closed in that window, so restore any pin the table no longer carries. The registered key above keeps a later drop from deleting it.
        if let Ok(pinned) = guard.pinned.lock() {
            for route in pinned.values() {
                let present = guard.added.lock().is_ok_and(|held| {
                    held.iter().any(|held| {
                        held.destination() == route.destination() && held.prefix() == route.prefix()
                    })
                });
                if present {
                    continue;
                }
                if let Ok(mut manager) = guard.manager.lock() {
                    let exists = manager.list().is_ok_and(|routes| {
                        routes.iter().any(|held| {
                            held.destination() == route.destination()
                                && held.prefix() == route.prefix()
                        })
                    });
                    if !exists && manager.add(route).is_ok() {
                        drop(manager);
                        if let Ok(mut held) = guard.added.lock() {
                            held.push(route.clone());
                        }
                    }
                }
            }
        }
        Ok(guard)
    }

    /// The effective route decides capture; the filtered route only picks the underlay. A
    /// physical default is still uncaptured when a half-default above it owns the address.
    fn route_to(&self, address: IpAddr) -> io::Result<DialRoute> {
        let interfaces = capture_interfaces();
        let mut manager = self
            .manager
            .lock()
            .map_err(|_| io::Error::other("the route table lock is poisoned"))?;
        let routes = manager.list()?;
        if local_route(&routes, address) {
            return Ok(DialRoute::uncaptured());
        }
        let effective = effective_route(&routes, address);
        let captured = effective.is_some_and(|route| self.owns(route, &routes));
        let underlay = if captured {
            let held: Vec<(IpAddr, u8)> = self
                .pinned
                .lock()
                .map(|pinned| pinned.keys().copied().collect())
                .unwrap_or_default();
            best_underlay_from(&routes, address, &interfaces, &held).and_then(|route| {
                let name = route.if_name().cloned().unwrap_or_default();
                if name.is_empty() && route.if_index().is_none() {
                    None
                } else {
                    Some((name, route.if_index()))
                }
            })
        } else {
            None
        };
        Ok(DialRoute { captured, underlay })
    }

    fn owns(&self, route: &Route, routes: &[Route]) -> bool {
        if let Some(name) = route.if_name() {
            return name.as_str() == self.interface;
        }
        if let Some(index) = route.if_index() {
            let own_index = routes.iter().find_map(|candidate| {
                candidate
                    .if_name()
                    .filter(|name| name.as_str() == self.interface)
                    .and(candidate.if_index())
            });
            return own_index == Some(index);
        }
        self.plan.routes().iter().any(|&(destination, prefix)| {
            route.destination() == destination && route.prefix() == prefix
        })
    }

    fn local_now(&self, address: IpAddr) -> bool {
        self.manager
            .lock()
            .is_ok_and(|mut manager| local_destination(&mut manager, address))
    }

    fn best_now(&self, address: IpAddr) -> Option<Route> {
        let mut held: Vec<(IpAddr, u8)> = self
            .pinned
            .lock()
            .ok()
            .map(|pinned| pinned.keys().copied().collect())
            .unwrap_or_default();
        if let Ok(global) = installed_pins().lock() {
            held.extend(global.keys().copied());
        }
        let captures = capture_interfaces();
        let mut manager = self.manager.lock().ok()?;
        if local_destination(&mut manager, address) {
            return None;
        }
        best_underlay(&mut manager, address, &captures, &held)
    }

    /// Keep one dialled address on the best route that currently carries it, so a name resolved
    /// after the capture cannot send the proxy's own connection back into the device.
    fn pin(&self, address: IpAddr) -> Option<bool> {
        let bits = if address.is_ipv4() { 32 } else { 128 };
        let covered = |(outer, prefix): &(IpAddr, u8)| {
            same_family(*outer, address) && covers(*outer, *prefix, address, bits)
        };
        if !self.plan.routes().iter().any(&covered) {
            return None;
        }
        if self.local_now(address) {
            return Some(true);
        }
        // A kept prefix already has its route; a capture prefix does not, so the dial still needs its host route above the halves.
        let kept_covers = self.kept.lock().is_ok_and(|kept| kept.iter().any(&covered));
        if kept_covers
            && self.best_now(address).is_some_and(|route| {
                route
                    .if_name()
                    .is_none_or(|name| name.as_str() != self.interface)
            })
        {
            return Some(true);
        }
        let Ok(_pinning) = self.pinning.lock() else {
            return Some(false);
        };
        let key = (address, bits);
        let existing = self
            .pinned
            .lock()
            .ok()
            .and_then(|pinned| pinned.get(&key).cloned());
        let installed = installed_pins()
            .lock()
            .ok()
            .and_then(|global| global.get(&key).cloned());
        let Some(base) = self.best_now(address) else {
            eprintln!("tun inbound: no route to pin {address} to");
            return Some(false);
        };
        let route = edge_route(&base, address, bits);
        let Ok(mut manager) = self.manager.lock() else {
            return Some(false);
        };
        let live = manager.find_route(&address).ok().flatten();
        if installed.as_ref() == Some(&route)
            && live
                .as_ref()
                .is_some_and(|live| equivalent_pin(live, &route))
        {
            if existing.as_ref() != Some(&route) {
                self.keep_pin(key, address, bits, route);
            }
            return Some(true);
        }
        if let Some(old) = existing.as_ref() {
            let _ = manager.delete(old);
        }
        let added = match manager.add(&route) {
            Ok(()) => true,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                held_by_another_except(address, bits, self)
            }
            Err(error) => {
                let restored = match existing.as_ref() {
                    None => true,
                    Some(old) => match manager.add(old) {
                        Ok(()) => true,
                        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => true,
                        Err(_) => false,
                    },
                };
                if !restored {
                    if let Ok(mut pinned) = self.pinned.lock() {
                        pinned.remove(&key);
                    }
                    if let Ok(mut global) = installed_pins().lock() {
                        if global.get(&key) == existing.as_ref() {
                            global.remove(&key);
                        }
                    }
                    if let Ok(mut routes) = self.added.lock() {
                        routes
                            .retain(|held| held.destination() != address || held.prefix() != bits);
                    }
                }
                eprintln!("tun inbound: could not pin the outbound edge {address}: {error}");
                false
            }
        };
        if added {
            self.keep_pin(key, address, bits, route);
        } else if let Some(installed) = installed {
            if existing.as_ref() != Some(&installed) {
                self.keep_pin(key, address, bits, installed);
            }
        }
        Some(added)
    }

    fn unpin(&self, address: IpAddr) -> bool {
        let bits = if address.is_ipv4() { 32 } else { 128 };
        let key = (address, bits);
        // Serialize the whole ownership change through the global pin table, so the last owner reads the route that is actually installed.
        let Ok(mut global) = installed_pins().lock() else {
            return false;
        };
        let Some(_route) = self
            .pinned
            .lock()
            .ok()
            .and_then(|mut pinned| pinned.remove(&key))
        else {
            return false;
        };
        if let Ok(mut routes) = self.added.lock() {
            routes.retain(|held| held.destination() != address || held.prefix() != bits);
        }
        let others: Vec<Arc<Self>> = capture()
            .lock()
            .map(|slot| {
                slot.iter()
                    .filter_map(Weak::upgrade)
                    .filter(|guard| !std::ptr::eq(Arc::as_ptr(guard), self))
                    .collect()
            })
            .unwrap_or_default();
        if another_pin_holds(key, &others) {
            return true;
        }
        let current = global.remove(&key);
        drop(global);
        if let Some(route) = current {
            if let Ok(mut manager) = self.manager.lock() {
                defer_delete(&mut manager, &route);
            }
            CAPTURE_GENERATION.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        true
    }

    fn keep_pin(&self, key: (IpAddr, u8), address: IpAddr, bits: u8, route: Route) {
        if let Ok(mut global) = installed_pins().lock() {
            global.insert(key, route.clone());
        }
        if let Ok(mut routes) = self.added.lock() {
            routes.retain(|held| held.destination() != address || held.prefix() != bits);
            routes.push(route.clone());
        }
        if let Ok(mut pinned) = self.pinned.lock() {
            pinned.insert(key, route);
        }
    }

    fn release_now(&self) {
        let routes: Vec<Route> = self
            .added
            .lock()
            .map(|mut added| added.drain(..).collect())
            .unwrap_or_default();
        let pinned: Vec<((IpAddr, u8), Route)> = self
            .pinned
            .lock()
            .map(|mut pinned| pinned.drain().collect())
            .unwrap_or_default();
        let Ok(mut manager) = self.manager.lock() else {
            return;
        };
        if let Ok(mut global) = installed_pins().lock() {
            for (key, _) in &pinned {
                global.remove(key);
            }
            global.clear();
        }
        for route in routes.into_iter().rev() {
            defer_delete(&mut manager, &route);
        }
        for (_, route) in pinned {
            defer_delete(&mut manager, &route);
        }
        CAPTURE_GENERATION.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Delete the routes a failed install added, leaving routes another live capture already owns.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn retire(
    manager: &mut RouteManager,
    added: &mut Vec<Route>,
    pinned: &mut HashMap<(IpAddr, u8), Route>,
) {
    let others: Vec<Arc<Guard>> = capture()
        .lock()
        .map(|slot| slot.iter().filter_map(Weak::upgrade).collect())
        .unwrap_or_default();
    for route in added.drain(..).rev() {
        if !another_holds(route.destination(), route.prefix(), &others) {
            defer_delete(manager, &route);
        }
    }
    if let Ok(mut global) = installed_pins().lock() {
        for key in pinned.keys() {
            if !another_pin_holds(*key, &others) {
                if let Some(route) = global.remove(key) {
                    defer_delete(manager, &route);
                }
            }
        }
    }
    pinned.clear();
}

/// A listed main-table route for this prefix that leaves by another interface, so adding a second
/// capture cannot silently lose the traffic to the lower metric.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn foreign_route(
    manager: &mut RouteManager,
    destination: IpAddr,
    prefix: u8,
    interface: &str,
) -> Option<String> {
    manager.list().ok()?.into_iter().find_map(|existing| {
        (is_main_table(&existing)
            && existing.destination() == destination
            && existing.prefix() == prefix
            && existing
                .if_name()
                .is_some_and(|name| name.as_str() != interface))
        .then(|| existing.if_name().cloned().unwrap_or_default())
    })
}

/// Whether the exact route already sits on this guard's interface, so an install that lost the race with a retiring guard owns its removal.
/// Find the live capture that already holds a destination/prefix, if any.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn capture_holder(destination: IpAddr, prefix: u8) -> Option<String> {
    let guards: Vec<Arc<Guard>> = capture()
        .lock()
        .map(|slot| slot.iter().filter_map(Weak::upgrade).collect())
        .unwrap_or_default();
    guards.into_iter().find_map(|guard| {
        guard.added.lock().ok().and_then(|held| {
            held.iter()
                .any(|route| route.destination() == destination && route.prefix() == prefix)
                .then(|| guard.interface.clone())
        })
    })
}

/// The best current route for an address above the capture and this guard's own pins.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn best_underlay(
    manager: &mut RouteManager,
    address: IpAddr,
    captures: &[String],
    held: &[(IpAddr, u8)],
) -> Option<Route> {
    best_underlay_from(&manager.list().ok()?, address, captures, held)
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn best_underlay_from(
    routes: &[Route],
    address: IpAddr,
    captures: &[String],
    held: &[(IpAddr, u8)],
) -> Option<Route> {
    routes
        .iter()
        .filter(|route| underlay_route(route, address, captures, held))
        .min_by_key(|route| (std::cmp::Reverse(route.prefix()), default_metric(route)))
        .cloned()
}

/// The route the kernel would use before an interface filter: the effective route that decides
/// whether a destination enters the device.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn effective_route(routes: &[Route], address: IpAddr) -> Option<&Route> {
    let bits = if address.is_ipv4() { 32 } else { 128 };
    routes
        .iter()
        .filter(|route| {
            is_main_table(route)
                && same_family(route.destination(), address)
                && covers(route.destination(), route.prefix(), address, bits)
                && unscoped(route)
        })
        .min_by_key(|route| (std::cmp::Reverse(route.prefix()), default_metric(route)))
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn carries(route: &Route, address: IpAddr, held: &[(IpAddr, u8)]) -> bool {
    let bits = if address.is_ipv4() { 32 } else { 128 };
    is_main_table(route)
        && same_family(route.destination(), address)
        && covers(route.destination(), route.prefix(), address, bits)
        && !held.contains(&(route.destination(), route.prefix()))
        && unscoped(route)
}

/// Whether the Linux local table already owns this destination, so capturing it would shadow a host-local address.
#[cfg(target_os = "linux")]
fn local_destination(manager: &mut RouteManager, address: IpAddr) -> bool {
    manager
        .list()
        .is_ok_and(|routes| local_route(&routes, address))
}

#[cfg(target_os = "linux")]
fn local_route(routes: &[Route], address: IpAddr) -> bool {
    let bits = if address.is_ipv4() { 32 } else { 128 };
    routes.iter().any(|route| {
        route.table() == 255
            && same_family(route.destination(), address)
            && covers(route.destination(), route.prefix(), address, bits)
    })
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn local_destination(_manager: &mut RouteManager, _address: IpAddr) -> bool {
    false
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn local_route(_routes: &[Route], _address: IpAddr) -> bool {
    false
}

/// Whether the Linux local table covers the whole requested prefix, so capturing it cannot shadow a wider physical route.
#[cfg(target_os = "linux")]
fn local_covers(manager: &mut RouteManager, address: IpAddr, prefix: u8) -> bool {
    manager.list().is_ok_and(|routes| {
        routes.iter().any(|route| {
            route.table() == 255 && covers(route.destination(), route.prefix(), address, prefix)
        })
    })
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn local_covers(_manager: &mut RouteManager, _address: IpAddr, _prefix: u8) -> bool {
    false
}

/// Whether `route` is an underlay candidate: it carries the address, leaves by a physical interface,
/// and is not one of this guard's own pins.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn underlay_route(
    route: &Route,
    address: IpAddr,
    captures: &[String],
    held: &[(IpAddr, u8)],
) -> bool {
    carries(route, address, held)
        && route
            .if_name()
            .is_none_or(|name| !captures.iter().any(|capture| capture == name))
}

/// Whether another live capture added this exact route.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn another_holds(destination: IpAddr, prefix: u8, guards: &[Arc<Guard>]) -> bool {
    guards.iter().any(|guard| {
        guard.added.lock().is_ok_and(|held| {
            held.iter()
                .any(|route| route.destination() == destination && route.prefix() == prefix)
        })
    })
}

/// Whether a live guard owns this exact route, so an `AlreadyExists` route that predates every guard is never adopted for deletion.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn another_guard_holds(route: &Route) -> bool {
    capture().lock().is_ok_and(|slot| {
        slot.iter().filter_map(Weak::upgrade).any(|guard| {
            guard
                .added
                .lock()
                .is_ok_and(|held| held.iter().any(|owned| equivalent_pin(owned, route)))
        })
    })
}

/// Whether another live capture still pins this address, so its replacement route must stay.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn another_pin_holds(key: (IpAddr, u8), guards: &[Arc<Guard>]) -> bool {
    guards.iter().any(|guard| {
        guard
            .pinned
            .lock()
            .is_ok_and(|pinned| pinned.contains_key(&key))
    })
}

/// Whether a deferred delete already names this destination and prefix, so adopting the route must also own it against a later retry.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn pending_targets(destination: IpAddr, prefix: u8, interface: &str) -> bool {
    let named = |route: &Route| {
        route.destination() == destination
            && route.prefix() == prefix
            && route
                .if_name()
                .is_some_and(|name| name.as_str() == interface)
    };
    pending_deletes()
        .lock()
        .is_ok_and(|pending| pending.iter().any(named))
        || pending_pinned()
            .lock()
            .is_ok_and(|pending| pending.iter().any(|(_, route)| named(route)))
}

/// Whether a live capture already owns this destination and prefix. A route that predates every
/// guard stays unowned, so closing one capture cannot delete it.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn held_by_another(destination: IpAddr, prefix: u8) -> bool {
    let guards: Vec<Arc<Guard>> = capture()
        .lock()
        .map(|mut slot| {
            slot.retain(|weak| weak.strong_count() > 0);
            slot.iter().filter_map(Weak::upgrade).collect()
        })
        .unwrap_or_default();
    guards.into_iter().any(|guard| {
        guard.added.lock().is_ok_and(|held| {
            held.iter()
                .any(|route| route.destination() == destination && route.prefix() == prefix)
        })
    })
}

/// The same ownership check ignoring `me`, whose stale record was just deleted before a re-add.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn held_by_another_except(destination: IpAddr, prefix: u8, me: &Guard) -> bool {
    let guards: Vec<Arc<Guard>> = capture()
        .lock()
        .map(|mut slot| {
            slot.retain(|weak| weak.strong_count() > 0);
            slot.iter().filter_map(Weak::upgrade).collect()
        })
        .unwrap_or_default();
    guards.into_iter().any(|guard| {
        !std::ptr::eq(guard.as_ref(), me)
            && guard.added.lock().is_ok_and(|held| {
                held.iter()
                    .any(|route| route.destination() == destination && route.prefix() == prefix)
            })
    })
}

/// The capture interfaces in force, so one device's underlay lookup cannot pick another device's route.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn capture_interfaces() -> Vec<String> {
    let guards: Vec<Arc<Guard>> = capture()
        .lock()
        .map(|slot| slot.iter().filter_map(Weak::upgrade).collect())
        .unwrap_or_default();
    guards
        .into_iter()
        .map(|guard| guard.interface.clone())
        .collect()
}

/// Split an excluded prefix at the route boundaries that currently carry it, so one lookup cannot
/// move the whole prefix onto the route of its first address.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn keep_edges(
    manager: &mut RouteManager,
    destination: IpAddr,
    prefix: u8,
    captures: &[String],
) -> io::Result<Vec<Route>> {
    let routes = manager
        .list()?
        .into_iter()
        .filter(is_main_table)
        .collect::<Vec<_>>();
    let mut edges = Vec::new();
    keep_edges_for(
        &routes,
        network(destination, prefix),
        prefix,
        captures,
        &mut edges,
    )?;
    Ok(edges)
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn keep_edges_for(
    routes: &[Route],
    destination: IpAddr,
    prefix: u8,
    captures: &[String],
    edges: &mut Vec<Route>,
) -> io::Result<()> {
    let bits = if destination.is_ipv4() { 32 } else { 128 };
    let more_specific = routes.iter().any(|route| {
        let capture = route
            .if_name()
            .is_some_and(|name| captures.iter().any(|capture| capture == name));
        same_family(route.destination(), destination)
            && covers(destination, prefix, route.destination(), route.prefix())
            && if capture {
                route.prefix() >= prefix
            } else {
                route.prefix() > prefix
            }
    });
    if prefix >= bits || !more_specific {
        if let Some(base) = best_covering(routes, destination, captures) {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            if base.kind() != RouteKind::Unicast {
                let route = Route::new(destination, prefix).with_kind(base.kind());
                #[cfg(target_os = "linux")]
                let route = route.with_table(base.table());
                edges.push(route);
                return Ok(());
            }
            edges.push(edge_route(base, destination, prefix));
            return Ok(());
        }
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            format!("no route carries the excluded prefix {destination}/{prefix}"),
        ));
    }
    let child = prefix + 1;
    keep_edges_for(routes, destination, child, captures, edges)?;
    keep_edges_for(
        routes,
        upper_half(destination, bits, child),
        child,
        captures,
        edges,
    )
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn best_covering<'a>(
    routes: &'a [Route],
    address: IpAddr,
    captures: &[String],
) -> Option<&'a Route> {
    let bits = if address.is_ipv4() { 32 } else { 128 };
    routes
        .iter()
        .filter(|route| {
            is_main_table(route)
                && same_family(route.destination(), address)
                && covers(route.destination(), route.prefix(), address, bits)
                && route
                    .if_name()
                    .is_none_or(|name| !captures.iter().any(|capture| capture == name))
                && unscoped(route)
        })
        .min_by_key(|route| (std::cmp::Reverse(route.prefix()), default_metric(route)))
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn upper_half(address: IpAddr, bits: u8, prefix: u8) -> IpAddr {
    let bit = u32::from(bits - prefix);
    match address {
        IpAddr::V4(address) => IpAddr::V4(Ipv4Addr::from(u32::from(address) | (1_u32 << bit))),
        IpAddr::V6(address) => IpAddr::V6(Ipv6Addr::from(u128::from(address) | (1_u128 << bit))),
    }
}

/// Whether a live route is the pin this guard needs: a readback fills fields (interface index, table) that the installed pin leaves to the kernel, so compare the effective identity rather than the whole record.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn equivalent_pin(live: &Route, pin: &Route) -> bool {
    let interface = pin
        .if_name()
        .is_none_or(|name| live.if_name().is_some_and(|live| live == name))
        && pin
            .if_index()
            .is_none_or(|index| live.if_index() == Some(index));
    #[cfg(target_os = "linux")]
    let table = live.table() == pin.table();
    #[cfg(not(target_os = "linux"))]
    let table = true;
    live.destination() == pin.destination()
        && live.prefix() == pin.prefix()
        && live.gateway() == pin.gateway()
        && table
        && interface
}

/// Carry a route's gateway and device onto the host route for `address`, so the pin leaves by the
/// same underlay as the prefix it was read from.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn edge_route(base: &Route, address: IpAddr, bits: u8) -> Route {
    let mut route = Route::new(address, bits);
    if let Some(gateway) = base.gateway() {
        route = route.with_gateway(gateway);
    }
    if let Some(name) = base.if_name() {
        route = route.with_if_name(name.to_owned());
    } else if let Some(index) = base.if_index() {
        route = route.with_if_index(index);
    }
    #[cfg(target_os = "linux")]
    if let Some(source) = base.pref_source() {
        route = route.with_pref_source(source);
    }
    route
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn defer_delete(manager: &mut RouteManager, route: &Route) {
    if let Err(error) = manager.delete(route) {
        if error.kind() != io::ErrorKind::NotFound {
            if let Ok(mut pending) = pending_deletes().lock() {
                pending.push(route.clone());
            }
            schedule_retry();
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn retry_pending(manager: &mut RouteManager) {
    let routes = pending_deletes()
        .lock()
        .map(|mut pending| std::mem::take(&mut *pending))
        .unwrap_or_default();
    let pinned = pending_pinned()
        .lock()
        .map(|mut pending| std::mem::take(&mut *pending))
        .unwrap_or_default();
    cleanup_routes(manager, routes, pinned);
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn cleanup_routes(
    manager: &mut RouteManager,
    routes: Vec<Route>,
    pinned: Vec<((IpAddr, u8), Route)>,
) {
    let others: Vec<Arc<Guard>> = capture()
        .lock()
        .map(|slot| slot.iter().filter_map(Weak::upgrade).collect())
        .unwrap_or_default();
    let Ok(mut global) = installed_pins().lock() else {
        return;
    };
    for route in routes.into_iter().rev() {
        let key = (route.destination(), route.prefix());
        if global.contains_key(&key) || another_holds(key.0, key.1, &others) {
            continue;
        }
        defer_delete(manager, &route);
    }
    for (key, route) in pinned {
        if !others.is_empty() || another_pin_holds(key, &others) {
            continue;
        }
        global.remove(&key);
        defer_delete(manager, &route);
    }
    if others.is_empty() {
        let live = capture().lock().map_or(true, |mut slot| {
            slot.retain(|weak| weak.strong_count() > 0);
            !slot.is_empty()
        });
        if !live {
            for (_, route) in global.drain() {
                defer_delete(manager, &route);
            }
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn deferred_cleanup(routes: Vec<Route>, pinned: Vec<((IpAddr, u8), Route)>) {
    let _routes = route_write();
    let _operation = route_operation();
    let Ok(mut manager) = RouteManager::new() else {
        if let Ok(mut pending) = pending_deletes().lock() {
            pending.extend(routes);
        }
        if let Ok(mut pending) = pending_pinned().lock() {
            pending.extend(pinned);
        }
        schedule_retry();
        return;
    };
    cleanup_routes(&mut manager, routes, pinned);
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn schedule_retry() {
    static RETRY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if RETRY.swap(true, std::sync::atomic::Ordering::AcqRel) {
        return;
    }
    for attempt in 0..3 {
        let result = std::thread::Builder::new()
            .name("ferrox-route-cleanup".to_owned())
            .spawn(|| loop {
                std::thread::sleep(std::time::Duration::from_secs(1));
                let empty = pending_deletes()
                    .lock()
                    .is_ok_and(|pending| pending.is_empty())
                    && pending_pinned()
                        .lock()
                        .is_ok_and(|pending| pending.is_empty());
                if empty {
                    RETRY.store(false, std::sync::atomic::Ordering::Release);
                    let still_empty = pending_deletes()
                        .lock()
                        .is_ok_and(|pending| pending.is_empty())
                        && pending_pinned()
                            .lock()
                            .is_ok_and(|pending| pending.is_empty());
                    if still_empty {
                        return;
                    }
                    if RETRY.swap(true, std::sync::atomic::Ordering::AcqRel) {
                        return;
                    }
                }
                let _routes = route_write();
                let _operation = route_operation();
                let Ok(mut manager) = RouteManager::new() else {
                    continue;
                };
                retry_pending(&mut manager);
            });
        if result.is_ok() {
            return;
        }
        RETRY.store(false, std::sync::atomic::Ordering::Release);
        if attempt < 2 {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
impl Drop for Guard {
    fn drop(&mut self) {
        CAPTURE_GENERATION.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let Ok(mut added) = self.added.lock() else {
            return;
        };
        let routes: Vec<Route> = added.drain(..).collect();
        drop(added);
        // A dial can drop the last guard while holding `route_read`, and a capture can be released inside an install: waiting for the operation lock here would deadlock, so a helper takes both locks in install order once they are free.
        let Ok(_operation) = route_operation_lock().try_lock() else {
            let pinned: Vec<((IpAddr, u8), Route)> = self
                .pinned
                .lock()
                .map(|pinned| {
                    pinned
                        .iter()
                        .map(|(key, route)| (*key, route.clone()))
                        .collect()
                })
                .unwrap_or_default();
            let routes_queued = routes.clone();
            let pinned_queued = pinned.clone();
            if std::thread::Builder::new()
                .spawn(move || deferred_cleanup(routes, pinned))
                .is_err()
            {
                if let Ok(mut pending) = pending_deletes().lock() {
                    pending.extend(routes_queued);
                }
                if let Ok(mut pending) = pending_pinned().lock() {
                    pending.extend(pinned_queued);
                }
                schedule_retry();
            }
            return;
        };
        let others: Vec<Arc<Self>> = capture()
            .lock()
            .map(|mut slot| {
                slot.retain(|weak| weak.strong_count() > 0 && !std::ptr::eq(weak.as_ptr(), self));
                slot.iter().filter_map(Weak::upgrade).collect()
            })
            .unwrap_or_default();
        let Ok(mut manager) = self.manager.lock() else {
            return;
        };
        let Ok(mut global) = installed_pins().lock() else {
            return;
        };
        for route in routes.into_iter().rev() {
            // Two live captures can add the same destination; the kernel keeps one entry, so the last one to close removes it.
            let key = (route.destination(), route.prefix());
            if global.contains_key(&key) {
                continue;
            }
            if !another_holds(route.destination(), route.prefix(), &others) {
                defer_delete(&mut manager, &route);
            }
        }
        if others.is_empty() {
            let live = capture().lock().map_or(true, |mut slot| {
                slot.retain(|weak| weak.strong_count() > 0);
                !slot.is_empty()
            });
            if !live {
                for (_, route) in global.drain() {
                    defer_delete(&mut manager, &route);
                }
            }
        }
    }
}

/// A mobile host routes in its own VpnService, so `auto_route` names the platform it needs instead of capturing the table twice.
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub(crate) struct Guard;

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
impl Guard {
    pub(crate) fn install(_interface: &str, _plan: &Plan) -> io::Result<Arc<Self>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "`auto_route` needs a platform routing table; the host routes its own VpnService",
        ))
    }
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
fn default_metric(route: &Route) -> u32 {
    #[cfg(target_os = "windows")]
    {
        use windows_sys::Win32::NetworkManagement::IpHelper::{
            GetIpInterfaceEntry, MIB_IPINTERFACE_ROW,
        };
        use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
        use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
        // SAFETY: every field of the C row accepts an all-zero value; only the family and LUID are read.
        let mut row: MIB_IPINTERFACE_ROW = unsafe { std::mem::zeroed() };
        row.Family = if route.destination().is_ipv4() {
            AF_INET
        } else {
            AF_INET6
        };
        row.InterfaceIndex = route.if_index().unwrap_or_default();
        if let Some(luid) = route.luid() {
            row.InterfaceLuid = NET_LUID_LH { Value: luid };
        }
        // SAFETY: `row` names the route's interface and `GetIpInterfaceEntry` fills its metrics.
        if unsafe { GetIpInterfaceEntry(&mut row) } == 0 {
            return route
                .metric()
                .unwrap_or_default()
                .saturating_add(row.Metric);
        }
    }
    route.metric().unwrap_or(0)
}

#[cfg(target_os = "macos")]
fn default_metric(_route: &Route) -> u32 {
    0
}

#[cfg(target_os = "linux")]
fn is_main_table(route: &Route) -> bool {
    matches!(route.table(), 0 | 254)
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn is_main_table(_route: &Route) -> bool {
    true
}

#[cfg(target_os = "macos")]
fn unscoped(route: &Route) -> bool {
    !route.if_scope()
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
fn unscoped(_route: &Route) -> bool {
    true
}

fn same_family(outer: IpAddr, inner: IpAddr) -> bool {
    outer.is_ipv4() == inner.is_ipv4()
}

/// The prefix's network address, so a route config that names a host inside it installs and compares as the prefix.
fn network(address: IpAddr, prefix: u8) -> IpAddr {
    match address {
        IpAddr::V4(address) => {
            let mask = u32::MAX
                .checked_shl(32 - u32::from(prefix.min(32)))
                .unwrap_or(0);
            IpAddr::V4(Ipv4Addr::from(u32::from(address) & mask))
        }
        IpAddr::V6(address) => {
            let mask = u128::MAX
                .checked_shl(128 - u32::from(prefix.min(128)))
                .unwrap_or(0);
            IpAddr::V6(Ipv6Addr::from(u128::from(address) & mask))
        }
    }
}

/// Whether `outer/prefix` contains `inner/inner_prefix`, by masked bits alone.
fn overlaps(one: IpAddr, one_prefix: u8, other: IpAddr, other_prefix: u8) -> bool {
    same_family(one, other)
        && (covers(one, one_prefix, other, other_prefix)
            || covers(other, other_prefix, one, one_prefix))
}

/// Whether `outer/prefix` contains `inner/inner_prefix`, by masked bits alone.
fn covers(outer: IpAddr, prefix: u8, inner: IpAddr, inner_prefix: u8) -> bool {
    if prefix > inner_prefix {
        return false;
    }
    match (outer, inner) {
        (IpAddr::V4(outer), IpAddr::V4(inner)) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
            u32::from(outer) & mask == u32::from(inner) & mask
        }
        (IpAddr::V6(outer), IpAddr::V6(inner)) => {
            let mask = u128::MAX
                .checked_shl(128 - u32::from(prefix.min(128)))
                .unwrap_or(0);
            u128::from(outer) & mask == u128::from(inner) & mask
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn a_v4_device_captures_only_the_v4_halves() {
        let plan = Plan::new(true, false, &[], &[]);
        assert_eq!(
            plan.routes(),
            &[
                (IpAddr::V4(Ipv4Addr::UNSPECIFIED), 1),
                (IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0)), 1),
            ]
        );
    }

    #[test]
    fn a_route_default_captures_two_halves_per_family() {
        let v4 = Plan::new(true, false, &[], &[]);
        assert_eq!(v4.routes().len(), 2);
        let v6 = Plan::new(false, true, &[], &[]);
        assert_eq!(
            v6.routes(),
            &[
                (IpAddr::V6(Ipv6Addr::UNSPECIFIED), 1),
                (IpAddr::V6(Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0)), 1),
            ]
        );
    }

    #[test]
    fn a_dual_device_captures_both_halves() {
        let plan = Plan::new(true, true, &[], &[]);
        assert_eq!(plan.routes().len(), 4);
        assert_eq!(plan.routes()[2], (IpAddr::V6(Ipv6Addr::UNSPECIFIED), 1));
    }

    #[test]
    fn a_pin_is_dropped_when_no_capture_carries_its_family() {
        let v4 = (IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 32);
        let v6 = (
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            128,
        );
        let plan = Plan::new(true, false, &[], &[]).with_pins(&[v4, v6]);
        assert_eq!(plan.pins(), &[v4]);
    }

    #[test]
    fn a_named_route_inside_a_kept_prefix_is_dropped() {
        let keep = [(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8)];
        let plan = Plan::new(
            true,
            false,
            &[
                (IpAddr::V4(Ipv4Addr::new(10, 1, 0, 0)), 16),
                (IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)), 16),
            ],
            &keep,
        );
        assert!(plan
            .routes()
            .contains(&(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)), 16)));
        assert!(!plan
            .routes()
            .contains(&(IpAddr::V4(Ipv4Addr::new(10, 1, 0, 0)), 16)));
        let kept_half = Plan::new(true, false, &[], &[(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 1)]);
        assert!(!kept_half
            .routes()
            .contains(&(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 1)));
        assert!(kept_half
            .routes()
            .contains(&(IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0)), 1)));
    }

    #[test]
    fn a_named_prefix_installs_without_its_host_bits() {
        let plan = Plan::new(
            true,
            false,
            &[(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)), 16)],
            &[(IpAddr::V4(Ipv4Addr::new(10, 2, 3, 4)), 16)],
        );
        assert!(plan
            .routes()
            .contains(&(IpAddr::V4(Ipv4Addr::new(10, 1, 0, 0)), 16)));
        assert_eq!(plan.keep(), &[(IpAddr::V4(Ipv4Addr::new(10, 2, 0, 0)), 16)]);
    }

    #[test]
    fn a_kept_default_route_skips_the_family_halves() {
        let keep = [
            (IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            (IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        ];
        let plan = Plan::new(true, true, &[], &keep);
        assert!(plan.routes().is_empty(), "{:?}", plan.routes());
    }

    #[test]
    fn an_equal_prefix_is_contained() {
        let route = (IpAddr::V4(Ipv4Addr::new(10, 1, 0, 0)), 16);
        let plan = Plan::new(true, false, &[route], &[route]);
        assert!(!plan.routes().contains(&route));
        let host = (IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 32);
        let plan = Plan::new(true, false, &[host], &[host]);
        assert!(!plan.routes().contains(&host));
        let v6 = (
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            128,
        );
        let plan = Plan::new(false, true, &[v6], &[v6]);
        assert!(!plan.routes().contains(&v6));
    }

    #[test]
    fn a_duplicate_route_is_installed_once() {
        let route = (IpAddr::V4(Ipv4Addr::new(198, 18, 0, 0)), 15);
        let plan = Plan::new(true, false, &[route, route], &[]);
        assert_eq!(
            plan.routes()
                .iter()
                .filter(|named| **named == route)
                .count(),
            1
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "needs CAP_NET_ADMIN; ci.yml runs it as root"]
    fn a_real_guard_installs_pins_and_retires_a_route() {
        let target: IpAddr = "203.0.113.1".parse().unwrap();
        let captured = "203.0.113.0".parse().unwrap();
        let plan = Plan {
            routes: vec![(captured, 24)],
            ..Plan::default()
        };
        let first = Guard::install("lo", &plan).expect("install a route on loopback");
        let mut manager = RouteManager::new().expect("route table");
        let installed = manager.find_route(&target).expect("read").expect("route");
        assert_eq!(installed.prefix(), 24);
        let second =
            Guard::install("lo", &Plan::new(false, false, &[], &[])).expect("second capture");
        pin_dialled(target);
        let pinned = manager.find_route(&target).expect("read").expect("route");
        assert_eq!(
            pinned.prefix(),
            32,
            "the dialled address is pinned above the /24"
        );
        assert!(
            pinned.if_name().is_some_and(|name| name != "lo"),
            "the pin uses a named underlay outside the capture interfaces"
        );
        drop(first);
        let shared = manager.find_route(&target).expect("read").expect("route");
        assert_eq!(
            shared.prefix(),
            32,
            "the last live guard keeps the pinned route"
        );
        drop(second);
        let retired = manager.find_route(&target).expect("read");
        assert!(
            retired.is_none_or(|route| route.prefix() != 32),
            "the last guard removes the route it added"
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    #[test]
    fn a_kept_prefix_keeps_each_underlying_route() {
        let routes = vec![
            Route::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
                .with_gateway(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            Route::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)), 25)
                .with_gateway(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
        ];
        let mut edges = Vec::new();
        keep_edges_for(
            &routes,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)),
            24,
            &[],
            &mut edges,
        )
        .unwrap();
        assert_eq!(edges.len(), 2);
        assert_eq!(
            edges[0].destination(),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0))
        );
        assert_eq!(edges[0].prefix(), 25);
        assert_eq!(
            edges[0].gateway(),
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
        );
        assert_eq!(
            edges[1].destination(),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 128))
        );
        assert_eq!(edges[1].prefix(), 25);
        assert_eq!(
            edges[1].gateway(),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn an_excluded_prefix_under_a_discard_base_keeps_its_kind() {
        let routes = vec![
            Route::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0).with_kind(RouteKind::Blackhole),
            Route::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8).with_if_name("tun0".to_owned()),
        ];
        let mut edges = Vec::new();
        keep_edges_for(
            &routes,
            IpAddr::V4(Ipv4Addr::new(10, 1, 0, 0)),
            16,
            &["tun0".to_owned()],
            &mut edges,
        )
        .unwrap();
        assert_eq!(edges.len(), 1, "one route carries the exclusion");
        assert_eq!(
            edges[0].destination(),
            IpAddr::V4(Ipv4Addr::new(10, 1, 0, 0))
        );
        assert_eq!(edges[0].prefix(), 16, "the excluded prefix is the route");
        assert_eq!(edges[0].kind(), RouteKind::Blackhole);
        assert!(
            edges[0].if_name().is_none(),
            "a discard route binds no device"
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    #[test]
    fn a_route_that_carries_the_whole_exclusion_stays_one_pin() {
        let routes = vec![Route::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)), 24)
            .with_gateway(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))];
        let mut edges = Vec::new();
        keep_edges_for(
            &routes,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)),
            24,
            &[],
            &mut edges,
        )
        .unwrap();
        assert_eq!(edges.len(), 1);
        assert_eq!(
            edges[0].destination(),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0))
        );
        assert_eq!(edges[0].prefix(), 24);
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    #[test]
    fn a_physical_default_does_not_hide_a_capturing_half_default() {
        let address = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
        let physical =
            Route::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0).with_if_name("eth0".to_owned());
        let tunnel =
            Route::new(IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0)), 1).with_if_name("utun3".to_owned());
        let routes = vec![physical, tunnel];
        let effective = effective_route(&routes, address).expect("the effective route");
        assert_eq!(effective.prefix(), 1, "the tunnel half wins the capture");
        assert_eq!(
            effective.if_name().map(String::as_str),
            Some("utun3"),
            "the effective route names the device"
        );
        assert!(
            !underlay_route(effective, address, &["utun3".to_owned()], &[]),
            "the filtered lookup still refuses the tunnel as an underlay"
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    #[test]
    fn another_capture_interface_is_not_an_underlay() {
        let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9));
        let captures = vec!["tun-a".to_owned()];
        let tunnel = Route::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)), 24)
            .with_if_name("tun-a".to_owned());
        let physical =
            Route::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)), 24).with_if_name("eth0".to_owned());
        assert!(!underlay_route(&tunnel, address, &captures, &[]));
        assert!(underlay_route(&physical, address, &captures, &[]));
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    #[test]
    fn a_live_pin_matches_by_effective_fields() {
        let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9));
        let gateway = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let pin = Route::new(address, 32)
            .with_gateway(gateway)
            .with_if_name("eth0".to_owned());
        let live = Route::new(address, 32)
            .with_gateway(gateway)
            .with_if_name("eth0".to_owned())
            .with_if_index(7);
        assert!(
            equivalent_pin(&live, &pin),
            "the readback fields do not differ"
        );
        let moved = Route::new(address, 32)
            .with_gateway(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)))
            .with_if_name("eth0".to_owned());
        assert!(
            !equivalent_pin(&moved, &pin),
            "a new gateway is a different pin"
        );
    }

    #[test]
    fn containment_is_masked_bits_not_bytes() {
        let outer = IpAddr::V4(Ipv4Addr::new(172, 16, 0, 0));
        let inner = IpAddr::V4(Ipv4Addr::new(172, 31, 255, 1));
        assert!(covers(outer, 12, inner, 32));
        assert!(!covers(outer, 16, inner, 32));
        assert!(!covers(inner, 32, outer, 12));
        let v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0));
        let v6_inner = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 0));
        assert!(covers(v6, 32, v6_inner, 64));
        assert!(covers(v6, 48, v6_inner, 64));
        let v6_out = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb9, 0, 0, 0, 0, 0, 0));
        assert!(!covers(v6, 48, v6_out, 64));
    }
}
