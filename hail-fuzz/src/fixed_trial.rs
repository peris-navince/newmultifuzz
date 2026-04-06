use std::sync::{Mutex, OnceLock};

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct TrialHit {
    pub addr: u64,
    pub nth_touch: u64,
}

#[derive(Debug, Clone)]
struct TrialController {
    target_addr: u64,
    nth_touch: u64,
    current_touch: u64,
    armed: bool,
    hit: Option<TrialHit>,
}

static CONTROLLER: OnceLock<Mutex<Option<TrialController>>> = OnceLock::new();

fn controller_cell() -> &'static Mutex<Option<TrialController>> {
    CONTROLLER.get_or_init(|| Mutex::new(None))
}

pub fn arm(target_addr: u64, nth_touch: u64) {
    let mut guard = controller_cell().lock().unwrap();
    *guard = Some(TrialController {
        target_addr,
        nth_touch: nth_touch.max(1),
        current_touch: 0,
        armed: true,
        hit: None,
    });
}

pub fn disable() {
    let mut guard = controller_cell().lock().unwrap();
    *guard = None;
}

pub fn on_execution_reset() {
    let mut guard = controller_cell().lock().unwrap();
    if let Some(ctrl) = guard.as_mut() {
        ctrl.current_touch = 0;
        ctrl.hit = None;
        ctrl.armed = true;
    }
}

pub fn on_mmio_read(addr: u64) -> bool {
    let mut guard = controller_cell().lock().unwrap();
    let Some(ctrl) = guard.as_mut() else {
        return false;
    };
    if !ctrl.armed || addr != ctrl.target_addr {
        return false;
    }
    ctrl.current_touch += 1;
    if ctrl.current_touch == ctrl.nth_touch {
        ctrl.hit = Some(TrialHit { addr, nth_touch: ctrl.nth_touch });
        ctrl.armed = false;
        return true;
    }
    false
}

pub fn take_hit() -> Option<TrialHit> {
    let mut guard = controller_cell().lock().unwrap();
    guard.as_mut().and_then(|ctrl| ctrl.hit.take())
}

pub fn peek_hit() -> Option<TrialHit> {
    let guard = controller_cell().lock().unwrap();
    guard.as_ref().and_then(|ctrl| ctrl.hit.clone())
}
