#![no_std]
#![no_main]

use aya_ebpf::{macros::classifier, programs::TcContext};

use packet_watcher::{try_egress_filter, try_ingress_filter};

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[classifier]
pub fn ingress_filter(ctx: TcContext) -> i32 {
    match unsafe { try_ingress_filter(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret as i32,
    }
}

#[classifier]
pub fn egress_filter(ctx: TcContext) -> i32 {
    match unsafe { try_egress_filter(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret as i32,
    }
}
