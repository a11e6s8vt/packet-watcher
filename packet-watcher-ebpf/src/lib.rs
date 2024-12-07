#![no_std]

pub(crate) mod egress;
pub(crate) mod ingress;
use aya_ebpf::{
    bindings::{TC_ACT_OK, TC_ACT_PIPE, TC_ACT_SHOT},
    cty::c_long,
    macros::map,
    maps::PerfEventArray,
    programs::TcContext,
};
use core::mem;
pub use egress::try_egress_filter;
pub use ingress::try_ingress_filter;

use packet_watcher_common::{TcAct, TrafficDirection, TrafficEvent};

#[map]
static mut INGRESS_EVENTS: PerfEventArray<TrafficEvent> = PerfEventArray::<TrafficEvent>::new(0);

#[map]
static mut EGRESS_EVENTS: PerfEventArray<TrafficEvent> = PerfEventArray::<TrafficEvent>::new(0);

#[inline(always)]
pub unsafe fn ptr_at<T>(ctx: &TcContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

pub unsafe fn process_packet(
    ctx: &TcContext,
    tc_act: TcAct,
    event: &mut TrafficEvent,
    direction: TrafficDirection,
) -> Result<i32, c_long> {
    event.tc_act = tc_act;

    match direction {
        TrafficDirection::Ingress => unsafe { INGRESS_EVENTS.output(ctx, event, 0) },
        TrafficDirection::Egress => unsafe { EGRESS_EVENTS.output(ctx, event, 0) },
    }

    Ok(match tc_act {
        TcAct::Ok => TC_ACT_OK,
        TcAct::Shot => TC_ACT_SHOT,
        TcAct::Pipe => TC_ACT_PIPE,
    })
}
