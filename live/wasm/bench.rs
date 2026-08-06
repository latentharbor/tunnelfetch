// The Rust half of the toolchain comparison. Same three functions as bench.c, no wasm-bindgen,
// no allocator crate — the point is to compare code generation, not framework overhead.
//
//   rustc --target wasm32-unknown-unknown -O --crate-type=cdylib -o ../src/wasmbytes.wasm bench.rs
//
// `alloc` reuses one Vec rather than replacing it, so a caller that splits a transfer into many
// crossings is not timing the allocator. The C modules hand back a fixed arena for the same reason.

#![no_std]
#![allow(static_mut_refs)]

use core::panic::PanicInfo;

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    loop {}
}

const ARENA_BYTES: usize = 16 << 20;
static mut ARENA: [u8; ARENA_BYTES] = [0u8; ARENA_BYTES];

#[no_mangle]
pub unsafe extern "C" fn alloc(_len: usize) -> *mut u8 {
    ARENA.as_mut_ptr()
}

/// Touch every byte, with an accumulator a compiler cannot fold away.
#[no_mangle]
pub unsafe extern "C" fn sum(ptr: *const u8, len: usize) -> u32 {
    let mut acc: u32 = 0;
    for i in 0..len {
        acc = acc.wrapping_mul(31).wrapping_add(*ptr.add(i) as u32);
    }
    acc
}

/// Walk TLS-record-shaped headers: 5-byte header, big-endian length at [3..4], skip the body.
#[no_mangle]
pub unsafe extern "C" fn frame_walk(ptr: *const u8, len: usize) -> u32 {
    let mut n: u32 = 0;
    let mut off: usize = 0;
    while off + 5 <= len {
        let blen = ((*ptr.add(off + 3) as usize) << 8) | (*ptr.add(off + 4) as usize);
        off += 5 + blen;
        n += 1;
        if blen == 0 {
            break; // a zero-length record would spin forever
        }
    }
    n
}
