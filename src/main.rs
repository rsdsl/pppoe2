use rsdsl_pppoe2::Result;

fn main() -> Result<()> {
    let (_a, _b, _c) =
        rsdsl_pppoe2_sys::new_session("wlan0", [0x41, 0x41, 0x41, 0x41, 0x41, 0x41].into(), 1)?;
    loop {}
}
