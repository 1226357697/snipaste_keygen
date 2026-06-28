use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::NetworkManagement::NetManagement::{
    NetApiBufferFree, NetWkstaGetInfo, WKSTA_INFO_100,
};
use blake2::{
    Blake2sVar,
    digest::{Update, VariableOutput},
};
use serde_json::json;
use flate2::{Compression, write::GzEncoder};
use std::io::Write;
use base64::{engine::general_purpose, Engine as _};

mod utils;
use utils::get_machine_guid;

fn wide_ptr_to_string(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0;

    unsafe {
        while *ptr.add(len) != 0 {
            len += 1;
        }

        let slice = std::slice::from_raw_parts(ptr, len);
        String::from_utf16_lossy(slice)
    }
}

fn get_dom() -> Result<String, std::io::Error> {
    let mut buf: *mut u8 = std::ptr::null_mut();

    let status =
        unsafe { NetWkstaGetInfo(std::ptr::null(), 100, &mut buf as *mut _) };

    if status != ERROR_SUCCESS {
        return Err(std::io::Error::from_raw_os_error(status as i32));
    }

    let info = unsafe { &*(buf as *const WKSTA_INFO_100) };
    let dom =  wide_ptr_to_string(info.wki100_langroup);
    unsafe {NetApiBufferFree(buf as *const _)};

    Ok(dom)
}

fn x_blake2_128(data:&[u8], r_sz:usize)->Vec<u8> {
    let mut  hasher = Blake2sVar::new(16).unwrap();

    hasher.update(b"Snipaste 2");
    hasher.update(b"1");
    hasher.update(data);

    let mut out = [0u8; 16];
    hasher.finalize_variable(&mut out).unwrap();

    out[16 - r_sz..].to_vec()
}

fn format_string_with_separator(
    input: &str,
    separator: &str,
    first_step: usize,
    subsequent_step: usize,
) -> String {
    if separator.is_empty() || input.is_empty() {
        return input.to_string();
    }

    let mut result = String::new();
    let mut pos = 0;
    let len = input.len();
    let mut step = first_step;

    while pos < len {
        if pos > 0 {
            result.push_str(separator);
        }

        let actual_step = step.min(len - pos);

        result.push_str(&input[pos..pos + actual_step]);

        pos += actual_step;
        step = subsequent_step;
    }

    result
}

fn calculate_adjacent_char_diff_sum(input: &str) -> String {
    if input.is_empty() {
        return "0".to_string();
    }

    let bytes = input.as_bytes();
    let length = bytes.len();

    if length == 1 {
        return input.to_string();
    }

    let mut total_diff_sum: usize = 0;

    for i in 1..length {
        let prev = bytes[i - 1];
        let curr = bytes[i];

        total_diff_sum += curr.abs_diff(prev) as usize;
    }

    let index = total_diff_sum % length;

    (bytes[index] as char).to_string()
}

fn gen_machineid(r_sz:usize)-> Option<String> {

    let Ok(guid) = get_machine_guid() else{
        return None;
    };

    let hash_bytes = x_blake2_128(guid.as_bytes(), r_sz);
    let mut s  = hash_bytes.iter()
    .map(|b| format!("{:02X}", b))
    .collect::<String>();

    s = format_string_with_separator(s.as_str(), "-", 4, 8);

    let raw = s.replace('-', "");

    s.push_str(&calculate_adjacent_char_diff_sum(&raw));
    s.push('1');

    return  Some(s);
}

fn create_license_json(name:String, dom:String, machineid:String) ->String{
    let iat_string = "2026-06-25 12:01:01";
    let time_string = "2099-01-01 11:11:11";
    let lic = "12138".to_string();
    let email = "12138@kunkun.com";
    let device = 666u32;

    let license = json!({
        "nam": name,
        "eml": email,
        "lic": lic,
        "dev": device,
        "pln": "Personal",
        "dom": dom,
        "api":0,
        "iat": iat_string,
        "exp": time_string,
        "exx": time_string,
        "ref": time_string,
        "hwi": {
            "machineid": machineid,
            "platform": 1,
            "domain": "",
        },
    });

    serde_json::to_string(&license).unwrap()
}


fn gen_device_info( dom:&String, machineid:&String) ->String{

    let info = json!({
        "dom": dom,
        "machineid": machineid,
    });

    serde_json::to_string(&info).unwrap()
}

fn gzip_base64(str:&String) -> Result<String, std::io::Error>{
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(str.as_bytes())?;

    let compressed = encoder.finish()?;
    let encoded = general_purpose::STANDARD.encode(compressed);
    Ok(encoded)
}

fn main() {

    let machineid = gen_machineid(9).expect("Failed to the gen machineid");
    let dom = get_dom().expect("Failed to get the dom");
    let device_info = gen_device_info(&dom, &machineid);
    let encoded_device = gzip_base64(&device_info).expect("Failed to encode the device information");

    println!("The device information is {encoded_device}");
}
