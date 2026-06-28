use windows_sys::Win32::{
    Foundation::ERROR_SUCCESS,
    System::Registry::{
        HKEY, HKEY_LOCAL_MACHINE, KEY_READ, REG_SZ, REG_VALUE_TYPE, RegCloseKey,
        RegOpenKeyExW, RegQueryValueExW,
    },
};

struct RegKey(HKEY);

impl RegKey {
    
    fn new(key:HKEY) ->Self{
        RegKey(key)
    }
    fn raw(&self) ->HKEY{
         self.0
    }
}

impl Drop for RegKey {

    fn drop(&mut self) {
        unsafe {
            RegCloseKey(self.0);
        }
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn query_value(
    key: &RegKey,
    value_name: &[u16],
    value_type: &mut REG_VALUE_TYPE,
) -> Result<Vec<u8>, u32> {
    // let mut value_type = 0u32;
    let mut data_size = 0u32;
    let mut status = unsafe {
        RegQueryValueExW(
            key.raw(),
            value_name.as_ptr(),
            std::ptr::null_mut(),
            value_type,
            std::ptr::null_mut(),
            &mut data_size,
        )
    };

    if status != ERROR_SUCCESS {
        return Err(status);
    }

    let mut buf = vec![0u8; data_size as usize];
    status = unsafe {
        RegQueryValueExW(
            key.raw(),
            value_name.as_ptr(),
            std::ptr::null_mut(),
            value_type,
            buf.as_mut_ptr(),
            &mut data_size,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(status);
    }

    Ok(buf)
}

pub fn get_machine_guid() -> Result<String, std::io::Error> {
    let subkey = wide(r"SOFTWARE\Microsoft\Cryptography");
    let mut hkey = std::ptr::null_mut();
    let status =
        unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey.as_ptr(), 0, KEY_READ, &mut hkey) };

    if status != ERROR_SUCCESS {
        return Err(std::io::Error::from_raw_os_error(status as i32));
    }
    let hkey = RegKey::new(hkey);

    let value_name = wide("MachineGuid");
    let mut value_type: REG_VALUE_TYPE = 0;
    let data = match query_value(&hkey, &value_name, &mut value_type) {
        Ok(data) => data,
        Err(status) => {
            return Err(std::io::Error::from_raw_os_error(status as i32));
        }
    };


    if value_type != REG_SZ {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "MachineGuid is not REG_SZ",
        ));
    }

    let mut utf16 = Vec::new();

    for chunk in data.chunks_exact(2) {
        let ch = u16::from_le_bytes([chunk[0], chunk[1]]);
        if ch == 0 {
            break;
        }
        utf16.push(ch);
    }

    String::from_utf16(&utf16).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "MachineGuid is not valid UTF-16",
        )
    })
}
