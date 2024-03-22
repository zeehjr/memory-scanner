use windows::Win32::{
    Foundation::{CloseHandle, HANDLE, HMODULE},
    System::{
        Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W,
            TH32CS_SNAPMODULE,
        },
        ProcessStatus::{EnumProcessModules, GetModuleFileNameExW},
    },
};

#[allow(dead_code)]
pub fn list_process_module_names(
    process_handle: HANDLE,
) -> Result<Vec<String>, windows::core::Error> {
    let mut modules: [isize; 1024] = [0; 1024];

    let mut module_list_size: u32 = 0;

    unsafe {
        EnumProcessModules(
            process_handle,
            modules.as_mut_ptr().cast(),
            1024,
            &mut module_list_size,
        )
        .unwrap()
    };

    let module_size: usize = std::mem::size_of::<HMODULE>();

    let module_count = module_list_size as usize / module_size;

    let mut module_names: Vec<String> = vec![];

    for i in 0..module_count {
        let mut mod_name: [u16; 260] = [0; 260];

        unsafe { GetModuleFileNameExW(process_handle, HMODULE(modules[i]), &mut mod_name) };

        module_names.push(String::from_utf16(&mod_name).unwrap());
    }

    Ok(module_names)
}

#[allow(dead_code)]
pub fn list_process_modules(process_id: u32) -> Vec<MODULEENTRY32W> {
    let mut modules: Vec<MODULEENTRY32W> = vec![];

    let h_snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, process_id).unwrap() };

    let mut module_entry: MODULEENTRY32W = MODULEENTRY32W::default();

    module_entry.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;

    let mut count = 0;

    let mut result =
        unsafe { Module32FirstW(h_snapshot, &mut module_entry as *mut MODULEENTRY32W) };

    while result.clone().is_ok() {
        count = count + 1;
        modules.push(module_entry.clone());

        result = unsafe { Module32NextW(h_snapshot, &mut module_entry as *mut MODULEENTRY32W) };
    }

    unsafe { CloseHandle(h_snapshot).unwrap() };

    modules
}
