# rust-argument-spoofing

Process Argument Spoofing tool written in Rust that runs "powershell.exe -exec bypass calc.exe" instead of "powershell.exe echo hello!" witch is the original argument.
This technique allows evasion of defense mechanisms and logging systems, including Windows logs and Sysmon, achieved by altering the command line while the process is in a suspended state.

## Build
```bash
cargo build --release
```

## Usage

To use this tool, run it from the command line with the following syntax:

```bash
./arg-spoof.exe
```

## References

1. [MITRE Attack](https://attack.mitre.org/techniques/T1564/010/)
2. [Bordergate Argument Spoofing with C#](https://www.bordergate.co.uk/argument-spoofing/)
3. [Spoofing Command Line Arguments to Dump LSASS in Rust](https://www.synercomm.com/blog/spoofing-command-line-arguments-to-dump-lsass-in-rust/)

## DISCLAIMER

Please only use this tool on systems you have permission to access! Ethical use only.

Any actions and or activities related to the tools I have created is solely your responsibility.The misuse of the tools I have created can result in criminal charges brought against the persons in question. I will not be held responsible in the event any criminal charges be brought against any individuals misusing the tools I have made to break the law.

You are responsible for your own actions.

## License

This project is licensed under the [MIT License](LICENSE).

Feel free to use, modify, and distribute this code in accordance with the license terms.
