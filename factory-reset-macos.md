# How to factory reset your macOS (Intel & Silicon)

## Why & when

**Factory resetting your device is the only way to make sure your device isn't infected and will clear any doubts you have.** 

Moreover, it’s recommended to do this step twice a year.

👍 You know your new device is clean, you test your backups.  
👎 It can take up to 90 minutes.

**Back up your data!**  

This guide shows how to fully erase a Mac and reinstall macOS, covering both Intel-based and Apple Silicon (ARM) models. It doesn’t include the backup steps. 

## Steps

| What to do                         | Why this is important                                                                 | Intel Macs (2012 to 2020)                                                                 | Apple Silicon Macs (M1, M2, etc.)                                                                 |
|------------------------------------|----------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------|
| Sign out of iCloud                 | Disconnects the device from your Apple ID to prevent activation lock                  | System Preferences > Apple ID > Overview > Sign out                                      | System Settings > Apple ID > Sign out                                                             |
| Reset NVRAM                        | Resets system settings like screen resolution and security configurations             | Restart and hold `command + option + P + R` for 10 to 20 seconds                         | Not needed, handled automatically by the system                                                   |
| Enter recovery mode                | Access recovery tools to erase the disk and reinstall macOS                           | Restart and hold `command + R` until Apple logo appears                                  | Shut down, then hold the power button until "loading startup options" appears, then click Options > Continue |
| Erase the hard drive              | Deletes your files and system from internal storage                                   | In recovery: Utilities > Disk Utility > Select "Macintosh HD" > Erase volume group or Erase | Same steps using Disk Utility                                                                     |
| Delete other internal volumes      | Cleans up extra partitions or volumes left by system or apps                          | Select extra internal volumes in Disk Utility and click the minus button                 | Same process                                                                                       |
| Reinstall macOS                    | Installs a fresh copy of macOS, ready for new user                                    | In recovery: Choose Reinstall macOS and follow on-screen instructions                    | Same process                                                                                       |
| Wait for install to complete       | Final step; once done, the Mac will be ready for setup                                | Takes 30 to 90 minutes depending on internet and Mac speed                               | Same duration and setup                                                                           |
