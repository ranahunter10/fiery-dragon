# Runbook: build the target VM `p15-dev-2604`

This runbook rebuilds the development and measurement VM from nothing. It records exactly what was done on 2026-10-21, including the mistakes made the first time, so that nobody repeats them. The evidence from the original build is in [`docs/evidence/phase0/`](../evidence/phase0/README.md).

**Result:**
- Ubuntu Server 26.04.1, GA kernel **7.0.0-38-generic, held**;
- 4 vCPU / 8 GB / 64 GB fixed disk, EFI, no Secure Boot, plain ext4 (no LVM);
- reachable as `ssh p15`.

---

## 0. Host prerequisites (Windows)

| Item | Requirement | Why |
|---|---|---|
| CPU / RAM | ≥ 8 logical cores and ≥ 16 GB for the 4 vCPU / 8 GB VM | Measurements need headroom on the host |
| VirtualBox | **≥ 7.2.8** (built with 7.2.22r175245) | Kernel 7.0 guests need 7.2.8 or later |
| Free disk | ≥ 70 GB | 64 GB fixed VDI plus snapshots |
| Hyper-V | Record `(Get-CimInstance Win32_ComputerSystem).HypervisorPresent` | If `True`, VirtualBox runs on the Windows hypervisor, which changes timing and disk numbers |

**Verify every download before using it:**

```powershell
# VirtualBox installer, checked against Oracle's SHA256SUMS
$f = Get-ChildItem "$env:USERPROFILE\Downloads\VirtualBox-7.2.*-Win.exe" | Select -First 1
$mine = (Get-FileHash $f.FullName -Algorithm SHA256).Hash.ToLower()
$sums = (Invoke-WebRequest "https://download.virtualbox.org/virtualbox/7.2.22/SHA256SUMS" -UseBasicParsing).Content
if ((($sums -split "`n") | Where-Object { $_ -match [regex]::Escape($f.Name) }) -match "^$mine") { "MATCH" } else { "NO MATCH - stop" }

# Ubuntu ISO: save SHA256SUMS to a file first. Windows PowerShell returns this one as bytes, not text.
$iso = Get-ChildItem "$env:USERPROFILE\Downloads\ubuntu-26.04*-live-server-amd64.iso" | Select -First 1
Invoke-WebRequest "https://releases.ubuntu.com/26.04/SHA256SUMS" -OutFile "$env:USERPROFILE\Downloads\SHA256SUMS-26.04" -UseBasicParsing
$mine = (Get-FileHash $iso.FullName -Algorithm SHA256).Hash.ToLower()
if ((Get-Content "$env:USERPROFILE\Downloads\SHA256SUMS-26.04" | Where-Object { $_ -match [regex]::Escape($iso.Name) }) -match "^$mine") { "MATCH" } else { "NO MATCH - stop" }
```

## 1. Create the VM with the script, not the GUI wizard

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\vm\create-vm.ps1
```

[`tools/vm/create-vm.ps1`](../../tools/vm/create-vm.ps1) sets every option explicitly and stops at the first error.

**Expected:** it ends with `disk GB: 64` and `DONE`, and the settings list shows `memory=8192`, `cpus=4`, `firmware="EFI"`, `graphicscontroller="vmsvga"`, `nic1="nat"` and `Forwarding(0)="ssh,tcp,,2222,,22"`.

> **Lessons from 2026-10-21:**
> - **The GUI wizard silently kept its defaults** (a 25 GB disk) and the installer added LVM (11 GB root). That VM was discarded. Use the script.
> - **An empty variable disappears from the command line** in Windows PowerShell. When variables were set in one window and the commands were run in another, `createvm --name $name --ostype …` became `createvm --name --ostype …` and every later step failed with misleading errors. The script defines everything itself and is run in a fresh `powershell -File`.
> - **VirtualBox 7.2 prints OS types as `ID / Description: Ubuntu_64 -- …`**, not `ID: Ubuntu_64`. There is no 26.04-specific ID; `Ubuntu_64` is correct.
> - **A port-forward rule added in the GUI is lost** if either dialog is closed with ✕. The script adds it with `--natpf1`.

## 2. Install Ubuntu Server

Start the VM with `VBoxManage startvm p15-dev-2604`, then choose **Try or Install Ubuntu Server**. Never choose the HWE kernel entry.

| Screen | Choice |
|---|---|
| Installer update available | **Continue without updating**, so the install matches the verified ISO |
| Type | **Ubuntu Server** (not minimized); third-party drivers unticked |
| Network / proxy / mirror | DHCP / blank / default |
| Storage | **Use an entire disk**; **untick "Set up this disk as an LVM group"** (press Space until it shows `[ ]`) |
| Storage summary | Must show `/` **ext4 ≈ 62 GB on a partition of sda**, `/boot/efi` 1 GB, and **no `ubuntu-vg`**. If it doesn't, go Back |
| Profile | server `p15-dev`, user `ashu` |
| Ubuntu Pro | Skip |
| SSH | **[X] Install OpenSSH server** |
| Snaps | none |

> **Lesson:** on the second install the OpenSSH box was missed. SSH from the host then failed with `kex_exchange_identification: Connection aborted`. The fix was `sudo apt install -y openssh-server && sudo systemctl enable --now ssh`.
>
> How to read the two SSH errors:
> - **`Connection refused`**: nothing listens on host port 2222. The port-forward rule is missing.
> - **`Connection aborted`**: the forward works, but nothing listens on port 22 inside the VM.

After the install, boot from disk only, so a reboot can never land in the installer again:

```powershell
VBoxManage modifyvm p15-dev-2604 --boot1 disk --boot2 none     # with the VM powered off
```

## 3. Access: key login and the `p15` alias

On the host:

```powershell
if (-not (Test-Path "$env:USERPROFILE\.ssh\id_ed25519")) { ssh-keygen -t ed25519 -C "ashu-laptop" }
Get-Content "$env:USERPROFILE\.ssh\id_ed25519.pub" | ssh -p 2222 ashu@127.0.0.1 "mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
@'
Host p15
    HostName 127.0.0.1
    Port 2222
    User ashu
    IdentityFile ~/.ssh/id_ed25519
'@ | Add-Content "$env:USERPROFILE\.ssh\config"
ssh p15        # must log in without a password
```

After rebuilding the VM, clear the old host key first: `ssh-keygen -R "[127.0.0.1]:2222"`.

From then on, run it headless with `VBoxManage startvm p15-dev-2604 --type headless`.

## 4. Update once, then pin the kernel

In the VM:

```bash
sudo apt update && sudo apt full-upgrade -y && sudo reboot
# after the reboot:
uname -r                                          # 7.0.0-38-generic (or the build being reproduced)
apt list --installed 2>/dev/null | grep -i hwe    # only systemd-hwe-hwdb (a udev database, not a kernel)
sudo apt-mark hold linux-generic linux-image-generic linux-headers-generic
sudo systemctl disable --now unattended-upgrades
apt-mark showhold
```

**Snapshot:** power off, then run `VBoxManage snapshot p15-dev-2604 take "00-fresh-pinned"`.

## 5. Toolchain

First check that every package name exists. If one name is wrong, `apt install` rejects the whole list.

```bash
for p in clang llvm libbpf-dev bpftool dwarves bpftrace build-essential pkg-config \
         libelf-dev zlib1g-dev libzstd-dev git fio strace jq python3-venv \
         linux-tools-common linux-tools-$(uname -r); do
  printf "%-32s %s\n" "$p" "$(apt-cache policy "$p" 2>/dev/null | awk '/Candidate/{print $2}')"
done
sudo apt install -y clang llvm libbpf-dev bpftool dwarves bpftrace build-essential pkg-config \
  libelf-dev zlib1g-dev libzstd-dev git fio strace jq python3-venv \
  linux-tools-common linux-tools-$(uname -r)
apt-mark showhold && uname -r     # the kernel must be unchanged
```

**Snapshot:** `01-toolchain`.

### 5a. Packages added after `01-toolchain`

| Package | Why | Log |
|---|---|---|
| `gcc-multilib` | P8's 32-bit test program (`gcc -m32 -static`) | E-0048, E-0052 |
| `libssl-dev` | building the vendored bpftool v7.7.0, which links libcrypto | E-0061 |
| `python3-numpy` | `make check`: the three-way layout check reads the generated numpy dtypes | E-0065 |

```bash
sudo apt install -y gcc-multilib libssl-dev python3-numpy
apt-mark showhold && uname -r     # the kernel must be unchanged
```

**Snapshot after all three:** `02-dev-deps`.

## 6. Re-capture the evidence

A rebuilt VM must reproduce files 00–05 in [`docs/evidence/phase0/`](../evidence/phase0/README.md). Any difference is recorded as a new engineering-log row.

**Known gap:** the exact commands that produced those files were run interactively and are not yet in the repo. The next PR adds them as scripts under `tools/vm/`. Until then, this step cannot be reproduced from the repo alone.

## 6a. Turning the Windows hypervisor off for a measurement session (and back on)

The Hyper-V A-B-A runs ([evidence](../evidence/baseline/2026-10-25-hyperv-ABA/README.md)) showed process creation 4–5.5× faster with the Windows hypervisor off. **On Windows 11 the boot setting alone is not enough**: while Memory integrity (HVCI) is on, Windows still loads the hypervisor.

| Step | Off (for measuring) | Back on (always, afterwards) |
|---|---|---|
| 1 | VM: `sudo poweroff` | VM: `sudo poweroff` |
| 2 | Windows Security → Device security → Core isolation → **Memory integrity Off** (or registry `…\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity` `Enabled=0`) | **Memory integrity On** (or `Enabled=1`) |
| 3 | admin: `bcdedit /set hypervisorlaunchtype off` | admin: `bcdedit /set hypervisorlaunchtype auto` |
| 4 | **Restart** (not Shut down) | **Restart** |
| 5 | Verify: `HypervisorPresent` = **False**, `Win32_DeviceGuard.VirtualizationBasedSecurityStatus` = **0**; VBox.log shows `HM: Using VT-x implementation` | Verify: **True**, **2**, `Enabled` = **1**, `hypervisorlaunchtype Auto` |

**Before step 4, check BitLocker** (`manage-bde -status C:`). If protection is on, have the recovery key at hand. **Install nothing** while Memory integrity is off. WSL2 and Docker Desktop don't work until the hypervisor is back.

## 7. Before deleting a VM

Export it first, then record the hash:

```powershell
VBoxManage export p15-dev-2604 --ovf20 -o "$env:USERPROFILE\vm-backup\p15-dev-2604.ova"
Get-FileHash "$env:USERPROFILE\vm-backup\p15-dev-2604.ova" -Algorithm SHA256
```

**Never delete a validated environment until its replacement has reproduced the old result.** This rule was broken once (engineering log E-0009).
