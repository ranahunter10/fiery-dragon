# create-p15-vm.ps1 — p15 dev VM, every setting explicit. Stops at the first error.
$ErrorActionPreference = "Stop"
$vbm  = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
$name = "p15-dev-2604"
$os   = "Ubuntu_64"
$iso  = "$env:USERPROFILE\Downloads\ubuntu-26.04.1-live-server-amd64.iso"
$dir  = "$env:USERPROFILE\VirtualBox VMs\$name"
$disk = "$dir\$name.vdi"

function vb { & $vbm @args; if ($LASTEXITCODE -ne 0) { throw "FAILED: VBoxManage $args" } }

# --- pre-flight checks ---
if (-not (Test-Path $iso)) { throw "ISO not found: $iso" }
if (Test-Path $dir)        { throw "Folder already exists: $dir (delete it first)" }
if (-not ((& $vbm list ostypes) -match "^ID / Description:\s+$os\s+--")) { throw "OS type '$os' not in 'VBoxManage list ostypes'" }
"pre-flight OK: name=[$name] os=[$os]"

# --- machine ---
vb createvm --name $name --ostype $os --register
vb modifyvm $name --memory 8192 --cpus 4 --firmware efi --ioapic on --rtc-use-utc on --pae on --nested-paging on --paravirt-provider default
vb modifyvm $name --graphicscontroller vmsvga --vram 16 --audio-enabled off --usb-ohci off --usb-ehci off --usb-xhci off --mouse ps2
vb modifyvm $name --clipboard-mode disabled --drag-and-drop disabled
vb modifyvm $name --boot1 dvd --boot2 disk --boot3 none --boot4 none
vb modifyvm $name --nic1 nat --natpf1 "ssh,tcp,,2222,,22"

# --- storage: 64 GB pre-allocated + installer ISO ---
vb createmedium disk --filename $disk --size 65536 --format VDI --variant Fixed
vb storagectl $name --name SATA --add sata --controller IntelAhci --portcount 2
vb storageattach $name --storagectl SATA --port 0 --device 0 --type hdd --medium $disk --nonrotational on
vb storageattach $name --storagectl SATA --port 1 --device 0 --type dvddrive --medium $iso

# --- show what we built ---
& $vbm showvminfo $name --machinereadable | Select-String '^(ostype|memory|cpus|firmware|graphicscontroller|nic1|Forwarding|"SATA)'
"disk GB: " + [math]::Round((Get-Item $disk).Length / 1GB, 1)
"DONE"
