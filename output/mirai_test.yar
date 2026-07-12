import "elf"

rule Mirai_EM_X86_64
{
    meta:
        author = "auto-yara"
        entropy = "normal"

    strings:
        $s1 = "/proc/self/exe"
        $s2 = "185.247.224.41"
        $s3 = "/proc/%d"
        $s4 = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        $s5 = "/bin/systemd-daemon"
        $s6 = "/etc/init/systemd-agent.conf"
        $s7 = "/dev/urandom"
        $s8 = "87.98.162.88"
        $s9 = "82.221.103.244"
        $s10 = "67.215.246.10"
        $s11 = "/dev/ptmx"
        $s12 = "/dev/pts/%d"
        $s13 = "/etc/hosts"
        $s14 = "/etc/services"
        $s15 = "/etc/resolv.conf"
        $s16 = "127.0.0.1"
        $s17 = "/usr/local/bin:/bin:/usr/bin"
        $s18 = "/etc/localtime"
        $s19 = "/usr/share/zoneinfo/"
        $s20 = "/etc/zoneinfo/"
        $bp1 = {B8 3B 00 00 00 0F 05}
        $bp2 = {41 55 41 54 55 53 48 81 EC ?? ?? ?? ??}
        $bp3 = {41 56 41 55 41 54 55 53 48 83 EC ??}
        $bp4 = {41 56 41 55 41 54 55 53 48 83 EC ??}
        $bp5 = {41 56 41 55 41 54 55 53 48 81 EC ?? ?? ?? ??}

    condition:
        uint32(0) == 0x464C457F and elf.machine == elf.EM_X86_64 and 2 of ($s*) and 1 of ($bp*)
}