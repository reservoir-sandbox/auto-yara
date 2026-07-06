import "elf"

rule Mirai_EM_386
{
    meta:
        author = "auto-yara"
        entropy = "normal"

    strings:
        $s1 = "wget -O /tmp/dvrHelper http://"
        $s2 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\"><NewStatusURL>"
        $s3 = "/etc/services"
        $s4 = "/etc/resolv.conf"
        $s5 = "/etc/config/resolv.conf"
        $s6 = "/etc/hosts"
        $s7 = "/etc/config/hosts"

    condition:
        uint32(0) == 0x464C457F and elf.machine == elf.EM_386 and 2 of ($s*)
}