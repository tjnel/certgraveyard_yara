import "pe"

rule MAL_Compromised_Cert_SoftHub_GlobalSign_7A3DA17E80BD536BF7341730 {
   meta:
      description         = "Detects SoftHub with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-06-09"
      version             = "1.0"

      hash                = "fb2f4bc078c9a87b4a85bdca339a4019410c811777b480f6c357094eec5b483b"
      malware             = "SoftHub"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "ELH Palkehituse LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "7a:3d:a1:7e:80:bd:53:6b:f7:34:17:30"
      cert_thumbprint     = "7071D9A7059FD4D2E9DA2B6B4B656113451A4E9D"
      cert_valid_from     = "2026-06-09"
      cert_valid_to       = "2027-06-10"

      country             = "EE"
      state               = "Põlva"
      locality            = "Valgjärve"
      email               = "palkehitised@alkehitised.ee"
      rdn_serial_number   = "11171354"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "7a:3d:a1:7e:80:bd:53:6b:f7:34:17:30"
      )
}
