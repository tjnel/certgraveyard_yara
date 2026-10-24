import "pe"

rule MAL_Compromised_Cert_Unknown_Microsoft_330008A0F38650BE3ECB9900AC00000008A0F3 {
   meta:
      description         = "Detects Unknown with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-10-18"
      version             = "1.0"

      hash                = "a8d7e195089b11db3c3c362a4f81b0eb6dc502f204993b73ef37ae0947306a35"
      malware             = "Unknown"
      malware_type        = "Backdoor"
      malware_notes       = "https://rogueauthority.org/signed-peazip-msi-self-updating-dll-sideload"

      signer              = "Listenmaa Consulting Oy"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 03"
      cert_serial         = "33:00:08:a0:f3:86:50:be:3e:cb:99:00:ac:00:00:00:08:a0:f3"
      cert_thumbprint     = "49c705a25a81c82fe85f86a2379493ebeb93a128"
      cert_valid_from     = "2026-10-18"
      cert_valid_to       = "2026-10-21"

      country             = "FI"
      state               = "Uusimaa"
      locality            = "Tampere"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 03" and
         sig.serial == "33:00:08:a0:f3:86:50:be:3e:cb:99:00:ac:00:00:00:08:a0:f3"
      )
}
