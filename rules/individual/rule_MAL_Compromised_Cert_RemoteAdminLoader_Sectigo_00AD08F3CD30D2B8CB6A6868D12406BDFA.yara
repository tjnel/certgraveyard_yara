import "pe"

rule MAL_Compromised_Cert_RemoteAdminLoader_Sectigo_00AD08F3CD30D2B8CB6A6868D12406BDFA {
   meta:
      description         = "Detects RemoteAdminLoader with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-09"
      version             = "1.0"

      hash                = "b9b07224e5840482a5bf351c3f4984e46387dcf2808f9324c0da343d74136e1d"
      malware             = "RemoteAdminLoader"
      malware_type        = "Remote access tool"
      malware_notes       = "Fake cryptowallet that installs remote admin tool."

      signer              = "Anhui Kangbei Si Energy Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:ad:08:f3:cd:30:d2:b8:cb:6a:68:68:d1:24:06:bd:fa"
      cert_thumbprint     = "3F21E8D154D8A5061843D48BEBBB4E0CD650B67C"
      cert_valid_from     = "2026-01-09"
      cert_valid_to       = "2027-01-09"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:ad:08:f3:cd:30:d2:b8:cb:6a:68:68:d1:24:06:bd:fa"
      )
}
