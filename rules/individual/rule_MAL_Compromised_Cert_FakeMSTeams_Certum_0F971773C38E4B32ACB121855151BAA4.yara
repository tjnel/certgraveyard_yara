import "pe"

rule MAL_Compromised_Cert_FakeMSTeams_Certum_0F971773C38E4B32ACB121855151BAA4 {
   meta:
      description         = "Detects FakeMSTeams with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-14"
      version             = "1.0"

      hash                = "d01148808fbeefa22cd4541cdaaee8bc1f74e3045302115dc5b08b99ff93dc9c"
      malware             = "FakeMSTeams"
      malware_type        = "Unknown"
      malware_notes       = "C2: mon.systemautoupdater.com:3003"

      signer              = "Zlatin Stamatov"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "0f:97:17:73:c3:8e:4b:32:ac:b1:21:85:51:51:ba:a4"
      cert_thumbprint     = "EF22B4A85B2FC263BF88C343D26D1333A1A7CDF1"
      cert_valid_from     = "2026-03-14"
      cert_valid_to       = "2027-03-14"

      country             = "BG"
      state               = "Burgas"
      locality            = "Burgas"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "0f:97:17:73:c3:8e:4b:32:ac:b1:21:85:51:51:ba:a4"
      )
}
