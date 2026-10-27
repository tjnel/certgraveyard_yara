import "pe"

rule MAL_Compromised_Cert_Unknown_Certum_774888DF65E533EFAE99F32E0E58AF83 {
   meta:
      description         = "Detects Unknown with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-08-18"
      version             = "1.0"

      hash                = "86fd0662ac051a0bea219d758e49d52a194c0ff40718f59ffa702cba4fce3a8b"
      malware             = "Unknown"
      malware_type        = "Backdoor"
      malware_notes       = "https://rogueauthority.org/signed-windowsdefender-msi-rust-remote-shell"

      signer              = "Kovalainen Software Oy"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "77:48:88:df:65:e5:33:ef:ae:99:f3:2e:0e:58:af:83"
      cert_thumbprint     = "e1dd5e59029a66b1e6dab589ca0ad5bec5f3a8dc"
      cert_valid_from     = "2026-08-18"
      cert_valid_to       = "2027-08-18"

      country             = "FI"
      state               = "Pirkanmaa"
      locality            = "Tampere"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "77:48:88:df:65:e5:33:ef:ae:99:f3:2e:0e:58:af:83"
      )
}
