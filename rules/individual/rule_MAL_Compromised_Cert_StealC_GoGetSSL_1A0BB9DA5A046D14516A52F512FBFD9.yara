import "pe"

rule MAL_Compromised_Cert_StealC_GoGetSSL_1A0BB9DA5A046D14516A52F512FBFD9 {
   meta:
      description         = "Detects StealC with compromised cert (GoGetSSL)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-10-02"
      version             = "1.0"

      hash                = "37d7a8c504227f9c1986619fd8148f1737cf94e56ac91687f8ba33be7e945f5e"
      malware             = "StealC"
      malware_type        = "Infostealer"
      malware_notes       = ""

      signer              = "AirTiki ApS"
      cert_issuer_short   = "GoGetSSL"
      cert_issuer         = "GoGetSSL G4 CS RSA4096 SHA256 2022 CA-1"
      cert_serial         = "1a:0b:b9:da:5a:04:6d:14:51:6a:52:f5:12:fb:fd:9"
      cert_thumbprint     = "8557ed87faf3a242d4f22ef00e97aaf603f8a864"
      cert_valid_from     = "2026-10-02"
      cert_valid_to       = "2027-10-01"

      country             = "DK"
      state               = "---"
      locality            = "Nysted"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GoGetSSL G4 CS RSA4096 SHA256 2022 CA-1" and
         sig.serial == "1a:0b:b9:da:5a:04:6d:14:51:6a:52:f5:12:fb:fd:9"
      )
}
