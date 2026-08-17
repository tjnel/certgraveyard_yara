import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_73B4DCCF89567927F848C19B {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-10"
      version             = "1.0"

      hash                = "1534e8091708e13a24698de848faccac0ccbf82cc625f990bed0c7ec5388c345"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Komers Trading Company LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "73:b4:dc:cf:89:56:79:27:f8:48:c1:9b"
      cert_thumbprint     = "17580c5867a917d7c107dce479df1b806e609f6b"
      cert_valid_from     = "2026-04-10"
      cert_valid_to       = "2027-04-11"

      country             = "PL"
      state               = "Pomerania"
      locality            = "Dobrzewino"
      email               = "komers@komers.eu"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "73:b4:dc:cf:89:56:79:27:f8:48:c1:9b"
      )
}
