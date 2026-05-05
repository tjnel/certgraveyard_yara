import "pe"

rule MAL_Compromised_Cert_Unknown_GoGetSSL_0DB0CB5C25BC7AF916078B05A5902AED {
   meta:
      description         = "Detects Unknown with compromised cert (GoGetSSL)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-14"
      version             = "1.0"

      hash                = "a54f626f130c36709857215122d6ceb16e5fab7047316afc31a83dfa620cf292"
      malware             = "Unknown"
      malware_type        = "Loader"
      malware_notes       = "Disguised as Node.exe but reached out to C2: 666777228[.]com"

      signer              = "Soft Insanity Oy"
      cert_issuer_short   = "GoGetSSL"
      cert_issuer         = "GoGetSSL G4 CS RSA4096 SHA256 2022 CA-1"
      cert_serial         = "0d:b0:cb:5c:25:bc:7a:f9:16:07:8b:05:a5:90:2a:ed"
      cert_thumbprint     = "9DA75845BA58D1DEAFF034741720930B13E86091"
      cert_valid_from     = "2025-11-14"
      cert_valid_to       = "2026-11-13"

      country             = "FI"
      state               = "Kanta-Häme"
      locality            = "HÄMEENLINNA"
      email               = "???"
      rdn_serial_number   = "3212250-4"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GoGetSSL G4 CS RSA4096 SHA256 2022 CA-1" and
         sig.serial == "0d:b0:cb:5c:25:bc:7a:f9:16:07:8b:05:a5:90:2a:ed"
      )
}
