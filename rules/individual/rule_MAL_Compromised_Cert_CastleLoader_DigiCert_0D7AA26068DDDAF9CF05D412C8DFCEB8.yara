import "pe"

rule MAL_Compromised_Cert_CastleLoader_DigiCert_0D7AA26068DDDAF9CF05D412C8DFCEB8 {
   meta:
      description         = "Detects CastleLoader with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-12"
      version             = "1.0"

      hash                = "5441e3aaf800ec7a5a4dae946a8173537b140a850a5002ab9fa1903c1e0fa125"
      malware             = "CastleLoader"
      malware_type        = "Unknown"
      malware_notes       = "C2: koshei[.]icu"

      signer              = "LASSFERA s.r.o."
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "0d:7a:a2:60:68:dd:da:f9:cf:05:d4:12:c8:df:ce:b8"
      cert_thumbprint     = "4BCF10A7D6D4D26409B64A4A48B4CDC2771E3237"
      cert_valid_from     = "2026-03-12"
      cert_valid_to       = "2027-03-09"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "0d:7a:a2:60:68:dd:da:f9:cf:05:d4:12:c8:df:ce:b8"
      )
}
