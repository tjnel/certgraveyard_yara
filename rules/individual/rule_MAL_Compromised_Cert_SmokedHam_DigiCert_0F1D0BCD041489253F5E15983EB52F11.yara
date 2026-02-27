import "pe"

rule MAL_Compromised_Cert_SmokedHam_DigiCert_0F1D0BCD041489253F5E15983EB52F11 {
   meta:
      description         = "Detects SmokedHam with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-16"
      version             = "1.0"

      hash                = "82399d57042cd8056fd5e3b45618cc6cdf9621573fcfb9b62531d987e2650e48"
      malware             = "SmokedHam"
      malware_type        = "Unknown"
      malware_notes       = "Malicious trojanized installers impersonating software applications leading to SmokedHam RAT"

      signer              = "Softguard Technology Yazılım Hizmetleri Anonim Şirketi"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "0f:1d:0b:cd:04:14:89:25:3f:5e:15:98:3e:b5:2f:11"
      cert_thumbprint     = "4EF659A2314D0A4990CE97C01FEFDFD1F851F06A"
      cert_valid_from     = "2026-02-16"
      cert_valid_to       = "2027-02-15"

      country             = "TR"
      state               = "İstanbul"
      locality            = "Avcılar"
      email               = "???"
      rdn_serial_number   = "1043733"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "0f:1d:0b:cd:04:14:89:25:3f:5e:15:98:3e:b5:2f:11"
      )
}
