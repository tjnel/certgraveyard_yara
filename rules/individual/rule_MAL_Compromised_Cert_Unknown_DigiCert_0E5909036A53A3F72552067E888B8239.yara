import "pe"

rule MAL_Compromised_Cert_Unknown_DigiCert_0E5909036A53A3F72552067E888B8239 {
   meta:
      description         = "Detects Unknown with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-11-08"
      version             = "1.0"

      hash                = "6445145ba1f2a8a3fdd9d4a3a3b25be420b61dbe03f7cee5c38e6956e3fc4a48"
      malware             = "Unknown"
      malware_type        = "Trojan"
      malware_notes       = "The malware downloads remote files to drop into temporary directories and then creates firewall exclusions for them."

      signer              = "34.028.832 HIGOR PEREIRA MORAIS"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "0e:59:09:03:6a:53:a3:f7:25:52:06:7e:88:8b:82:39"
      cert_thumbprint     = "2B598D1AAB6A031C52FC757F131FDECDFDB16C52"
      cert_valid_from     = "2024-11-08"
      cert_valid_to       = "2025-11-07"

      country             = "BR"
      state               = "PARAIBA"
      locality            = "CAMPINA GRANDE"
      email               = "???"
      rdn_serial_number   = "34.028.832/0001-38"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "0e:59:09:03:6a:53:a3:f7:25:52:06:7e:88:8b:82:39"
      )
}
