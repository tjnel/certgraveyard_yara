import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_SSL_com_50B4A05EC90AB6364EAB2C1924F9908A {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-09"
      version             = "1.0"

      hash                = "2dbd8280bf1faa923b4537d9342d6a69d7f56bde3e1b5559bd4f483af38dce1d"
      malware             = "NetSupport RAT"
      malware_type        = "Remote access tool"
      malware_notes       = ""

      signer              = "Sobitas Software GmbH"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "50:b4:a0:5e:c9:0a:b6:36:4e:ab:2c:19:24:f9:90:8a"
      cert_thumbprint     = "0825f3614b524d1f86664041d4ae21818b3c6cbc"
      cert_valid_from     = "2025-09-09"
      cert_valid_to       = "2026-09-08"

      country             = "AT"
      state               = "Vienna"
      locality            = "Vienna"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "50:b4:a0:5e:c9:0a:b6:36:4e:ab:2c:19:24:f9:90:8a"
      )
}
