import "pe"

rule MAL_Compromised_Cert_OverlordRAT_Certum_4C4593AB032C0A92CDB5439DB561EB99 {
   meta:
      description         = "Detects OverlordRAT with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-06-16"
      version             = "1.0"

      hash                = "0ee2f1a6c88a725bac0211cb1df1e62412e08c4c28364cb28e2dcaa5991cb1dd"
      malware             = "OverlordRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "WANG BING"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "4c:45:93:ab:03:2c:0a:92:cd:b5:43:9d:b5:61:eb:99"
      cert_thumbprint     = "fb5a434ff16f9f89ff6298121ecfd2339384dd7f"
      cert_valid_from     = "2026-06-16"
      cert_valid_to       = "2027-06-16"

      country             = "CN"
      state               = "HEBEI"
      locality            = "HANDAN"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "4c:45:93:ab:03:2c:0a:92:cd:b5:43:9d:b5:61:eb:99"
      )
}
