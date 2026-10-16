import "pe"

rule MAL_Compromised_Cert_Wailsloader_SSL_com_1F2F4DDC5D24A208DF6D068654F265BB {
   meta:
      description         = "Detects Wailsloader with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-09-07"
      version             = "1.0"

      hash                = "73cb8ff57d809fe1042ef02ba5571d8ad7ee871cadf01a9bbc609f69f8d407ed"
      malware             = "Wailsloader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Adelise Zoe Hernandez Melendez"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "1f:2f:4d:dc:5d:24:a2:08:df:6d:06:86:54:f2:65:bb"
      cert_thumbprint     = "012548818EBF113E6101E7EA96F122D982F85189"
      cert_valid_from     = "2026-09-07"
      cert_valid_to       = "2027-09-07"

      country             = "US"
      state               = "Florida"
      locality            = "Oldsmar"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "1f:2f:4d:dc:5d:24:a2:08:df:6d:06:86:54:f2:65:bb"
      )
}
