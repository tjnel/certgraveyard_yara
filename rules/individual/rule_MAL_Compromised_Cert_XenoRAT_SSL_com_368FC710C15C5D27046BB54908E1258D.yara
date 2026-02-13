import "pe"

rule MAL_Compromised_Cert_XenoRAT_SSL_com_368FC710C15C5D27046BB54908E1258D {
   meta:
      description         = "Detects XenoRAT with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-04"
      version             = "1.0"

      hash                = "d8e984b4cf7122e97ac108cfc8143f1887b743af6aefe34e79e2891c94054112"
      malware             = "XenoRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Bato Dugarminaev"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "36:8f:c7:10:c1:5c:5d:27:04:6b:b5:49:08:e1:25:8d"
      cert_thumbprint     = "388A3C918DE5080C7B504C39205F033BFC59E22A"
      cert_valid_from     = "2026-02-04"
      cert_valid_to       = "2027-02-03"

      country             = "MT"
      state               = "Ħamrun"
      locality            = "Ħamrun"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "36:8f:c7:10:c1:5c:5d:27:04:6b:b5:49:08:e1:25:8d"
      )
}
