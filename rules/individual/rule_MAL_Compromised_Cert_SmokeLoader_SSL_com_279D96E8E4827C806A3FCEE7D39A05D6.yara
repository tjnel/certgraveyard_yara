import "pe"

rule MAL_Compromised_Cert_SmokeLoader_SSL_com_279D96E8E4827C806A3FCEE7D39A05D6 {
   meta:
      description         = "Detects SmokeLoader with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-16"
      version             = "1.0"

      hash                = "b69a80dfb4c92d29c0b5767cb9717c5498cf27794d9ca6b394deec9873ce0cd6"
      malware             = "SmokeLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Alilab Interaktif Teknolojiler Oyun ve Film Prod. Ltd. Sirketi"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "27:9d:96:e8:e4:82:7c:80:6a:3f:ce:e7:d3:9a:05:d6"
      cert_thumbprint     = "331034DF7587CBF845C60FC086CED07C0B1D3355"
      cert_valid_from     = "2026-03-16"
      cert_valid_to       = "2027-03-16"

      country             = "TR"
      state               = "İstanbul"
      locality            = "Umraniye"
      email               = "???"
      rdn_serial_number   = "1034460"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "27:9d:96:e8:e4:82:7c:80:6a:3f:ce:e7:d3:9a:05:d6"
      )
}
