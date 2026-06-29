import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_SSL_com_0E8A201CD9D72CF63D9F0F238E9EE6E6 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-06-12"
      version             = "1.0"

      hash                = "87c8df8bca39bbb86f4b2bccadb106aa7c3837db4b314694325cb25222c871e5"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "AYNUR BATUHAN SMART TECH"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "0e:8a:20:1c:d9:d7:2c:f6:3d:9f:0f:23:8e:9e:e6:e6"
      cert_thumbprint     = "80F7FE5003FDC50CDC66673528A051D5A86371CC"
      cert_valid_from     = "2026-06-12"
      cert_valid_to       = "2027-06-10"

      country             = "TR"
      state               = "Kayseri Province"
      locality            = "Melikgazi"
      email               = "???"
      rdn_serial_number   = "42986"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "0e:8a:20:1c:d9:d7:2c:f6:3d:9f:0f:23:8e:9e:e6:e6"
      )
}
