import "pe"

rule MAL_Compromised_Cert_AnyPDFTrojan_DigiCert_0E513A559B22A73332C8E5CADF02AE17 {
   meta:
      description         = "Detects AnyPDFTrojan with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-16"
      version             = "1.0"

      hash                = "a48284edc2079d5cdde52c63fa25ac06e929f4324328c0d22fccc2ac5977df28"
      malware             = "AnyPDFTrojan"
      malware_type        = "Backdoor"
      malware_notes       = "anyPDF is an Adclicker Trojan and a Backdoor - displays hidden ads on your device and simulates ad presses to generate revenue to the attackers. It has the capability to steal PDF related files that you open in your web browser and would be able to send your browsing history to C2 if instructed to do so. See https://rifteyy.org/report/anypdf-malware-analysis for analysis."

      signer              = "Lupus Tech Limited"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "0e:51:3a:55:9b:22:a7:33:32:c8:e5:ca:df:02:ae:17"
      cert_thumbprint     = "09B373711A32A0D2360E2F6996C8E3C7DB8BD64F"
      cert_valid_from     = "2025-04-16"
      cert_valid_to       = "2028-04-20"

      country             = "GB"
      state               = "???"
      locality            = "Egham"
      email               = "???"
      rdn_serial_number   = "13890437"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "0e:51:3a:55:9b:22:a7:33:32:c8:e5:ca:df:02:ae:17"
      )
}
